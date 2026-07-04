"""
extract_docker_cve.py — SpiritCLI Dockerfile CVE scanner

Companion to extract_docker.py. Where extract_docker.py lints Dockerfile
*hygiene* (feeds the 'config' sub-score), this module checks the base
image and any version-pinned packages against OSV.dev's public
vulnerability database and feeds the 'cve' sub-score (25% weight).

Requires: pip install requests
"""

import re
import requests

OSV_API = "https://api.osv.dev/v1/query"
EOL_API = "https://endoflife.date/api/{product}.json"
REQUEST_TIMEOUT = 8  # seconds, so a slow/offline network doesn't hang a scan

# Map common Dockerfile base image names to OSV ecosystem strings.
# https://ossf.github.io/osv-schema/#affectedpackage-field
#
# Deliberately does NOT include "node" or "python": those images track a
# language *runtime*, not a package published under any OSV-tracked
# ecosystem (OSV's "npm" ecosystem is packages on the npm registry, not
# the Node.js interpreter itself). Runtime-version staleness for those is
# checked separately via _check_runtime_eol(), against each runtime's
# real end-of-life schedule instead of a query OSV can't answer.
BASE_IMAGE_ECOSYSTEM = {
    "alpine": "Alpine",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
}

# Base image name -> endoflife.date product slug, for runtimes not covered
# by an OSV ecosystem.
RUNTIME_EOL_PRODUCT = {
    "node": "nodejs",
    "python": "python",
}


def _query_runtime_eol(product_slug, version_string):
    """Query endoflife.date for a runtime's support status. Node's release
    cycles are keyed by major version only (e.g. "14"); Python's are keyed
    by major.minor (e.g. "3.7") — try both candidate keys against the
    returned cycle list rather than guessing one format up front."""
    try:
        resp = requests.get(EOL_API.format(product=product_slug), timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        cycles = resp.json()
    except (requests.RequestException, ValueError):
        return None

    match = re.match(r"(\d+)(?:\.(\d+))?", version_string)
    if not match:
        return None
    major, minor = match.group(1), match.group(2)
    candidates = [major]
    if minor:
        candidates.append(f"{major}.{minor}")

    for cycle in cycles:
        if str(cycle.get("cycle")) in candidates:
            return cycle
    return None


def _finding(severity, file_path, line_num, message, fix, category="cve", cve_id=None):
    f = {
        "severity": severity,
        "file": file_path,
        "line": line_num,
        "message": message,
        "fix": fix,
        "category": category,
    }
    if cve_id:
        f["cve_id"] = cve_id
    return f


def _severity_from_osv(vuln):
    """OSV entries don't always carry a normalized severity; fall back sensibly."""
    sev_list = vuln.get("severity", [])
    for entry in sev_list:
        score = entry.get("score", "")
        if "CRITICAL" in score.upper():
            return "CRITICAL"
        if "HIGH" in score.upper():
            return "HIGH"
    # CVSS vector strings won't match the checks above; treat any listed
    # vuln with no clear severity as HIGH rather than silently downgrading it.
    return "HIGH" if sev_list or vuln.get("id") else "MEDIUM"


def _query_osv(package_name, version, ecosystem):
    """Query OSV.dev for known vulnerabilities in a specific package@version."""
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    try:
        resp = requests.post(OSV_API, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except requests.RequestException:
        # Network failure shouldn't crash the whole scan; surface it as a
        # single informational finding instead so the user knows CVE
        # checking was skipped.
        return None


def _parse_base_image(line):
    """FROM node:14.17.0-alpine AS build  ->  ('node', '14.17.0-alpine')"""
    parts = line.split()
    if len(parts) < 2:
        return None, None
    ref = parts[1]
    if "@sha256:" in ref:
        return ref.split("@")[0], None  # pinned by digest; no OSV version lookup possible
    if ":" not in ref:
        return ref, None
    name, version = ref.split(":", 1)
    return name, version


def _parse_pinned_packages(line):
    """
    apk add --no-cache openssl=3.1.4-r0 curl=8.4.0-r0
    apt-get install -y libssl3=3.0.11-1
    Returns list of (name, version) tuples for anything explicitly pinned.
    """
    pkgs = []
    for match in re.finditer(r"([a-zA-Z0-9._+-]+)=([a-zA-Z0-9._+~-]+)", line):
        pkgs.append((match.group(1), match.group(2)))
    return pkgs


def extract_docker_cve(file_path, file_contents):
    file_contents = file_contents.lstrip("\ufeff")
    findings = []
    lines = file_contents.split("\n")
    network_error_reported = False

    for i, raw_line in enumerate(lines):
        line_num = i + 1
        clean_line = raw_line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue
        upper = clean_line.upper()

        # --- Base image CVE check (Alpine/Debian/Ubuntu via OSV) ---
        if upper.startswith("FROM"):
            image_name, version = _parse_base_image(clean_line)
            if image_name and version:
                base_name = image_name.split("/")[-1]  # strip registry/org prefix
                ecosystem = BASE_IMAGE_ECOSYSTEM.get(base_name.lower())
                if ecosystem:
                    # strip variant suffixes like -alpine, -slim before querying
                    clean_version = version.split("-")[0]
                    vulns = _query_osv(base_name, clean_version, ecosystem)
                    if vulns is None and not network_error_reported:
                        findings.append(_finding(
                            "MEDIUM", file_path, line_num,
                            "Could not reach OSV.dev to check the base image for known "
                            "CVEs (network/timeout). CVE sub-score is incomplete for this scan.",
                            "Retry with network access, or run 'spirit scan --offline-cve-skip' "
                            "to acknowledge the gap explicitly.",
                            category="cve",
                        ))
                        network_error_reported = True
                    for v in (vulns or []):
                        findings.append(_finding(
                            _severity_from_osv(v), file_path, line_num,
                            f"Base image {base_name}:{version} is affected by "
                            f"{v.get('id', 'an unidentified vulnerability')}.",
                            "Upgrade the base image tag to a patched version; check the "
                            "OSV advisory for the fixed version range.",
                            category="cve",
                            cve_id=v.get("id"),
                        ))

                # --- Runtime EOL check (Node/Python — not OSV-queryable) ---
                eol_product = RUNTIME_EOL_PRODUCT.get(base_name.lower())
                if eol_product:
                    clean_version = version.split("-")[0]
                    cycle = _query_runtime_eol(eol_product, clean_version)
                    if cycle is not None:
                        eol_date = cycle.get("eol")
                        if eol_date and eol_date is not False:
                            findings.append(_finding(
                                "HIGH", file_path, line_num,
                                f"Base image {base_name}:{version} runs a {base_name} "
                                f"{cycle.get('cycle')} runtime, which reached end-of-life on "
                                f"{eol_date} and no longer receives security patches.",
                                f"Upgrade to a currently-supported {base_name} version.",
                                category="cve",
                            ))

        # --- Pinned package CVE check (apk/apt) ---
        if "apk add" in clean_line.lower() or "apt-get install" in clean_line.lower():
            ecosystem = "Alpine" if "apk" in clean_line.lower() else "Debian"
            for pkg_name, pkg_version in _parse_pinned_packages(clean_line):
                vulns = _query_osv(pkg_name, pkg_version, ecosystem)
                if vulns is None and not network_error_reported:
                    findings.append(_finding(
                        "MEDIUM", file_path, line_num,
                        "Could not reach OSV.dev to check pinned packages for known CVEs.",
                        "Retry with network access to complete the CVE sub-score.",
                        category="cve",
                    ))
                    network_error_reported = True
                for v in (vulns or []):
                    findings.append(_finding(
                        _severity_from_osv(v), file_path, line_num,
                        f"Package {pkg_name}={pkg_version} is affected by "
                        f"{v.get('id', 'an unidentified vulnerability')}.",
                        f"Bump {pkg_name} to a patched version per the OSV advisory.",
                        category="cve",
                        cve_id=v.get("id"),
                    ))

    return findings