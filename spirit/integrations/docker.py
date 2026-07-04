"""
extract_docker.py — SpiritCLI Dockerfile hygiene linter

Companion to extract_docker_cve.py. This module checks Dockerfile
*hygiene* — misconfigurations that aren't about a known CVE in a specific
package, but about how the image is built (running as root, using
mutable tags, leaking secrets into layers, etc). Feeds the 'config'
sub-score, same bucket as the bcrypt/jwt/axios/mongoose/express/lodash
checks in ast_engine/extractors.py.

No network calls — everything here is a static text/pattern check on the
Dockerfile itself.
"""

import re

SECRET_KEY_HINTS = ("password", "secret", "api_key", "apikey", "token", "private_key")


def _finding(severity, file_path, line_num, message, fix, category="config"):
    return {
        "severity": severity,
        "file": file_path,
        "line": line_num,
        "message": message,
        "fix": fix,
        "category": category,
    }


def _parse_base_image(line):
    """FROM node:14.17.0-alpine AS build  ->  ('node', '14.17.0-alpine')"""
    parts = line.split()
    if len(parts) < 2:
        return None, None
    ref = parts[1]
    if "@sha256:" in ref:
        return ref.split("@")[0], "pinned-digest"
    if ":" not in ref:
        return ref, None  # no tag at all -> implicit :latest
    name, version = ref.split(":", 1)
    return name, version


def extract_docker_config(file_path, file_contents):
    file_contents = file_contents.lstrip("\ufeff")
    findings = []
    lines = file_contents.split("\n")

    has_user_instruction = False
    has_healthcheck = False
    seen_from = False

    for i, raw_line in enumerate(lines):
        line_num = i + 1
        clean_line = raw_line.strip()
        if not clean_line or clean_line.startswith("#"):
            continue
        upper = clean_line.upper()

        # --- FROM: mutable/no tag ---
        if upper.startswith("FROM"):
            seen_from = True
            image_name, version = _parse_base_image(clean_line)
            if image_name:
                if version is None:
                    findings.append(_finding(
                        "high", file_path, line_num,
                        f"Base image '{image_name}' has no tag — defaults to "
                        f"':latest', which is mutable and not reproducible.",
                        f"Pin an explicit version, e.g. FROM {image_name}:<version>.",
                    ))
                elif version == "latest":
                    findings.append(_finding(
                        "high", file_path, line_num,
                        f"Base image '{image_name}:latest' is mutable — the same "
                        f"tag can point to different content over time.",
                        f"Pin an explicit version instead of 'latest'.",
                    ))

        # --- USER instruction present anywhere ---
        if upper.startswith("USER"):
            has_user_instruction = True

        # --- HEALTHCHECK present anywhere ---
        if upper.startswith("HEALTHCHECK"):
            has_healthcheck = True

        # --- ADD vs COPY ---
        if upper.startswith("ADD ") or upper == "ADD":
            # ADD auto-extracts archives and can fetch remote URLs — COPY is
            # the safer, more predictable default for local files.
            if "http://" in clean_line.lower() or "https://" in clean_line.lower():
                findings.append(_finding(
                    "medium", file_path, line_num,
                    "ADD is fetching a remote URL directly into the image — "
                    "no integrity check on the downloaded content.",
                    "Use RUN curl/wget with a checksum verification step, "
                    "or COPY a locally-vetted file instead.",
                ))
            else:
                findings.append(_finding(
                    "low", file_path, line_num,
                    "ADD used where COPY would do — ADD's auto-extraction "
                    "behavior is easy to trigger unintentionally.",
                    "Prefer COPY unless you specifically need ADD's "
                    "archive-extraction or remote-URL behavior.",
                ))

        # --- Secrets in ENV/ARG ---
        if upper.startswith("ENV") or upper.startswith("ARG"):
            lowered = clean_line.lower()
            for hint in SECRET_KEY_HINTS:
                if hint in lowered:
                    findings.append(_finding(
                        "critical", file_path, line_num,
                        f"Possible secret baked into the image via "
                        f"{'ENV' if upper.startswith('ENV') else 'ARG'} "
                        f"(matched '{hint}') — this persists in the image layer "
                        f"history even if unset later.",
                        "Pass secrets at runtime (e.g. Docker secrets, "
                        "environment injection at deploy time) instead of "
                        "baking them into the image.",
                    ))
                    break

        # --- apt-get without cleanup (bloats image, not itself a vuln, low sev) ---
        if "apt-get install" in clean_line.lower() and "rm -rf /var/lib/apt/lists" not in file_contents.lower():
            findings.append(_finding(
                "low", file_path, line_num,
                "apt-get install without cleaning up apt lists afterward — "
                "increases image size and attack surface unnecessarily.",
                "Chain with '&& rm -rf /var/lib/apt/lists/*' in the same RUN layer.",
            ))

    if seen_from and not has_user_instruction:
        findings.append(_finding(
            "high", file_path, len(lines),
            "No USER instruction found — container will run as root by default.",
            "Add a non-root USER instruction before the final CMD/ENTRYPOINT.",
        ))

    if seen_from and not has_healthcheck:
        findings.append(_finding(
            "low", file_path, len(lines),
            "No HEALTHCHECK instruction — orchestrators can't detect an "
            "unhealthy-but-running container.",
            "Add a HEALTHCHECK instruction appropriate to the service.",
        ))

    return findings