"""
reporting/sbom_exporter.py — SpiritCLI SBOM (Software Bill of Materials) export

Generates a CycloneDX-format SBOM (JSON) from the dependencies already
collected during a scan — both direct (from package.json) and transitive
(from package-lock.json, including chain info if available).

CycloneDX is a widely-used, tool-agnostic SBOM standard (OWASP project);
producing one here means SpiritCLI's output can be consumed by other
supply-chain tooling a banking org might already run, not just read as a
terminal table. https://cyclonedx.org/docs/1.5/json/

Deliberately conservative in scope: this lists components and, where a
transitive_path is available, direct parent->child edges reconstructed
from that path. It does not attempt to serialize the full dependency
graph (every possible edge) — SBOM consumers care most about "what's
installed and at what version," which this covers completely; the full
graph is a nice-to-have most consumers don't need for compliance purposes.
"""

import json
import uuid
from datetime import datetime, timezone


def _purl(name, version, ecosystem="npm"):
    """Package URL — the standard way CycloneDX/SPDX identify a package.
    https://github.com/package-url/purl-spec"""
    return f"pkg:{ecosystem}/{name}@{version}"


def _bom_ref(name, version):
    """Stable identifier for a component within this SBOM, used to link
    the dependency graph section back to each component."""
    return f"{name}@{version}"


def generate_cyclonedx_sbom(dependencies, project_name="project", project_version="0.0.0"):
    """
    dependencies: list of Dependency objects (from Engine._collect_dependencies)
    Returns a CycloneDX 1.5 JSON-serializable dict.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    components = []
    ref_by_name = {}

    for dep in dependencies:
        ref = _bom_ref(dep.name, dep.version)
        ref_by_name[dep.name] = ref
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": dep.name,
            "version": dep.version,
            "purl": _purl(dep.name, dep.version),
            "scope": "optional" if getattr(dep, "is_dev", False) else "required",
            # non-standard but useful custom property: lets a consumer
            # filter directly-declared vs. automatically-pulled-in packages
            # without cross-referencing package.json separately
            "properties": [
                {"name": "spiritcli:direct", "value": str(bool(dep.is_direct)).lower()},
            ],
        })

    # ── dependency graph edges ──────────────────────────────
    # Reconstructed from each transitive dependency's shortest chain back
    # to a direct dependency, e.g. ["express", "qs"] becomes an edge
    # express -> qs. Direct dependencies with no transitive_path get an
    # entry with no dependsOn (CycloneDX allows this — it just means
    # "no further resolved sub-dependencies recorded here").
    edges = {}  # bom-ref -> set of bom-refs it depends on
    for dep in dependencies:
        chain = getattr(dep, "transitive_path", None) or []
        for i in range(len(chain) - 1):
            parent_name, child_name = chain[i], chain[i + 1]
            parent_ref = ref_by_name.get(parent_name)
            child_ref = ref_by_name.get(child_name)
            if parent_ref and child_ref:
                edges.setdefault(parent_ref, set()).add(child_ref)

    dependencies_section = []
    for dep in dependencies:
        ref = ref_by_name[dep.name]
        depends_on = sorted(edges.get(ref, []))
        entry = {"ref": ref}
        if depends_on:
            entry["dependsOn"] = depends_on
        dependencies_section.append(entry)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {"vendor": "Team DrunkenDevs", "name": "SpiritCLI", "version": "0.1.0"}
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
        "dependencies": dependencies_section,
    }

    return sbom


def export_sbom(dependencies, output_path, project_name="project", project_version="0.0.0"):
    """Build the SBOM and write it to output_path as formatted JSON.
    Returns output_path on success. Raises on write failure — unlike the
    scanners, a requested export that silently fails to write is worse
    than an explicit error, since the person asked for a specific file."""
    sbom = generate_cyclonedx_sbom(dependencies, project_name, project_version)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
    return output_path
