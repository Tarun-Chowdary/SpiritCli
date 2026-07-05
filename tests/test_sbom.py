"""
tests/test_sbom.py — SpiritCLI SBOM (CycloneDX) exporter tests
"""

import json
import os
import pytest
from reporting.sbom_exporter import generate_cyclonedx_sbom, export_sbom


class FakeDep:
    """Minimal stand-in matching models.Dependency's shape."""
    def __init__(self, name, version, is_direct=True, is_dev=False, transitive_path=None):
        self.name = name
        self.version = version
        self.is_direct = is_direct
        self.is_dev = is_dev
        self.transitive_path = transitive_path or []


# ── required CycloneDX structure ────────────────────────────

def test_required_top_level_fields_present():
    sbom = generate_cyclonedx_sbom([FakeDep("lodash", "4.17.21")])
    for key in ("bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"):
        assert key in sbom


def test_bom_format_is_cyclonedx():
    sbom = generate_cyclonedx_sbom([])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"


def test_serial_number_is_valid_urn_uuid():
    sbom = generate_cyclonedx_sbom([])
    assert sbom["serialNumber"].startswith("urn:uuid:")


def test_metadata_component_reflects_project_name():
    sbom = generate_cyclonedx_sbom([], project_name="demo-bank-app", project_version="2.1.0")
    assert sbom["metadata"]["component"]["name"] == "demo-bank-app"
    assert sbom["metadata"]["component"]["version"] == "2.1.0"


def test_empty_dependency_list_produces_empty_components():
    sbom = generate_cyclonedx_sbom([])
    assert sbom["components"] == []
    assert sbom["dependencies"] == []


# ── component fields ─────────────────────────────────────────

def test_component_has_correct_purl():
    sbom = generate_cyclonedx_sbom([FakeDep("express", "4.18.2")])
    comp = sbom["components"][0]
    assert comp["purl"] == "pkg:npm/express@4.18.2"


def test_component_bom_ref_unique_per_name_version():
    sbom = generate_cyclonedx_sbom([FakeDep("express", "4.18.2")])
    assert sbom["components"][0]["bom-ref"] == "express@4.18.2"


def test_direct_dependency_marked_true():
    sbom = generate_cyclonedx_sbom([FakeDep("express", "4.18.2", is_direct=True)])
    props = sbom["components"][0]["properties"]
    direct_prop = next(p for p in props if p["name"] == "spiritcli:direct")
    assert direct_prop["value"] == "true"


def test_transitive_dependency_marked_false():
    sbom = generate_cyclonedx_sbom([FakeDep("qs", "6.11.0", is_direct=False)])
    props = sbom["components"][0]["properties"]
    direct_prop = next(p for p in props if p["name"] == "spiritcli:direct")
    assert direct_prop["value"] == "false"


def test_dev_dependency_scope_is_optional():
    sbom = generate_cyclonedx_sbom([FakeDep("jest", "29.0.0", is_dev=True)])
    assert sbom["components"][0]["scope"] == "optional"


def test_regular_dependency_scope_is_required():
    sbom = generate_cyclonedx_sbom([FakeDep("express", "4.18.2", is_dev=False)])
    assert sbom["components"][0]["scope"] == "required"


# ── dependency graph edges ──────────────────────────────────

def test_transitive_path_becomes_dependency_edge():
    deps = [
        FakeDep("express", "4.18.2", is_direct=True),
        FakeDep("qs", "6.11.0", is_direct=False, transitive_path=["express", "qs"]),
    ]
    sbom = generate_cyclonedx_sbom(deps)
    express_entry = next(d for d in sbom["dependencies"] if d["ref"] == "express@4.18.2")
    assert express_entry["dependsOn"] == ["qs@6.11.0"]


def test_multi_hop_chain_creates_correct_edges():
    deps = [
        FakeDep("a", "1.0.0", is_direct=True),
        FakeDep("b", "1.0.0", is_direct=False, transitive_path=["a", "b"]),
        FakeDep("c", "1.0.0", is_direct=False, transitive_path=["a", "b", "c"]),
    ]
    sbom = generate_cyclonedx_sbom(deps)
    a_entry = next(d for d in sbom["dependencies"] if d["ref"] == "a@1.0.0")
    b_entry = next(d for d in sbom["dependencies"] if d["ref"] == "b@1.0.0")
    assert a_entry["dependsOn"] == ["b@1.0.0"]
    assert b_entry["dependsOn"] == ["c@1.0.0"]


def test_direct_dependency_with_no_transitive_path_has_no_dependson():
    deps = [FakeDep("standalone-pkg", "1.0.0", is_direct=True, transitive_path=[])]
    sbom = generate_cyclonedx_sbom(deps)
    entry = sbom["dependencies"][0]
    assert "dependsOn" not in entry


def test_multiple_direct_deps_no_cross_contamination():
    deps = [
        FakeDep("express", "4.18.2", is_direct=True),
        FakeDep("bcrypt", "5.1.0", is_direct=True),
        FakeDep("qs", "6.11.0", is_direct=False, transitive_path=["express", "qs"]),
        FakeDep("node-pre-gyp", "0.11.0", is_direct=False, transitive_path=["bcrypt", "node-pre-gyp"]),
    ]
    sbom = generate_cyclonedx_sbom(deps)
    express_entry = next(d for d in sbom["dependencies"] if d["ref"] == "express@4.18.2")
    bcrypt_entry = next(d for d in sbom["dependencies"] if d["ref"] == "bcrypt@5.1.0")
    assert express_entry["dependsOn"] == ["qs@6.11.0"]
    assert bcrypt_entry["dependsOn"] == ["node-pre-gyp@0.11.0"]


# ── file export ──────────────────────────────────────────────

def test_export_sbom_writes_valid_json(tmp_path):
    deps = [FakeDep("express", "4.18.2")]
    output_path = str(tmp_path / "sbom.json")
    result_path = export_sbom(deps, output_path, project_name="test-app")
    assert result_path == output_path
    assert os.path.exists(output_path)

    with open(output_path) as f:
        loaded = json.load(f)
    assert loaded["bomFormat"] == "CycloneDX"
    assert loaded["metadata"]["component"]["name"] == "test-app"


def test_export_sbom_pretty_printed(tmp_path):
    deps = [FakeDep("express", "4.18.2")]
    output_path = str(tmp_path / "sbom.json")
    export_sbom(deps, output_path)
    with open(output_path) as f:
        content = f.read()
    # indent=2 means multi-line output, not a single compact line
    assert "\n" in content
