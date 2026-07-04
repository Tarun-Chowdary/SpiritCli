"""
tests/test_docker_cve.py — SpiritCLI Dockerfile CVE scanner tests

All OSV.dev network calls are mocked via monkeypatch — these tests must
run offline and deterministically, never hitting the real API.
"""

import pytest
import requests

from integrations.docker_cve import (
    extract_docker_cve,
    _parse_base_image,
    _parse_pinned_packages,
    _severity_from_osv,
)


class _FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._json_data


def _mock_post_with_vulns(vulns_by_package):
    """Build a fake requests.post that returns vulns keyed by package name."""
    def fake_post(url, json=None, timeout=None):
        pkg_name = json["package"]["name"]
        vulns = vulns_by_package.get(pkg_name, [])
        return _FakeResponse({"vulns": vulns})
    return fake_post


def _mock_post_network_error(url, json=None, timeout=None):
    raise requests.ConnectionError("simulated network failure")


# ── _parse_base_image ───────────────────────────────────────

def test_parse_base_image_with_tag():
    name, version = _parse_base_image("FROM node:14.17.0-alpine AS build")
    assert name == "node"
    assert version == "14.17.0-alpine"


def test_parse_base_image_no_tag():
    name, version = _parse_base_image("FROM node")
    assert name == "node"
    assert version is None


def test_parse_base_image_digest_pinned():
    name, version = _parse_base_image("FROM node@sha256:abcdef1234567890")
    assert name == "node"
    assert version is None


# ── _parse_pinned_packages ───────────────────────────────────

def test_parse_pinned_packages_apk():
    pkgs = _parse_pinned_packages("apk add --no-cache openssl=3.1.4-r0 curl=8.4.0-r0")
    assert ("openssl", "3.1.4-r0") in pkgs
    assert ("curl", "8.4.0-r0") in pkgs


def test_parse_pinned_packages_apt():
    pkgs = _parse_pinned_packages("apt-get install -y libssl3=3.0.11-1")
    assert ("libssl3", "3.0.11-1") in pkgs


def test_parse_pinned_packages_none_pinned():
    pkgs = _parse_pinned_packages("apt-get install -y curl")
    assert pkgs == []


# ── _severity_from_osv ───────────────────────────────────────

def test_severity_critical_detected():
    vuln = {"severity": [{"score": "CRITICAL"}]}
    assert _severity_from_osv(vuln) == "CRITICAL"


def test_severity_high_detected():
    vuln = {"severity": [{"score": "HIGH: 8.1"}]}
    assert _severity_from_osv(vuln) == "HIGH"


def test_severity_unclear_defaults_high_if_id_present():
    vuln = {"id": "GHSA-xxxx", "severity": [{"score": "CVSS:3.1/AV:N"}]}
    assert _severity_from_osv(vuln) == "HIGH"


def test_severity_no_data_defaults_medium():
    vuln = {}
    assert _severity_from_osv(vuln) == "MEDIUM"


# ── extract_docker_cve: base image ──────────────────────────

def test_base_image_with_known_cve_detected(monkeypatch):
    monkeypatch.setattr(
        requests, "post",
        _mock_post_with_vulns({
            "alpine": [{"id": "CVE-2023-1234", "severity": [{"score": "HIGH"}]}]
        }),
    )
    source = "FROM alpine:3.9\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2023-1234"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "cve"


def test_base_image_clean_no_findings(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    # alpine isn't in RUNTIME_EOL_PRODUCT, so this only exercises the OSV
    # path (no live network call needed for it to stay "clean")
    source = "FROM alpine:3.19\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []


def test_node_image_clean_no_findings_when_still_supported(monkeypatch):
    # Explicitly mock BOTH OSV and the EOL API — node's real support
    # window changes over time, so "clean" for node must never depend on
    # today's actual date matching a hardcoded version.
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    monkeypatch.setattr(requests, "get", _mock_get_eol({
        "nodejs": [{"cycle": "20", "eol": False, "latest": "20.99.0"}],
    }))
    source = "FROM node:20.11.0-alpine\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []


def test_base_image_unrecognized_ecosystem_skipped(monkeypatch):
    # e.g. a custom/private base image — no ecosystem mapping and no EOL
    # product mapping, should not attempt a query or crash
    called = {"count": 0}

    def fake_call(*args, **kwargs):
        called["count"] += 1
        return _FakeResponse({"vulns": []})

    monkeypatch.setattr(requests, "post", fake_call)
    monkeypatch.setattr(requests, "get", fake_call)
    source = "FROM mycompany/internal-base:3.2.1\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []
    assert called["count"] == 0


def test_base_image_digest_pinned_skips_query(monkeypatch):
    called = {"count": 0}

    def fake_post(*args, **kwargs):
        called["count"] += 1
        return _FakeResponse({"vulns": []})

    monkeypatch.setattr(requests, "post", fake_post)
    source = "FROM node@sha256:abcdef1234567890\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []
    assert called["count"] == 0


# ── extract_docker_cve: pinned packages ─────────────────────

def test_pinned_apk_package_with_cve_detected(monkeypatch):
    monkeypatch.setattr(
        requests, "post",
        _mock_post_with_vulns({
            "openssl": [{"id": "CVE-2023-5678", "severity": [{"score": "CRITICAL"}]}]
        }),
    )
    source = "FROM alpine:3.18\nRUN apk add --no-cache openssl=3.1.4-r0\n"
    findings = extract_docker_cve("Dockerfile", source)
    cve_findings = [f for f in findings if f.get("cve_id") == "CVE-2023-5678"]
    assert len(cve_findings) == 1
    assert cve_findings[0]["severity"] == "CRITICAL"


def test_pinned_apt_package_with_cve_detected(monkeypatch):
    monkeypatch.setattr(
        requests, "post",
        _mock_post_with_vulns({
            "libssl3": [{"id": "CVE-2023-9999", "severity": [{"score": "HIGH"}]}]
        }),
    )
    source = "FROM debian:12\nRUN apt-get install -y libssl3=3.0.11-1\n"
    findings = extract_docker_cve("Dockerfile", source)
    cve_findings = [f for f in findings if f.get("cve_id") == "CVE-2023-9999"]
    assert len(cve_findings) == 1


def test_unpinned_package_install_not_checked(monkeypatch):
    called = {"count": 0}

    def fake_post(*args, **kwargs):
        called["count"] += 1
        return _FakeResponse({"vulns": []})

    monkeypatch.setattr(requests, "post", fake_post)
    # base image has no ecosystem mapping so it won't itself trigger a query;
    # isolates the assertion to apt-get's unpinned-package behavior
    source = "FROM mycompany/internal-base:1.0\nRUN apt-get install -y curl\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []
    assert called["count"] == 0


# ── network failure handling ─────────────────────────────────

def test_network_failure_reports_single_informational_finding(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_network_error)
    source = (
        "FROM node:14.17.0-alpine\n"
        "RUN apk add --no-cache openssl=3.1.4-r0 curl=8.4.0-r0\n"
    )
    findings = extract_docker_cve("Dockerfile", source)
    # Should not crash, and should report the network issue only once
    # even though multiple queries would have been attempted.
    network_findings = [f for f in findings if "Could not reach OSV.dev" in f["message"]]
    assert len(network_findings) == 1
    assert network_findings[0]["severity"] == "MEDIUM"


def test_network_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_network_error)
    source = "FROM alpine:3.18\n"
    # Should complete without raising
    findings = extract_docker_cve("Dockerfile", source)
    assert isinstance(findings, list)


# ── extract_docker_cve: runtime EOL check (node/python) ─────

def _mock_get_eol(cycles_by_product):
    def fake_get(url, timeout=None):
        for product, cycles in cycles_by_product.items():
            if f"/{product}.json" in url:
                return _FakeResponse(cycles)
        return _FakeResponse([])
    return fake_get


def test_node_eol_version_flagged_high(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    monkeypatch.setattr(requests, "get", _mock_get_eol({
        "nodejs": [{"cycle": "14", "eol": "2023-04-30", "latest": "14.21.3"}],
    }))
    source = "FROM node:14.17.0-alpine\n"
    findings = extract_docker_cve("Dockerfile", source)
    eol_findings = [f for f in findings if "end-of-life" in f["message"]]
    assert len(eol_findings) == 1
    assert eol_findings[0]["severity"] == "HIGH"
    assert "2023-04-30" in eol_findings[0]["message"]


def test_node_supported_version_not_flagged(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    monkeypatch.setattr(requests, "get", _mock_get_eol({
        "nodejs": [{"cycle": "20", "eol": False, "latest": "20.11.0"}],
    }))
    source = "FROM node:20.11.0-alpine\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert not any("end-of-life" in f["message"] for f in findings)


def test_python_eol_version_flagged_high(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    monkeypatch.setattr(requests, "get", _mock_get_eol({
        "python": [{"cycle": "3.7", "eol": "2023-06-27", "latest": "3.7.17"}],
    }))
    source = "FROM python:3.7-slim\n"
    findings = extract_docker_cve("Dockerfile", source)
    eol_findings = [f for f in findings if "end-of-life" in f["message"]]
    assert len(eol_findings) == 1
    assert eol_findings[0]["severity"] == "HIGH"


def test_eol_lookup_cycle_not_found_no_crash(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))
    monkeypatch.setattr(requests, "get", _mock_get_eol({
        "nodejs": [{"cycle": "20", "eol": False, "latest": "20.11.0"}],
    }))
    # version 99 won't be in the cycles list — should not crash, no finding
    source = "FROM node:99.0.0-alpine\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []


def test_eol_api_network_failure_no_crash(monkeypatch):
    monkeypatch.setattr(requests, "post", _mock_post_with_vulns({}))

    def fake_get(*args, **kwargs):
        raise requests.ConnectionError("simulated failure")

    monkeypatch.setattr(requests, "get", fake_get)
    source = "FROM node:14.17.0-alpine\n"
    findings = extract_docker_cve("Dockerfile", source)
    # Should not raise; EOL lookup failing just means no EOL finding
    assert isinstance(findings, list)


# ── comments / blank lines ignored ──────────────────────────

def test_comments_and_blank_lines_ignored(monkeypatch):
    called = {"count": 0}

    def fake_post(*args, **kwargs):
        called["count"] += 1
        return _FakeResponse({"vulns": []})

    monkeypatch.setattr(requests, "post", fake_post)
    source = "# FROM alpine:1.0\n\nFROM alpine:3.19\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings == []
    assert called["count"] == 1  # only the real FROM line queried, not the comment


# ── line numbers ─────────────────────────────────────────────

def test_line_numbers_correct(monkeypatch):
    monkeypatch.setattr(
        requests, "post",
        _mock_post_with_vulns({
            "alpine": [{"id": "CVE-2023-1234", "severity": [{"score": "HIGH"}]}]
        }),
    )
    source = "# comment\n\nFROM alpine:3.9\n"
    findings = extract_docker_cve("Dockerfile", source)
    assert findings[0]["line"] == 3