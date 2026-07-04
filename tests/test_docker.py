"""
tests/test_docker.py — SpiritCLI Dockerfile hygiene linter tests
"""

import pytest
from integrations.docker import extract_docker_config


def _severities(findings):
    return [f["severity"] for f in findings]


def _messages(findings):
    return [f["message"] for f in findings]


# ── FROM / base image tag ───────────────────────────────────

def test_missing_tag_flagged():
    source = "FROM node\nCMD [\"node\", \"app.js\"]"
    findings = extract_docker_config("Dockerfile", source)
    assert any("no tag" in m for m in _messages(findings))


def test_latest_tag_flagged():
    source = "FROM node:latest\nCMD [\"node\", \"app.js\"]"
    findings = extract_docker_config("Dockerfile", source)
    assert any("mutable" in m for m in _messages(findings))


def test_pinned_tag_not_flagged_for_mutability():
    source = "FROM node:18.19.0-alpine\nUSER node\nHEALTHCHECK CMD true"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("mutable" in m or "no tag" in m for m in _messages(findings))


def test_digest_pinned_not_flagged():
    source = "FROM node@sha256:abcdef1234567890\nUSER node\nHEALTHCHECK CMD true"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("mutable" in m or "no tag" in m for m in _messages(findings))


# ── USER instruction (root check) ───────────────────────────

def test_missing_user_flagged_as_root():
    source = "FROM node:18.19.0-alpine\nCOPY . .\nCMD [\"node\", \"app.js\"]"
    findings = extract_docker_config("Dockerfile", source)
    assert any("root" in m.lower() for m in _messages(findings))


def test_user_present_not_flagged_as_root():
    source = "FROM node:18.19.0-alpine\nUSER appuser\nCMD [\"node\", \"app.js\"]"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("root" in m.lower() for m in _messages(findings))


# ── HEALTHCHECK ──────────────────────────────────────────────

def test_missing_healthcheck_flagged():
    source = "FROM node:18.19.0-alpine\nUSER appuser\nCMD [\"node\", \"app.js\"]"
    findings = extract_docker_config("Dockerfile", source)
    assert any("healthcheck" in m.lower() for m in _messages(findings))


def test_healthcheck_present_not_flagged():
    source = (
        "FROM node:18.19.0-alpine\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
        "CMD [\"node\", \"app.js\"]"
    )
    findings = extract_docker_config("Dockerfile", source)
    assert not any("healthcheck" in m.lower() for m in _messages(findings))


# ── ADD vs COPY ──────────────────────────────────────────────

def test_add_remote_url_flagged_medium():
    source = "FROM node:18.19.0-alpine\nADD https://example.com/file.tar.gz /app/\n"
    findings = extract_docker_config("Dockerfile", source)
    add_findings = [f for f in findings if "ADD" in f["message"]]
    assert len(add_findings) == 1
    assert add_findings[0]["severity"] == "medium"


def test_add_local_file_flagged_low():
    source = "FROM node:18.19.0-alpine\nADD localfile.tar.gz /app/\n"
    findings = extract_docker_config("Dockerfile", source)
    add_findings = [f for f in findings if "ADD" in f["message"]]
    assert len(add_findings) == 1
    assert add_findings[0]["severity"] == "low"


def test_copy_not_flagged():
    source = "FROM node:18.19.0-alpine\nCOPY localfile.tar.gz /app/\n"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("ADD" in m for m in _messages(findings))


# ── Secrets in ENV/ARG ───────────────────────────────────────

def test_secret_in_env_flagged_critical():
    source = "FROM node:18.19.0-alpine\nENV DB_PASSWORD=hunter2\n"
    findings = extract_docker_config("Dockerfile", source)
    secret_findings = [f for f in findings if "secret" in f["message"].lower()]
    assert len(secret_findings) == 1
    assert secret_findings[0]["severity"] == "critical"


def test_secret_in_arg_flagged_critical():
    source = "FROM node:18.19.0-alpine\nARG API_KEY=abc123\n"
    findings = extract_docker_config("Dockerfile", source)
    secret_findings = [f for f in findings if "secret" in f["message"].lower()]
    assert len(secret_findings) == 1
    assert secret_findings[0]["severity"] == "critical"


def test_env_without_secret_hint_not_flagged():
    source = "FROM node:18.19.0-alpine\nENV NODE_ENV=production\n"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("secret" in m.lower() for m in _messages(findings))


# ── apt-get cleanup ──────────────────────────────────────────

def test_apt_get_without_cleanup_flagged_low():
    source = "FROM debian:12\nRUN apt-get install -y curl\n"
    findings = extract_docker_config("Dockerfile", source)
    apt_findings = [f for f in findings if "apt-get" in f["message"]]
    assert len(apt_findings) == 1
    assert apt_findings[0]["severity"] == "low"


def test_apt_get_with_cleanup_not_flagged():
    source = (
        "FROM debian:12\n"
        "RUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    )
    findings = extract_docker_config("Dockerfile", source)
    assert not any("apt-get" in m for m in _messages(findings))


# ── comments / blank lines ignored ──────────────────────────

def test_comments_and_blank_lines_ignored():
    source = "# base image\n\nFROM node:18.19.0-alpine\n# run as non-root\nUSER appuser\n"
    findings = extract_docker_config("Dockerfile", source)
    assert not any("root" in m.lower() or "no tag" in m for m in _messages(findings))


# ── line numbers ─────────────────────────────────────────────

def test_line_numbers_correct():
    source = "FROM node\nRUN echo hi\nCMD [\"node\"]"
    findings = extract_docker_config("Dockerfile", source)
    from_finding = next(f for f in findings if "no tag" in f["message"])
    assert from_finding["line"] == 1


# ── category tagging ─────────────────────────────────────────

def test_all_findings_tagged_config_category():
    source = "FROM node:latest\nENV SECRET=abc\n"
    findings = extract_docker_config("Dockerfile", source)
    assert all(f["category"] == "config" for f in findings)