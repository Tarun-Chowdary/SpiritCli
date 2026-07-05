"""
integrations/secrets_scanner.py — SpiritCLI hardcoded secrets scanner

Catches credentials committed directly into source code — API keys, AWS
keys, private key blocks, database connection strings with embedded
passwords, and generic "password = '...'" style assignments.

Language-agnostic: secrets don't care whether they're sitting in a .js,
.py, .env, or config file, so this runs as a plain text/regex pass over
raw source rather than going through either language's AST extractor.
Feeds config_score, same bucket as bcrypt/jwt/axios/dockerfile findings.

Deliberately conservative on false positives: obvious placeholders
("changeme", "your_api_key_here", "xxxx", "<REDACTED>", etc.) are
excluded, since a scanner that cries wolf on every example/test fixture
gets ignored. Real secret scanners (gitleaks, trufflehog) additionally
use Shannon entropy scoring to catch low-signature secrets — that's a
reasonable v2 addition, not required for the common, recognizable
patterns this covers today.
"""

import re

PLACEHOLDER_HINTS = (
    "changeme", "change_me", "your_", "example", "xxxx", "placeholder",
    "<", "redacted", "insert_", "replace_", "todo", "fixme", "dummy",
    "test123", "sample", "notarealkey", "notreal",
)


def _looks_like_placeholder(value):
    lowered = value.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


def _finding(severity, file_path, line_num, message, fix, category="secret"):
    return {
        "severity": severity,
        "file": file_path,
        "line": line_num,
        "message": message,
        "fix": fix,
        "category": category,
    }


# Each rule: (name, compiled pattern, severity, message template, fix template)
# Pattern must have a capturing group for the matched secret value where
# applicable, used only for the placeholder check — never reproduced in
# the finding message itself.
_RULES = [
    (
        "aws_access_key",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "critical",
        "Hardcoded AWS Access Key ID detected.",
        "Remove the key from source, rotate it immediately in AWS IAM, "
        "and load credentials via environment variables or a secrets manager.",
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
        "Private key block committed directly in source.",
        "Remove the key from source and rotate it — anything committed to "
        "version control must be treated as compromised, even after deletion.",
    ),
    (
        "github_token",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        "critical",
        "Hardcoded GitHub personal access token detected.",
        "Revoke the token in GitHub settings and load it via environment "
        "variables or a secrets manager instead.",
    ),
    (
        "slack_token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b"),
        "high",
        "Hardcoded Slack token detected.",
        "Revoke the token in Slack app settings and load it via environment "
        "variables instead.",
    ),
    (
        "db_connection_string_with_credentials",
        re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:\s'\"]+:([^@\s'\"]+)@"),
        "critical",
        "Database connection string with embedded credentials found in source.",
        "Move the connection string to an environment variable and remove "
        "the embedded password from source.",
    ),
    (
        "generic_api_key_assignment",
        re.compile(
            r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)"
            r"\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
            re.IGNORECASE,
        ),
        "high",
        "Hardcoded API key or secret assignment found in source.",
        "Move this value to an environment variable or secrets manager, "
        "and rotate the key since it may already be exposed via git history.",
    ),
    (
        "known_secret_value_shape",
        # Matched by the SECRET'S OWN shape, not the variable name it's
        # assigned to — catches cases like `stripe_secret: "sk_live_..."`
        # or `foo = "sk_live_..."` that variable-name-based matching above
        # would miss entirely. Prefixes are real, publicly-documented
        # formats used by these providers.
        re.compile(
            r"\b(sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|"
            r"pk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|"
            r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b"
        ),
        "critical",
        "Hardcoded provider secret key detected (recognized key format, "
        "e.g. Stripe or SendGrid).",
        "Remove the key from source, rotate it in the provider's dashboard, "
        "and load it via environment variables or a secrets manager.",
    ),
    (
        "generic_password_assignment",
        re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]",
            re.IGNORECASE,
        ),
        "critical",
        "Hardcoded password assignment found in source.",
        "Move this value to an environment variable or secrets manager, "
        "and rotate the credential.",
    ),
]


def scan_source(file_path, source):
    """
    Scan a single file's source text for hardcoded secrets.
    Returns a list of finding dicts. Never raises — a scan failure on one
    file (e.g. binary content misread as text) should not break the rest
    of a scan.
    """
    findings = []
    try:
        lines = source.split("\n")
    except Exception:
        return findings

    for line_num, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        for name, pattern, severity, message, fix in _RULES:
            for match in pattern.finditer(raw_line):
                # if the rule captured a value, skip obvious placeholders
                if match.groups():
                    captured = match.group(1)
                    if _looks_like_placeholder(captured):
                        continue
                findings.append(_finding(
                    severity, file_path, line_num, message, fix,
                ))

    return findings