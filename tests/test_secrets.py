"""
tests/test_secrets.py — SpiritCLI hardcoded secrets scanner tests
"""

import pytest
from integrations.secrets_scanner import scan_source


def _messages(findings):
    return [f["message"] for f in findings]


# ── real secrets: should all fire ───────────────────────────

def test_aws_access_key_detected():
    fake_key = "AKIA" + "ZQ3DSKFHRT6NXJPL"  # split so it's not a scannable literal
    source = f'const AWS_KEY = "{fake_key}";'
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "AWS" in findings[0]["message"]


def test_private_key_block_detected():
    source = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "Private key" in findings[0]["message"]


def test_github_token_detected():
    token = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
    source = f'token = "{token}"'
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert "GitHub" in findings[0]["message"]


def test_slack_token_detected():
    fake_token = "xoxb-" + "1234567890-abcdefghijklmnop"
    source = f'SLACK_TOKEN = "{fake_token}"'
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert "Slack" in findings[0]["message"]


def test_db_connection_string_with_password_detected():
    source = 'DATABASE_URL = "postgres://admin:SuperSecret123@db.prod.internal:5432/bank"'
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "connection string" in findings[0]["message"]


def test_generic_api_key_assignment_detected():
    source = 'api_key = "sk_abcdefghijklmnop1234567890"'
    findings = scan_source("test.js", source)
    assert any("API key" in m for m in _messages(findings))


def test_generic_password_assignment_detected():
    source = 'password: "hunter2ActualPass!"'
    findings = scan_source("test.js", source)
    assert len(findings) == 1
    assert "password" in findings[0]["message"].lower()


def test_stripe_style_key_detected_by_value_shape():
    # variable name doesn't match any name-based rule — must be caught by
    # the secret's own recognizable value shape instead
    fake_key = "sk_live_" + "51H8xyzABCDEFGHIJKLMNOP"
    source = f'stripe_secret: "{fake_key}",'
    findings = scan_source("test.js", source)
    assert any("provider secret" in m.lower() for m in _messages(findings))


def test_sendgrid_style_key_detected():
    fake_key = "SG." + "abcdefghijklmnop" + "." + "qrstuvwxyz1234567890ABCD"
    source = f'SENDGRID_KEY = "{fake_key}"'
    findings = scan_source("test.js", source)
    assert any("provider secret" in m.lower() for m in _messages(findings))


# ── placeholders / examples: should stay silent ─────────────

def test_placeholder_password_not_flagged():
    source = 'password: "changeme"'
    findings = scan_source("test.js", source)
    assert findings == []


def test_example_api_key_not_flagged():
    source = 'api_key = "your_api_key_here_1234567890"'
    findings = scan_source("test.js", source)
    assert findings == []


def test_todo_secret_not_flagged():
    source = 'secret_key: "TODO_REPLACE_ME_1234567890"'
    findings = scan_source("test.js", source)
    assert findings == []


def test_empty_password_not_flagged():
    source = 'password = ""'
    findings = scan_source("test.js", source)
    assert findings == []


def test_aws_documented_example_key_not_flagged():
    # AWS's own published example key from their documentation
    fake_key = "AKIA" + "IOSFODNN7EXAMPLE"
    source = f'const AWS_KEY = "{fake_key}";'
    findings = scan_source("test.js", source)
    assert findings == []


def test_test_db_connection_with_placeholder_password_not_flagged():
    source = 'DATABASE_URL = "postgres://user:changeme@localhost/test"'
    findings = scan_source("test.js", source)
    assert findings == []


def test_plain_comment_not_flagged():
    source = "// remember to set your password before deploying"
    findings = scan_source("test.js", source)
    assert findings == []


def test_blank_and_whitespace_lines_ignored():
    source = "\n\n   \n\t\n"
    findings = scan_source("test.js", source)
    assert findings == []


# ── multi-secret file ────────────────────────────────────────

def test_multiple_secrets_in_one_file_all_detected():
    fake_aws = "AKIA" + "ZQ3DSKFHRT6NXJPL"
    fake_stripe = "sk_live_" + "51H8xyzABCDEFGHIJKLMNOP"
    source = (
        'const DATABASE_URL = "postgres://admin:Pr0dP@ssw0rd!@db.internal:5432/bank";\n'
        '\n'
        'const config = {\n'
        f'  aws_key: "{fake_aws}",\n'
        f'  stripe_secret: "{fake_stripe}",\n'
        '};\n'
    )
    findings = scan_source("config.js", source)
    assert len(findings) == 3


# ── line numbers ─────────────────────────────────────────────

def test_line_numbers_correct():
    fake_key = "AKIA" + "ZQ3DSKFHRT6NXJPL"
    source = f"// line 1\n// line 2\nconst AWS_KEY = \"{fake_key}\";\n"
    findings = scan_source("test.js", source)
    assert findings[0]["line"] == 3


# ── robustness ───────────────────────────────────────────────

def test_does_not_raise_on_non_string_input():
    # scan_source should degrade gracefully, never raise, even on
    # unexpected input (e.g. a file read as bytes rather than str upstream)
    findings = scan_source("test.js", 12345)
    assert findings == []


def test_category_tagged_as_secret():
    fake_key = "AKIA" + "ZQ3DSKFHRT6NXJPL"
    source = f'const AWS_KEY = "{fake_key}";'
    findings = scan_source("test.js", source)
    assert all(f["category"] == "secret" for f in findings)