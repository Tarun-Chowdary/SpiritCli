# SpiritCLI

**Real-Time Dependency Security Intelligence for Banking Codebases**

[![PyPI version](https://img.shields.io/pypi/v/spiritcli.svg)](https://pypi.org/project/spiritcli/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-121%2B%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)

SpiritCLI is an offline-first CLI security scanner that goes beyond CVE checks — combining AST-based configuration analysis, transitive dependency graphing, supply-chain provenance scoring, and CI/CD-ready reporting for security-critical codebases like banking applications.

```bash
pip install spiritcli
```

---

## Table of Contents

- [Why SpiritCLI](#why-spiritcli)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [Security Fingerprint Score](#security-fingerprint-score)
- [Architecture](#architecture)
- [CI/CD Integration](#cicd-integration)
- [Comparison with Other Tools](#comparison-with-other-tools)
- [Compliance Mapping](#compliance-mapping)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Team](#team)
- [License](#license)

---

## Why SpiritCLI

Traditional scanners (Dependabot, Trivy, Snyk) only check **declared** dependencies against known CVEs. That leaves major blind spots:

- A codebase with 50 direct dependencies can have 500–2000 transitive ones — invisible to standard scanners.
- Misconfigurations with zero CVEs (e.g. `bcrypt rounds=4`, `JWT alg:'none'`, disabled TLS validation) can be just as dangerous as a known vulnerability.
- Static reports arrive long after insecure code ships to production.
- Supply-chain attacks (SolarWinds, XZ Utils) are ignored entirely by CVE-only tooling.

SpiritCLI addresses all four gaps in a single, offline-first CLI tool.

---

## Features

### AST-Based Configuration Analysis

Uses Tree-sitter (JS/TS) and Python's `ast` module — not regex — to catch dangerous config patterns, including resolved constants and commented-out code that regex tools get wrong.

Detects: weak `bcrypt` rounds, `jsonwebtoken alg:'none'`, `axios rejectUnauthorized:false`, `mongoose strict:false`, `lodash.merge` prototype pollution, Express CORS wildcards, missing/misconfigured `helmet()`.

### Direct & Transitive CVE Scanning

- Checks `package.json` / `requirements.txt` dependencies against **OSV.dev** and GitHub Security Advisories
- Parses `package-lock.json` (v1/v2/v3) and builds a full dependency graph
- Uses BFS to trace the exact edge path from your functions to a vulnerable transitive dependency (e.g. `processPayment() → bank-utils → payment-sdk → crypto-js [MD5]`)
- Handles circular dependency graphs without infinite loops

### Secrets Detection

Scans for AWS keys, GitHub PATs, Slack tokens, DB connection strings, PEM private keys, Stripe/SendGrid keys, and 50+ secret patterns, with entropy analysis and placeholder/test-fixture filtering to reduce false positives.

### OS & Container Layer Scanning

- Dockerfile hygiene (secrets in ENV/ARG, missing `USER`, mutable `:latest` tags, risky `ADD`)
- Base-image CVE scanning (Alpine/Debian/Ubuntu)
- Runtime EOL checks via `endoflife.date` (flags deprecated Node.js/Python before deployment)

### Provenance Trust Score

Scores whether a dependency can be trusted _before_ asking if it's vulnerable — maintainer concentration, maintenance activity, publication integrity (npm/PyPI vs GitHub source diff), typosquatting detection, download anomaly detection.

### Phantom Dependency Detector

Builds two parallel graphs (declared manifest vs. actual imports) to catch:

- **Ghost dependencies** — declared but never imported
- **Undeclared imports** — used but not declared, silently relying on transitive resolution

### Dependency Freshness Detector

Scores direct _and_ transitive dependencies against real registry data, surfacing version gaps with full chain context.

### Security Fingerprint & Git Enforcement

A weighted 0–100 score (Configuration Safety 30%, CVE Exposure 25%, Provenance Trust 20%, Dependency Freshness 15%, Phantom Risk 10%) that gates git pushes:

| Zone          | Score  | Behavior                                      |
| ------------- | ------ | --------------------------------------------- |
| 🔴 Quarantine | 0–35   | Push blocked on any critical finding          |
| 🟡 Warning    | 36–70  | Push allowed, mandatory acknowledgment logged |
| 🟢 Safe       | 71–100 | Clean push, brief summary only                |

### Smart Auto-Remediation (`spirit fix`)

- Configuration fixes (e.g. `rounds=4 → rounds=12`) as reviewable diffs — nothing applied blindly
- Context-aware version upgrades that check your actual API usage against target changelogs
- Automatic manifest fixes for ghost/undeclared dependencies

### SBOM Export & License Compliance

CycloneDX-compliant SBOM (JSON/XML/SPDX) with full transitive graph, component hashes, and purl identifiers. License compliance via SPDX + ClearlyDefined with whitelist/blacklist policy enforcement.

### Reporting

Per-file health breakdown, degradation root-cause analysis, ASCII/SVG/HTML score trajectory graphs, and trend classification (Improving/Degrading/Volatile/Stable).

---

## Installation

```bash
pip install spiritcli
```

Requires Python 3.8+.

## Quick Start

```bash
# Initialize git hooks (pre-push scan enforcement)
spirit install-hooks

# Run a full scan
spirit scan

# Auto-remediate findings (reviewable diffs)
spirit fix

# Generate a full security report
spirit report --format html

# Export a CycloneDX SBOM
spirit sbom --format cyclonedx

# Watch mode — real-time scanning during development
spirit watch
```

## CLI Commands

| Command                | Description                                            |
| ---------------------- | ------------------------------------------------------ |
| `spirit scan`          | Full security scan (CVE, config, secrets, provenance)  |
| `spirit fix`           | Auto-remediate findings via reviewable diffs           |
| `spirit watch`         | Continuous real-time scanning                          |
| `spirit report`        | Generate detailed security report (terminal/JSON/HTML) |
| `spirit push`          | Git pre-push enforcement hook                          |
| `spirit audit`         | View SQLite audit trail                                |
| `spirit license`       | License compliance check                               |
| `spirit sbom`          | Export CycloneDX SBOM                                  |
| `spirit install-hooks` | Wire SpiritCLI into git hooks                          |
| `spirit diff`          | Diff-scan — only scan what changed                     |

---

## Security Fingerprint Score

```
Configuration Safety      30%   ███████████░░░░░░░░░  55
CVE Exposure              25%   ██████████████░░░░░░  72
Provenance Trust          20%   ████████████████░░░░  80
Dependency Freshness      15%   ████████████░░░░░░░░  60
Phantom Dep. Risk         10%   ██████████████░░░░░░  70

Overall: 68/100 — WARNING ZONE
```

---

## Architecture

```
CLI Interface     spirit watch | spirit scan | spirit push | spirit fix | spirit report
        ↓
Analysis Engines  AST Parser | Import Graph | Fingerprint Engine | Registry APIs | Manifest Diff
        ↓
Data Sources      OSV/CVE DB | npm/PyPI APIs | GitHub API | Git Diff Engine | SPDX/ClearlyDefined
        ↓
Output Layer      Terminal (ASCII) | JSON (CI/CD) | HTML Report | Git Hook | GitHub Actions
```

Offline-first by design — all core analysis runs locally, no cloud dependency on the developer machine.

---

## CI/CD Integration

Zero rip-and-replace — drop into your existing pipeline:

```
git commit → spirit scan (hook) → git push → CI: spirit scan --diff → Merge gate → SIEM / audit log
```

Example GitHub Actions step:

```yaml
- name: SpiritCLI Security Scan
  run: |
    pip install spiritcli
    spirit scan --diff --format json --output spirit-report.json
```

Exit codes map directly to pass/fail build steps. JSON output feeds any pipeline gate or policy check.

---

## Comparison with Other Tools

| Capability                                | Dependabot | Trivy   | Snyk                     | SpiritCLI                       |
| ----------------------------------------- | ---------- | ------- | ------------------------ | ------------------------------- |
| CVE scanning (direct deps)                | Yes        | Yes     | Yes                      | Yes                             |
| Transitive BFS chain tracing to your code | Partial    | No      | Reachability (paid tier) | **Yes — free, exact edge path** |
| Config-context AST analysis               | No         | No      | No                       | **Yes**                         |
| Phantom/ghost dependency detection        | No         | No      | No                       | **Yes**                         |
| Provenance & trust score                  | No         | No      | No                       | **Yes**                         |
| Runtime EOL checks                        | No         | No      | No                       | **Yes**                         |
| SBOM export (CycloneDX)                   | No         | Partial | Yes                      | **Yes**                         |
| Cost                                      | Free       | Free    | $25–105/user/mo          | **Free, open source**           |

---

## Compliance Mapping

| SpiritCLI Feature       | Standard                        |
| ----------------------- | ------------------------------- |
| SBOM Export (CycloneDX) | US Executive Order 14028        |
| Secrets Detection       | PCI-DSS Req 3.6, SOC 2 CC6.1    |
| Audit Logging (SQLite)  | Banking change-control mandates |

---

## Testing

121+ automated tests covering circular dependency graphs, BOM edge cases, network failure handling, multi-hop transitive chains, and AST edge cases.

```bash
pip install -e ".[dev]"
pytest
```

---

## Roadmap

- [ ] **Real Data-Flow Analysis** — full variable-level taint tracking from source to sink
- [ ] **LLM-Powered Remediation** — local, privacy-first LLMs for complex multi-file fixes
- [ ] **Team Live Dashboard** — centralized real-time portal for org-wide fingerprint monitoring
- [ ] **Automated Threat Emails** — instant alerts on QUARANTINE-zone drops or critical secrets

---

## Contributing

Contributions are welcome! Please open an issue to discuss significant changes before submitting a PR.

```bash
git clone https://github.com/<org>/spiritcli.git
cd spiritcli
pip install -e ".[dev]"
pytest
```

---

## 📫 Contact / Support

- For questions, suggestions, or support, please open an issue on the [GitHub repository](https://github.com/Tarun-Chowdary/SpiritCli/issues).
- You can also reach out via email: yegi.2992@gmail.com

---

## License

MIT License. See [LICENSE](LICENSE) for details.

```
>_ spirit scan --complete
pip install spiritcli
```

---

<div align="center">

If this project helped you, consider giving it a ⭐ on GitHub — it helps a lot!

**Built with 🔐 and a lot of ☕**

</div>
