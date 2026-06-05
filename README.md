# SpiritCLI

> Real-Time Dependency Security Intelligence for Modern Applications

---

# Overview

SpiritCLI is a next-generation dependency security intelligence platform designed to detect risks that traditional Software Composition Analysis (SCA) tools fail to identify.

Existing tools such as npm audit, Snyk, Dependabot, and OWASP Dependency Check focus primarily on known vulnerabilities (CVEs). While useful, they ignore a much larger security problem:

A dependency can be completely free of CVEs and still be dangerous when configured incorrectly.

Examples:

- bcrypt configured with rounds=4
- JWT configured with algorithm=none
- axios configured with TLS verification disabled
- express applications running without security middleware

SpiritCLI addresses this gap by analyzing:

1. Dependency vulnerabilities
2. Dependency configurations
3. Dependency trustworthiness
4. Dependency usage paths
5. Dependency hygiene
6. Security trends over time

The goal is to answer:

"Is this dependency, configured the way YOUR application configures it, safe for production use?"

---

# Problem Statement

Modern applications depend heavily on open-source software.

A typical backend service may contain:

- 50–100 direct dependencies
- 500–2000 transitive dependencies

Current dependency scanners answer:

"Does this package have a known CVE?"

SpiritCLI answers:

- How is this package configured?
- Is the configuration secure?
- Is the package trustworthy?
- Is the vulnerable package actually reachable?
- Is security improving or degrading?

---

# Key Features

## Feature 1: Configuration Context Analysis

Detects insecure dependency configurations.

Examples:

bcrypt:

```js
bcrypt.hashSync(password, 4);
```

JWT:

```js
jwt.sign(data, key, {
  algorithm: "none",
});
```

Axios:

```js
rejectUnauthorized: false;
```

SpiritCLI parses source code, extracts configuration values, and compares them against a security knowledge base.

---

## Feature 2: Transitive Dependency Risk Tracing

Builds dependency graphs and traces vulnerability paths.

Example:

processPayment()
↓
payment-sdk
↓
bank-utils
↓
crypto-js
↓
MD5

Developers can immediately understand risk impact.

---

## Feature 3: Security Health Fingerprint

Computes a dynamic security score.

Factors:

| Factor                  | Weight |
| ----------------------- | ------ |
| Configuration Safety    | 30%    |
| CVE Exposure            | 25%    |
| Provenance Trust        | 20%    |
| Dependency Freshness    | 15%    |
| Phantom Dependency Risk | 10%    |

Zones:

| Score  | Status     |
| ------ | ---------- |
| 0–35   | Quarantine |
| 36–70  | Warning    |
| 71–100 | Safe       |

---

## Feature 4: Risk-Based Push Enforcement

Git pushes are evaluated before deployment.

Quarantine:

Push blocked.

Warning:

Developer acknowledgment required.

Safe:

Push proceeds normally.

---

## Feature 5: Provenance Trust Score

Evaluates supply-chain trust.

Checks:

- Maintainer activity
- Repository activity
- Package freshness
- Typosquatting
- Publication integrity

---

## Feature 6: Phantom Dependency Detection

Detects:

### Ghost Dependencies

Declared but unused.

### Undeclared Imports

Used but not declared.

---

## Feature 7: Smart Auto Remediation

Automatically generates fixes.

Examples:

```diff
- bcrypt.hashSync(password,4)
+ bcrypt.hashSync(password,12)
```

---

## Feature 8: Spirit Report

Generates:

- Terminal reports
- JSON reports
- HTML reports
- Security trends
- Root cause analysis

---

# Project Structure

```text
SpiritCLI/
├── spirit.py
├── spirit/
├── tests/
├── docs/
├── demo_apps/
├── README.md
├── ARCHITECTURE.md
└── requirements.txt
```

---

# Technology Stack

## Language

Python 3.11+

## CLI

- Click
- Rich

## Parsing

- Tree-Sitter
- Python AST

## Storage

- SQLite

## APIs

- OSV
- GitHub
- npm Registry
- PyPI

## Version Control

- GitPython
- Git Hooks

---

# Commands

## Scan

```bash
spirit scan .
```

Performs:

- CVE Analysis
- Config Analysis
- Trust Analysis
- Fingerprint Generation

---

## Watch

```bash
spirit watch .
```

Real-time monitoring.

---

## Push

```bash
spirit push
```

Security gate.

---

## Fix

```bash
spirit fix
```

Apply remediation.

---

## Report

```bash
spirit report
```

Generate reports.

---

# Team Members

## Tarun

- Architecture
- Security Fingerprint
- Rule Design
- Integration

## Lokesh

- AST Engine
- Dependency Graphs
- Tracing

## Likhith

- CLI
- Git Integration
- Watch System

## Anish

- Reporting
- Database
- External APIs

---

# Development Phases

Phase 1

- CLI
- CVE Scanning
- Security Score

Phase 2

- AST Analysis
- Config Rules

Phase 3

- Push Enforcement
- Reports

Phase 4

- Provenance
- Auto Remediation

---

# docs/

Contains project documentation.

Purpose:

- Architecture diagrams
- Scoring documentation
- API documentation
- Development guides

Files:

architecture.md
scoring.md
api_reference.md

Users never execute files from docs.

This folder is for developers.

---

# demo_apps/

Contains intentionally vulnerable applications.

Purpose:

Demonstrate SpiritCLI capabilities.

Examples:

vulnerable_bank_app/
secure_bank_app/

Used for:

- Testing
- Demonstrations
- Presentations

---

# tests/

Contains all automated tests.

Purpose:

Validate system correctness.

Examples:

test_ast.py
test_scoring.py
test_fixer.py

Every major module should have corresponding tests.

---

# spirit/

Contains the actual implementation of SpiritCLI.

This is the core application directory.

All features are implemented here.

---

# Future Scope

- Multi-language support
- Java support
- Rust support
- IDE Extensions
- VSCode Integration
- AI-assisted remediation
- Kubernetes security scanning
