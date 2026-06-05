# SpiritCLI Architecture

---

# High-Level Architecture

                 +----------------+
                 |   CLI Layer    |
                 +--------+-------+
                          |
                          v
                 +----------------+
                 | Scan Engine    |
                 +--------+-------+
                          |
      +-------------------+------------------+
      |                   |                  |
      v                   v                  v

+-----------+ +---------------+ +---------------+
| AST Layer | | Dependency | | Registry APIs |
| | | Graph Layer | | |
+-----------+ +---------------+ +---------------+
| | |
+-------------------+------------------+
|
v
+----------------+
| Findings Engine|
+--------+-------+
|
v
+----------------+
| Scoring Engine |
+--------+-------+
|
v
+----------------+
| Reporting |
+----------------+

---

# Execution Flow

Example:

```bash
spirit scan .
```

Flow:

1. CLI receives command
2. Engine initializes scan
3. Dependencies collected
4. CVEs queried
5. Source code parsed
6. Configurations extracted
7. Rules applied
8. Findings generated
9. Score computed
10. Report generated

---

# Layer 1: CLI Layer

Responsible for:

User interaction.

Commands:

- scan
- watch
- push
- fix
- report

Files:

cli/

Purpose:

Convert user requests into engine operations.

---

# Layer 2: Scan Engine

Main orchestration layer.

Files:

core/

Responsibilities:

- Scan lifecycle
- Findings aggregation
- Coordination

Acts as the project brain.

---

# Layer 3: AST Analysis Layer

Purpose:

Understand source code.

Process:

Source Code
↓
Parser
↓
AST
↓
Visitors
↓
Extractors
↓
Configurations

Example:

```js
bcrypt.hashSync(password, 4);
```

Extracted:

```json
{
  "library": "bcrypt",
  "parameter": "rounds",
  "value": 4
}
```

---

# Layer 4: Configuration Analysis

Purpose:

Determine if extracted values are safe.

Example Rule:

```json
{
  "library": "bcrypt",
  "parameter": "rounds",
  "minimum": 10
}
```

Detected:

```json
{
  "value": 4
}
```

Result:

Critical Finding

---

# Layer 5: Dependency Graph Engine

Purpose:

Map package relationships.

Example:

```text
Application
│
├── payment-sdk
│
├── bank-utils
│
└── crypto-js
```

Supports:

- tracing
- blast radius analysis
- path visualization

---

# Layer 6: Provenance Engine

Purpose:

Supply-chain trust analysis.

Inputs:

GitHub API
npm Registry
PyPI

Outputs:

Trust Score

---

# Layer 7: Phantom Dependency Engine

Builds:

Manifest Graph

```json
package.json
```

vs

Import Graph

```js
import axios
```

Comparison detects:

- Ghost dependencies
- Undeclared imports

---

# Layer 8: Scoring Engine

Computes fingerprint.

Formula:

Score =
ConfigSafety × 0.30

- CVEExposure × 0.25
- Trust × 0.20
- Freshness × 0.15
- PhantomRisk × 0.10

Output:

```text
78/100
SAFE
```

---

# Layer 9: Git Enforcement

Installed as:

pre-push hook

Process:

Developer Push
↓
Run Scan
↓
Compute Score
↓
Evaluate Zone
↓
Allow / Block

---

# Layer 10: Reporting

Generates:

Terminal
JSON
HTML

Contains:

- Findings
- Scores
- Trends
- Root Cause Analysis

---

# Database Architecture

SQLite

Tables:

scans
findings
scores
audit_logs
history

Purpose:

Store security history.

---

# Security Knowledge Base

Location:

config_analysis/knowledge_base/

Contains:

bcrypt.json
jwt.json
axios.json
express.json

Purpose:

Centralized security rules.

---

# Testing Strategy

Unit Tests

- AST
- Scoring
- Rules

Integration Tests

- Scan Pipeline
- Reporting

End-to-End Tests

- Vulnerable Banking App
- Secure Banking App

---

# Design Principles

1. Modular Architecture
2. Offline First
3. Extensible Rules
4. Language Agnostic Future
5. Fast Incremental Scanning
6. Security By Default
7. Explainable Findings
