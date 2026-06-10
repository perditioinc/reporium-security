# reporium-security

![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen)

<!-- perditio-badges -->
[![Suite: Reporium](https://img.shields.io/badge/suite-Reporium-blue)](https://github.com/perditioinc)
[![CI](https://github.com/perditioinc/reporium-security/actions/workflows/test.yml/badge.svg)](https://github.com/perditioinc/reporium-security/actions/workflows/test.yml)
<!-- /perditio-badges -->

<!-- perditio-badges:security -->
![Security Grade: A](https://img.shields.io/badge/security-A-brightgreen)
<!-- /perditio-badges:security -->

Security scanning tool that checks all public repos for secrets, CVEs, workflow issues, and file exposure.

## What It Does

Runs 5 security checks on any repository:

1. **Secrets** -- Pattern matching against source files for hardcoded credentials (GitHub PATs, AWS keys, API keys, passwords)
2. **Dependencies** -- Runs pip-audit to find known CVEs in Python dependencies
3. **Workflows** -- Validates GitHub Actions workflows use SHA-pinned actions, avoid dangerous triggers, and follow least-privilege permissions
4. **Files** -- Checks for sensitive files (.env, .pem, .key, .p12, .pfx) tracked in git
5. **History** -- Scans recent git history (last 20 commits) for secrets that may have been committed then removed

## Install

```bash
pip install git+https://github.com/perditioinc/reporium-security.git
```

## Usage

Scan the current directory:

```bash
reporium-security scan
```

Scan a GitHub repository:

```bash
reporium-security scan perditioinc/repo-name
```

Generate a report file:

```bash
reporium-security scan . --output SECURITY_REPORT.md
```

Use as a module:

```python
from reporium_security import scan_repo

report = scan_repo(".")
print(report.grade)   # A, B, C, D, or F
print(report.summary)
```

## Reusable Workflow

Other repos can call the security scan workflow:

```yaml
jobs:
  security:
    uses: perditioinc/reporium-security/.github/workflows/security-scan.yml@main
```

## Grade System

| Grade | Meaning |
|-------|---------|
| **A** | All 5 checks pass, 0 issues |
| **B** | 1 warning (low CVE or unpinned action) |
| **C** | 2 warnings or 1 medium CVE |
| **D** | Any check fails structurally (workflow errors, high/critical CVE) |
| **F** | Any exposed secret found (source files, tracked files, or git history) |

## Development

```bash
git clone https://github.com/perditioinc/reporium-security.git
cd reporium-security
pip install -e ".[dev]"
pytest tests/ -v
```
