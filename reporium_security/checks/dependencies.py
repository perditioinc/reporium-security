"""Check for known CVEs in Python dependencies using pip-audit."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CVEFinding:
    """A single CVE found in a dependency."""

    package: str
    version: str
    vulnerability_id: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class DependenciesCheckResult:
    """Result of the dependency CVE check."""

    passed: bool = True
    findings: list[CVEFinding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    @property
    def summary(self) -> str:
        if self.skipped:
            return f"Dependency check skipped: {self.skip_reason}"
        if self.passed:
            return "No known CVEs found in dependencies."
        high_critical = [
            f for f in self.findings if f.severity in ("HIGH", "CRITICAL")
        ]
        return (
            f"Found {len(self.findings)} CVE(s) "
            f"({len(high_critical)} HIGH/CRITICAL) in dependencies."
        )

    @property
    def has_high_or_critical(self) -> bool:
        return any(f.severity in ("HIGH", "CRITICAL") for f in self.findings)

    @property
    def has_medium(self) -> bool:
        return any(f.severity == "MEDIUM" for f in self.findings)

    @property
    def has_low(self) -> bool:
        return any(f.severity == "LOW" for f in self.findings)


def check_dependencies(repo_path: Path) -> DependenciesCheckResult:
    """Run pip-audit on requirements.txt if it exists."""
    result = DependenciesCheckResult()
    requirements_file = repo_path / "requirements.txt"

    if not requirements_file.exists():
        result.skipped = True
        result.skip_reason = "No requirements.txt found."
        return result

    try:
        proc = subprocess.run(
            [
                "pip-audit",
                "--requirement",
                str(requirements_file),
                "--format",
                "json",
                "--output",
                "-",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(repo_path),
        )
    except FileNotFoundError:
        result.skipped = True
        result.skip_reason = "pip-audit not installed."
        return result
    except subprocess.TimeoutExpired:
        result.skipped = True
        result.skip_reason = "pip-audit timed out."
        return result

    # pip-audit returns exit code 1 when vulnerabilities are found
    output = proc.stdout.strip()
    if not output:
        return result

    try:
        audit_data = json.loads(output)
    except json.JSONDecodeError:
        result.skipped = True
        result.skip_reason = "Failed to parse pip-audit output."
        return result

    dependencies = audit_data if isinstance(audit_data, list) else audit_data.get("dependencies", [])

    for dep in dependencies:
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            severity = vuln.get("fix_versions", [""])
            # pip-audit doesn't always provide severity directly;
            # we infer from the aliases or default to MEDIUM
            vuln_id = vuln.get("id", "UNKNOWN")
            desc = vuln.get("description", "No description available.")

            # Determine severity from the vulnerability data
            aliases = vuln.get("aliases", [])
            sev = _infer_severity(vuln)

            finding = CVEFinding(
                package=dep.get("name", "unknown"),
                version=dep.get("version", "unknown"),
                vulnerability_id=vuln_id,
                description=desc[:200],
                severity=sev,
            )
            result.findings.append(finding)

    if result.findings:
        result.passed = False

    return result


def _infer_severity(vuln: dict) -> str:
    """Infer severity from pip-audit vulnerability data."""
    # Check if severity is directly available
    if "severity" in vuln:
        return vuln["severity"].upper()

    # Check description for severity hints
    desc = vuln.get("description", "").upper()
    if "CRITICAL" in desc:
        return "CRITICAL"
    if "HIGH" in desc:
        return "HIGH"
    if "LOW" in desc:
        return "LOW"

    return "MEDIUM"
