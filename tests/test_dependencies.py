"""Tests for the dependency CVE scanner.

This is the fifth scanner and previously had no coverage. All tests mock the
`pip-audit` subprocess invocation so they run fully offline: no live network,
no pip-audit install, no PyPI advisory database. The mock returns canned JSON
in pip-audit's documented shape, which exercises the real parsing, severity
inference, and pass/fail logic in `check_dependencies`.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from reporium_security.checks import dependencies as deps_mod
from reporium_security.checks.dependencies import check_dependencies, _infer_severity


def _write_requirements(tmp_path: Path, contents: str = "requests==2.31.0\n") -> None:
    (tmp_path / "requirements.txt").write_text(contents)


def _fake_run(stdout: str, returncode: int = 1):
    """Build a stand-in for subprocess.run that returns canned pip-audit output.

    pip-audit exits 1 when vulnerabilities are found, 0 when clean; the scanner
    keys off stdout content rather than the exit code, but we mirror real codes.
    """

    def _runner(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=["pip-audit"], returncode=returncode, stdout=stdout, stderr=""
        )

    return _runner


# pip-audit JSON output shape: a top-level object with a "dependencies" list.
_VULN_HIGH = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.31.0",
            "vulns": [
                {
                    "id": "GHSA-xxxx-high",
                    "description": "A HIGH severity request smuggling issue.",
                    "aliases": ["CVE-2099-0001"],
                    "fix_versions": ["2.32.0"],
                }
            ],
        }
    ]
}

_VULN_MEDIUM = {
    "dependencies": [
        {
            "name": "jinja2",
            "version": "3.1.2",
            "vulns": [
                {
                    "id": "GHSA-yyyy-medium",
                    "description": "An XSS issue with no severity word in the text.",
                    "aliases": [],
                    "fix_versions": ["3.1.3"],
                }
            ],
        }
    ]
}

_CLEAN = {"dependencies": [{"name": "requests", "version": "2.32.0", "vulns": []}]}


class TestDependencyDetection:
    """A planted vulnerable dependency must be reported as a failure."""

    def test_high_cve_detected_and_fails(self, tmp_path: Path, monkeypatch):
        _write_requirements(tmp_path)
        monkeypatch.setattr(
            deps_mod.subprocess, "run", _fake_run(json.dumps(_VULN_HIGH), returncode=1)
        )

        result = check_dependencies(tmp_path)

        assert not result.passed
        assert not result.skipped
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.package == "requests"
        assert finding.version == "2.31.0"
        assert finding.vulnerability_id == "GHSA-xxxx-high"
        assert result.has_high_or_critical
        assert finding.severity == "HIGH"

    def test_medium_cve_detected(self, tmp_path: Path, monkeypatch):
        _write_requirements(tmp_path, "jinja2==3.1.2\n")
        monkeypatch.setattr(
            deps_mod.subprocess, "run", _fake_run(json.dumps(_VULN_MEDIUM), returncode=1)
        )

        result = check_dependencies(tmp_path)

        assert not result.passed
        assert result.has_medium
        assert not result.has_high_or_critical
        assert result.findings[0].severity == "MEDIUM"


class TestDependencyNonDetection:
    """A clean dependency set must pass; missing tooling/inputs must skip."""

    def test_no_vulnerabilities_passes(self, tmp_path: Path, monkeypatch):
        _write_requirements(tmp_path)
        monkeypatch.setattr(
            deps_mod.subprocess, "run", _fake_run(json.dumps(_CLEAN), returncode=0)
        )

        result = check_dependencies(tmp_path)

        assert result.passed
        assert not result.skipped
        assert result.findings == []

    def test_empty_output_passes(self, tmp_path: Path, monkeypatch):
        """pip-audit emitting empty stdout (no findings) is a pass, not a skip."""
        _write_requirements(tmp_path)
        monkeypatch.setattr(
            deps_mod.subprocess, "run", _fake_run("", returncode=0)
        )

        result = check_dependencies(tmp_path)

        assert result.passed
        assert not result.skipped

    def test_missing_requirements_is_skipped(self, tmp_path: Path):
        """No requirements.txt means the check is skipped, not failed."""
        result = check_dependencies(tmp_path)

        assert result.skipped
        assert result.passed
        assert "requirements.txt" in result.skip_reason

    def test_pip_audit_not_installed_is_skipped(self, tmp_path: Path, monkeypatch):
        """If pip-audit is absent the check skips rather than crashing or failing."""
        _write_requirements(tmp_path)

        def _raise_not_found(*_a: Any, **_k: Any):
            raise FileNotFoundError("pip-audit")

        monkeypatch.setattr(deps_mod.subprocess, "run", _raise_not_found)

        result = check_dependencies(tmp_path)

        assert result.skipped
        assert result.passed
        assert "pip-audit" in result.skip_reason

    def test_timeout_is_skipped(self, tmp_path: Path, monkeypatch):
        """A pip-audit timeout skips gracefully (no network is available in CI)."""
        _write_requirements(tmp_path)

        def _raise_timeout(*_a: Any, **_k: Any):
            raise subprocess.TimeoutExpired(cmd="pip-audit", timeout=120)

        monkeypatch.setattr(deps_mod.subprocess, "run", _raise_timeout)

        result = check_dependencies(tmp_path)

        assert result.skipped
        assert result.passed
        assert "timed out" in result.skip_reason

    def test_malformed_json_is_skipped(self, tmp_path: Path, monkeypatch):
        """Unparseable pip-audit output skips rather than crashing."""
        _write_requirements(tmp_path)
        monkeypatch.setattr(
            deps_mod.subprocess, "run", _fake_run("not json at all", returncode=0)
        )

        result = check_dependencies(tmp_path)

        assert result.skipped
        assert "parse" in result.skip_reason.lower()


class TestSeverityInference:
    """Severity inference must honor an explicit field, then description hints."""

    def test_explicit_severity_field_wins(self):
        assert _infer_severity({"severity": "critical"}) == "CRITICAL"

    def test_description_critical_hint(self):
        assert _infer_severity({"description": "A CRITICAL deserialization bug"}) == "CRITICAL"

    def test_description_high_hint(self):
        assert _infer_severity({"description": "HIGH risk path traversal"}) == "HIGH"

    def test_description_low_hint(self):
        assert _infer_severity({"description": "LOW impact info leak"}) == "LOW"

    def test_default_is_medium(self):
        assert _infer_severity({"description": "no severity word present"}) == "MEDIUM"
