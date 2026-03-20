"""Tests for SECURITY_REPORT.md generation."""

from reporium_security.checks.secrets import SecretsCheckResult, SecretFinding
from reporium_security.checks.dependencies import DependenciesCheckResult
from reporium_security.checks.workflows import WorkflowsCheckResult, WorkflowFinding
from reporium_security.checks.files import FilesCheckResult
from reporium_security.checks.history import HistoryCheckResult
from reporium_security.scanner import SecurityGrade, SecurityReport
from reporium_security.reporter import generate_report


def _make_clean_report() -> SecurityReport:
    """Create a clean (grade A) security report."""
    return SecurityReport(
        repo_name="test-repo",
        grade=SecurityGrade.A,
        secrets=SecretsCheckResult(),
        dependencies=DependenciesCheckResult(),
        workflows=WorkflowsCheckResult(),
        files=FilesCheckResult(),
        history=HistoryCheckResult(),
    )


class TestReportGeneration:
    """Test SECURITY_REPORT.md generation."""

    def test_clean_report_contains_grade(self):
        report = _make_clean_report()
        md = generate_report(report)
        assert "Grade: A" in md

    def test_clean_report_contains_repo_name(self):
        report = _make_clean_report()
        md = generate_report(report)
        assert "test-repo" in md

    def test_clean_report_contains_all_sections(self):
        report = _make_clean_report()
        md = generate_report(report)
        assert "## Secrets Check" in md
        assert "## Dependency CVE Check" in md
        assert "## Workflow Security Check" in md
        assert "## Sensitive File Check" in md
        assert "## Git History Check" in md

    def test_clean_report_shows_passing(self):
        report = _make_clean_report()
        md = generate_report(report)
        assert "No secrets detected" in md
        assert "No known CVEs" in md
        assert "All workflows follow security best practices" in md
        assert "No sensitive files detected" in md

    def test_report_with_secrets_shows_findings(self):
        secrets = SecretsCheckResult(
            passed=False,
            findings=[
                SecretFinding(
                    file="config.py",
                    line_number=10,
                    pattern_name="Hardcoded password",
                    matched_text='password = "secret"',
                )
            ],
        )
        report = SecurityReport(
            repo_name="bad-repo",
            grade=SecurityGrade.F,
            secrets=secrets,
            dependencies=DependenciesCheckResult(),
            workflows=WorkflowsCheckResult(),
            files=FilesCheckResult(),
            history=HistoryCheckResult(),
        )
        md = generate_report(report)
        assert "Grade: F" in md
        assert "config.py" in md
        assert "Hardcoded password" in md

    def test_report_with_workflow_issues(self):
        workflows = WorkflowsCheckResult(
            passed=False,
            findings=[
                WorkflowFinding(
                    file=".github/workflows/ci.yml",
                    issue="Action 'actions/checkout@v4' uses tag instead of SHA",
                    severity="warning",
                )
            ],
        )
        report = SecurityReport(
            repo_name="warn-repo",
            grade=SecurityGrade.B,
            secrets=SecretsCheckResult(),
            dependencies=DependenciesCheckResult(),
            workflows=workflows,
            files=FilesCheckResult(),
            history=HistoryCheckResult(),
        )
        md = generate_report(report)
        assert "Grade: B" in md
        assert "tag instead of SHA" in md

    def test_report_with_skipped_dependencies(self):
        deps = DependenciesCheckResult(skipped=True, skip_reason="No requirements.txt found.")
        report = SecurityReport(
            repo_name="no-deps",
            grade=SecurityGrade.A,
            secrets=SecretsCheckResult(),
            dependencies=deps,
            workflows=WorkflowsCheckResult(),
            files=FilesCheckResult(),
            history=HistoryCheckResult(),
        )
        md = generate_report(report)
        assert "Skipped" in md
        assert "No requirements.txt" in md

    def test_report_ends_with_generator_note(self):
        report = _make_clean_report()
        md = generate_report(report)
        assert "reporium-security" in md
