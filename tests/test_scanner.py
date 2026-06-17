"""End-to-end tests for scan_repo and the grade-computation orchestrator.

These wire all five scanners together against fixture repositories built in
tmp_path. Each test plants exactly one class of problem (a secret, a sensitive
file, an unpinned action) and asserts both the per-check result and the overall
SecurityGrade, plus a clean baseline that must grade A.

Everything runs offline: the dependency scanner is allowed to skip (no
pip-audit / no network), and git history is exercised against a real local repo
created with git init.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from reporium_security.scanner import (
    SecurityGrade,
    _compute_grade,
    scan_repo,
)
from reporium_security.checks.secrets import SecretsCheckResult, SecretFinding
from reporium_security.checks.dependencies import DependenciesCheckResult
from reporium_security.checks.workflows import WorkflowsCheckResult, WorkflowFinding
from reporium_security.checks.files import FilesCheckResult, FileFinding
from reporium_security.checks.history import HistoryCheckResult


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "commit.gpgsign", "false")


def _commit_all(tmp_path: Path, message: str = "snapshot") -> None:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)


def _write_workflow(tmp_path: Path, content: str) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "ci.yml").write_text(content)


_SHA_PINNED = (
    "name: CI\n"
    "on: push\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
)

_TAG_PINNED = (
    "name: CI\n"
    "on: push\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
)


def _passing(**overrides):
    """Build a kwargs dict of all-passing check results for _compute_grade."""
    base = dict(
        secrets=SecretsCheckResult(passed=True),
        dependencies=DependenciesCheckResult(passed=True, skipped=True),
        workflows=WorkflowsCheckResult(passed=True),
        files=FilesCheckResult(passed=True),
        history=HistoryCheckResult(passed=True),
    )
    base.update(overrides)
    return base


class TestComputeGradeUnit:
    """Unit tests for the grade matrix using synthetic check results."""

    def test_all_clean_is_A(self):
        assert _compute_grade(**_passing()) == SecurityGrade.A

    def test_exposed_secret_is_F(self):
        secrets = SecretsCheckResult(
            passed=False,
            findings=[SecretFinding("config.py", 1, "Hardcoded password", 'password="x"')],
        )
        assert _compute_grade(**_passing(secrets=secrets)) == SecurityGrade.F

    def test_sensitive_file_is_F(self):
        files = FilesCheckResult(
            passed=False, findings=[FileFinding(".env", "tracked")]
        )
        assert _compute_grade(**_passing(files=files)) == SecurityGrade.F

    def test_history_secret_is_F(self):
        history = HistoryCheckResult(passed=False)
        assert _compute_grade(**_passing(history=history)) == SecurityGrade.F

    def test_workflow_error_is_D(self):
        workflows = WorkflowsCheckResult(
            passed=False,
            findings=[WorkflowFinding("ci.yml", "pull_request_target", "error")],
        )
        assert _compute_grade(**_passing(workflows=workflows)) == SecurityGrade.D

    def test_single_unpinned_warning_is_B(self):
        workflows = WorkflowsCheckResult(
            passed=False,
            findings=[WorkflowFinding("ci.yml", "tag instead of SHA", "warning")],
        )
        assert _compute_grade(**_passing(workflows=workflows)) == SecurityGrade.B

    def test_two_warnings_is_C(self):
        workflows = WorkflowsCheckResult(
            passed=False,
            findings=[
                WorkflowFinding("ci.yml", "tag instead of SHA", "warning"),
                WorkflowFinding("ci.yml", "no version pin", "warning"),
            ],
        )
        assert _compute_grade(**_passing(workflows=workflows)) == SecurityGrade.C


class TestScanRepoIntegration:
    """scan_repo against real fixture repositories."""

    def test_clean_repo_grades_A(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("print('hello world')\n")
        _write_workflow(tmp_path, _SHA_PINNED)
        _commit_all(tmp_path)

        report = scan_repo(tmp_path, repo_name="clean")

        assert report.grade == SecurityGrade.A
        assert report.secrets.passed
        assert report.files.passed
        assert report.workflows.passed
        assert report.history.passed

    def test_planted_secret_grades_F(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "settings.py").write_text('API_KEY = "a93kf02mfjs81lqz"\n')
        _write_workflow(tmp_path, _SHA_PINNED)
        _commit_all(tmp_path)

        report = scan_repo(tmp_path, repo_name="leaky")

        assert not report.secrets.passed
        assert report.grade == SecurityGrade.F

    def test_planted_env_file_grades_F(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("print('ok')\n")
        (tmp_path / ".env").write_text("DATABASE_URL=postgres://localhost/app\n")
        _write_workflow(tmp_path, _SHA_PINNED)
        _commit_all(tmp_path)

        report = scan_repo(tmp_path, repo_name="env-leak")

        assert not report.files.passed
        assert any(".env" in f.file for f in report.files.findings)
        assert report.grade == SecurityGrade.F

    def test_planted_pem_file_grades_F(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("print('ok')\n")
        (tmp_path / "server.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
        _write_workflow(tmp_path, _SHA_PINNED)
        _commit_all(tmp_path)

        report = scan_repo(tmp_path, repo_name="pem-leak")

        assert not report.files.passed
        assert any(".pem" in f.file for f in report.files.findings)
        assert report.grade == SecurityGrade.F

    def test_unpinned_action_grades_B(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("print('ok')\n")
        _write_workflow(tmp_path, _TAG_PINNED)
        _commit_all(tmp_path)

        report = scan_repo(tmp_path, repo_name="unpinned")

        assert not report.workflows.passed
        assert report.workflows.warning_count == 1
        assert report.workflows.error_count == 0
        # One warning, no secrets/files/history problems -> B.
        assert report.grade == SecurityGrade.B

    def test_repo_name_defaults_to_directory_name(self, tmp_path: Path):
        _init_repo(tmp_path)
        (tmp_path / "main.py").write_text("print('ok')\n")
        _commit_all(tmp_path)

        report = scan_repo(tmp_path)

        assert report.repo_name == tmp_path.name
