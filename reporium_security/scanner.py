"""Orchestrates all security checks and produces a SecurityReport."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

from reporium_security.checks.secrets import SecretsCheckResult, check_secrets
from reporium_security.checks.dependencies import DependenciesCheckResult, check_dependencies
from reporium_security.checks.workflows import WorkflowsCheckResult, check_workflows
from reporium_security.checks.files import FilesCheckResult, check_files
from reporium_security.checks.history import HistoryCheckResult, check_history


class SecurityGrade(str, enum.Enum):
    """Security grade for a repository."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    def __str__(self) -> str:
        return self.value


@dataclass
class SecurityReport:
    """Full security report for a repository."""

    repo_name: str
    grade: SecurityGrade
    secrets: SecretsCheckResult
    dependencies: DependenciesCheckResult
    workflows: WorkflowsCheckResult
    files: FilesCheckResult
    history: HistoryCheckResult

    @property
    def summary(self) -> str:
        lines = [
            f"Security Grade: {self.grade}",
            "",
            f"  Secrets:      {self.secrets.summary}",
            f"  Dependencies: {self.dependencies.summary}",
            f"  Workflows:    {self.workflows.summary}",
            f"  Files:        {self.files.summary}",
            f"  History:      {self.history.summary}",
        ]
        return "\n".join(lines)


def _compute_grade(
    secrets: SecretsCheckResult,
    dependencies: DependenciesCheckResult,
    workflows: WorkflowsCheckResult,
    files: FilesCheckResult,
    history: HistoryCheckResult,
) -> SecurityGrade:
    """Compute the overall security grade.

    Grade logic:
    - F: any exposed secret found (in source files, tracked files, or history)
    - D: any check fails structurally (errors in workflows, high/critical CVEs)
    - C: 2 warnings or 1 medium CVE
    - B: 1 warning (low CVE or unpinned action)
    - A: all 5 checks pass, 0 issues
    """
    # F: any exposed secret
    if not secrets.passed or not files.passed or not history.passed:
        return SecurityGrade.F

    # D: structural failures
    if workflows.error_count > 0:
        return SecurityGrade.D
    if dependencies.has_high_or_critical:
        return SecurityGrade.D

    # Count warnings
    warning_count = 0
    warning_count += workflows.warning_count

    if dependencies.has_medium:
        warning_count += 1

    if dependencies.has_low:
        warning_count += 1

    # C: 2+ warnings or 1 medium CVE
    if warning_count >= 2 or dependencies.has_medium:
        return SecurityGrade.C

    # B: 1 warning
    if warning_count == 1:
        return SecurityGrade.B

    # A: clean
    return SecurityGrade.A


def scan_repo(repo_path: str | Path, repo_name: str = "") -> SecurityReport:
    """Run all security checks on a repository and return a SecurityReport."""
    path = Path(repo_path)
    if not repo_name:
        repo_name = path.name

    secrets_result = check_secrets(path)
    deps_result = check_dependencies(path)
    workflows_result = check_workflows(path)
    files_result = check_files(path)
    history_result = check_history(path)

    grade = _compute_grade(
        secrets_result,
        deps_result,
        workflows_result,
        files_result,
        history_result,
    )

    return SecurityReport(
        repo_name=repo_name,
        grade=grade,
        secrets=secrets_result,
        dependencies=deps_result,
        workflows=workflows_result,
        files=files_result,
        history=history_result,
    )
