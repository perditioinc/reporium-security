"""Check GitHub Actions workflows for security issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SHA_PATTERN = re.compile(r"@[0-9a-f]{40}$")


@dataclass
class WorkflowFinding:
    """A single workflow security finding."""

    file: str
    issue: str
    severity: str  # warning, error


@dataclass
class WorkflowsCheckResult:
    """Result of the workflows check."""

    passed: bool = True
    findings: list[WorkflowFinding] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.passed:
            return "All workflows follow security best practices."
        errors = [f for f in self.findings if f.severity == "error"]
        warnings = [f for f in self.findings if f.severity == "warning"]
        parts = []
        if errors:
            parts.append(f"{len(errors)} error(s)")
        if warnings:
            parts.append(f"{len(warnings)} warning(s)")
        return f"Found {', '.join(parts)} in GitHub Actions workflows."

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "error")


def _check_uses_sha(workflow_content: str, filename: str) -> list[WorkflowFinding]:
    """Check that all `uses:` directives reference a SHA, not a tag."""
    findings = []
    for line_num, line in enumerate(workflow_content.splitlines(), start=1):
        stripped = line.strip()
        if "uses:" in stripped:
            action_ref = stripped.split("uses:")[-1].strip()
            # Strip trailing inline YAML comment (e.g. "@<sha> # v4.2.2") so the
            # SHA anchor still matches when versions are documented inline.
            if "#" in action_ref:
                action_ref = action_ref.split("#", 1)[0].strip()
            if not action_ref:
                continue
            # Strip surrounding quotes if present
            if (action_ref.startswith('"') and action_ref.endswith('"')) or (
                action_ref.startswith("'") and action_ref.endswith("'")
            ):
                action_ref = action_ref[1:-1]
            # Skip local actions (./path)
            if action_ref.startswith("./") or action_ref.startswith(".\\"):
                continue
            # Check for SHA pinning
            if "@" in action_ref and not SHA_PATTERN.search(action_ref):
                findings.append(
                    WorkflowFinding(
                        file=filename,
                        issue=f"Line {line_num}: Action '{action_ref}' uses tag instead of SHA",
                        severity="warning",
                    )
                )
            elif "@" not in action_ref and "/" in action_ref:
                findings.append(
                    WorkflowFinding(
                        file=filename,
                        issue=f"Line {line_num}: Action '{action_ref}' has no version pin",
                        severity="warning",
                    )
                )
    return findings


def _check_triggers(workflow_data: dict, filename: str) -> list[WorkflowFinding]:
    """Check for dangerous triggers like pull_request_target."""
    findings = []
    triggers = workflow_data.get(True, {})  # YAML parses 'on' as True
    if triggers is None:
        triggers = {}
    if isinstance(triggers, str):
        triggers = {triggers: None}
    if isinstance(triggers, list):
        triggers = {t: None for t in triggers}

    if "pull_request_target" in triggers:
        findings.append(
            WorkflowFinding(
                file=filename,
                issue="Uses pull_request_target trigger (dangerous — can expose secrets to PRs)",
                severity="error",
            )
        )
    return findings


def _check_permissions(workflow_data: dict, filename: str) -> list[WorkflowFinding]:
    """Check for overly broad permissions."""
    findings = []
    permissions = workflow_data.get("permissions")

    if permissions == "write-all":
        findings.append(
            WorkflowFinding(
                file=filename,
                issue="Uses 'permissions: write-all' (overly broad)",
                severity="error",
            )
        )

    return findings


def check_workflows(repo_path: Path) -> WorkflowsCheckResult:
    """Check all GitHub Actions workflows for security issues."""
    result = WorkflowsCheckResult()
    workflows_dir = repo_path / ".github" / "workflows"

    if not workflows_dir.exists():
        return result

    for workflow_file in workflows_dir.glob("*.yml"):
        filename = str(workflow_file.relative_to(repo_path))
        content = workflow_file.read_text(encoding="utf-8", errors="ignore")

        # Check uses: SHA pinning
        result.findings.extend(_check_uses_sha(content, filename))

        # Parse YAML for structural checks
        try:
            workflow_data = yaml.safe_load(content)
        except yaml.YAMLError:
            result.findings.append(
                WorkflowFinding(
                    file=filename,
                    issue="Failed to parse workflow YAML",
                    severity="error",
                )
            )
            continue

        if not isinstance(workflow_data, dict):
            continue

        result.findings.extend(_check_triggers(workflow_data, filename))
        result.findings.extend(_check_permissions(workflow_data, filename))

    # Also check .yaml extension
    for workflow_file in workflows_dir.glob("*.yaml"):
        filename = str(workflow_file.relative_to(repo_path))
        content = workflow_file.read_text(encoding="utf-8", errors="ignore")
        result.findings.extend(_check_uses_sha(content, filename))

        try:
            workflow_data = yaml.safe_load(content)
        except yaml.YAMLError:
            continue

        if isinstance(workflow_data, dict):
            result.findings.extend(_check_triggers(workflow_data, filename))
            result.findings.extend(_check_permissions(workflow_data, filename))

    if result.findings:
        result.passed = False

    return result
