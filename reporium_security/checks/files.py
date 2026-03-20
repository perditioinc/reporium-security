"""Check for sensitive files tracked in git."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SENSITIVE_PATTERNS: list[str] = [
    ".env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
]

SENSITIVE_EXACT: set[str] = {".env"}
SENSITIVE_EXTENSIONS: set[str] = {".pem", ".key", ".p12", ".pfx"}


@dataclass
class FileFinding:
    """A sensitive file found in the repository."""

    file: str
    reason: str


@dataclass
class FilesCheckResult:
    """Result of the file exposure check."""

    passed: bool = True
    findings: list[FileFinding] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.passed:
            return "No sensitive files detected in the repository."
        return f"Found {len(self.findings)} sensitive file(s) tracked in git."


def check_files(repo_path: Path) -> FilesCheckResult:
    """Check for sensitive files tracked in git."""
    result = FilesCheckResult()

    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            cwd=str(repo_path),
            timeout=30,
        )
        tracked_files = proc.stdout.strip().splitlines()
    except (subprocess.SubprocessError, FileNotFoundError):
        # Fall back to filesystem scan if git is not available
        tracked_files = [
            str(p.relative_to(repo_path))
            for p in repo_path.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]

    for filepath in tracked_files:
        name = Path(filepath).name
        suffix = Path(filepath).suffix

        if name in SENSITIVE_EXACT:
            result.findings.append(
                FileFinding(
                    file=filepath,
                    reason=f"Sensitive file '{name}' is tracked in git",
                )
            )
            result.passed = False

        elif suffix in SENSITIVE_EXTENSIONS:
            result.findings.append(
                FileFinding(
                    file=filepath,
                    reason=f"Sensitive file type '{suffix}' is tracked in git",
                )
            )
            result.passed = False

    return result
