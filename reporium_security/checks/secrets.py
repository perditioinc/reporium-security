"""Scan source files for hardcoded secrets and credentials."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SECRET_PATTERNS: dict[str, str] = {
    "GitHub PAT classic": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub PAT fine-grained": r"github_pat_[a-zA-Z0-9_]{82}",
    "Google API key": r"AIza[0-9A-Za-z\-_]{35}",
    "OpenAI key": r"sk-[a-zA-Z0-9]{48}",
    "Hardcoded password": r'(?i)password\s*=\s*["\'][^"\']{4,}["\']',
    "Hardcoded secret": r'(?i)secret\s*=\s*["\'][^"\']{4,}["\']',
    "Hardcoded API key": r'(?i)api_key\s*=\s*["\'][^"\']{4,}["\']',
    "AWS access key": r"AKIA[0-9A-Z]{16}",
}

COMPILED_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()
}

SCANNABLE_EXTENSIONS: set[str] = {".py", ".js", ".ts", ".yaml", ".yml", ".json"}

SKIP_PATHS: set[str] = {
    ".env.example",
    "node_modules",
    "__pycache__",
}

SKIP_DIRS: set[str] = {"node_modules", "__pycache__", ".git"}


@dataclass
class SecretFinding:
    """A single secret finding in a file."""

    file: str
    line_number: int
    pattern_name: str
    matched_text: str


@dataclass
class SecretsCheckResult:
    """Result of the secrets check."""

    passed: bool = True
    findings: list[SecretFinding] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.passed:
            return "No secrets detected in source files."
        return f"Found {len(self.findings)} potential secret(s) in source files."


def _should_skip(path: Path) -> bool:
    """Return True if the path should be skipped."""
    parts = path.parts
    for skip_dir in SKIP_DIRS:
        if skip_dir in parts:
            return True
    if path.name in SKIP_PATHS:
        return True
    # Skip test fixture directories
    for part in parts:
        if part in ("fixtures", "test_fixtures", "testdata"):
            return True
    return False


def check_secrets(repo_path: Path) -> SecretsCheckResult:
    """Scan source files in repo_path for hardcoded secrets."""
    result = SecretsCheckResult()

    for ext in SCANNABLE_EXTENSIONS:
        for filepath in repo_path.rglob(f"*{ext}"):
            if _should_skip(filepath):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                for pattern_name, compiled in COMPILED_PATTERNS.items():
                    if compiled.search(line):
                        # Don't flag the pattern definitions themselves
                        if "SECRET_PATTERNS" in line or "COMPILED_PATTERNS" in line:
                            continue
                        # Don't flag regex pattern strings (r"..." definitions)
                        if line.strip().startswith('"') and line.strip().endswith('",'):
                            continue
                        # Don't flag test assertions or pattern definitions
                        if "assert" in line.lower() or "r'" in line or 'r"' in line:
                            continue
                        result.findings.append(
                            SecretFinding(
                                file=str(filepath.relative_to(repo_path)),
                                line_number=line_number,
                                pattern_name=pattern_name,
                                matched_text=line.strip()[:80],
                            )
                        )
                        result.passed = False

    return result
