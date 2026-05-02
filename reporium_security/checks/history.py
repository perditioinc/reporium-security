"""Scan recent git history for secrets that may have been committed then removed."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from reporium_security.checks.secrets import COMPILED_PATTERNS


@dataclass
class HistoryFinding:
    """A secret found in git history."""

    commit: str
    pattern_name: str
    matched_text: str


@dataclass
class HistoryCheckResult:
    """Result of the git history check."""

    passed: bool = True
    findings: list[HistoryFinding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    @property
    def summary(self) -> str:
        if self.skipped:
            return f"History check skipped: {self.skip_reason}"
        if self.passed:
            return "No secrets detected in recent git history."
        return f"Found {len(self.findings)} potential secret(s) in git history."


def check_history(repo_path: Path) -> HistoryCheckResult:
    """Scan the last 20 commits for secrets."""
    result = HistoryCheckResult()

    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--max-count=20"],
            capture_output=True,
            cwd=str(repo_path),
            timeout=60,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        result.skipped = True
        result.skip_reason = "Could not run git log."
        return result

    if proc.returncode != 0:
        result.skipped = True
        result.skip_reason = "git log returned an error."
        return result

    # Decode with errors='replace' to handle binary content in diffs
    output = proc.stdout.decode("utf-8", errors="replace")
    if not output.strip():
        # No commits yet
        return result

    current_commit = ""
    current_file = ""
    for line in output.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:12]
            current_file = ""
            continue

        if line.startswith("diff --git"):
            current_file = ""
            continue

        # Capture the target file path from the +++ diff header so we can
        # skip documentation/audit files (markdown notes describing patterns
        # or workflows trigger false positives that are not real secrets).
        if line.startswith("+++"):
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                target = parts[1].strip()
                if target == "/dev/null":
                    current_file = ""
                elif target.startswith("b/"):
                    current_file = target[2:]
                else:
                    current_file = target
            continue

        # Only scan diff additions
        if not line.startswith("+"):
            continue

        # Skip lines from documentation files — markdown audit notes routinely
        # quote the regexes themselves, which is a deterministic false positive.
        # Also skip test files: stub values like `_api_key="test"` match the
        # regex but are pytest fixtures that never reach production. This was
        # caught after reporium-api PR #447 added two such test stubs and
        # turned the daily Security Scan from A to F overnight.
        if current_file:
            lower_file = current_file.lower()
            if lower_file.endswith((".md", ".rst", ".txt", ".markdown")):
                continue
            if "audit/" in lower_file or "docs/" in lower_file:
                continue
            if "tests/" in lower_file or "/test_" in lower_file or lower_file.startswith("test_"):
                continue

        for pattern_name, compiled in COMPILED_PATTERNS.items():
            if compiled.search(line):
                # Skip pattern definitions (this repo's own code)
                if "SECRET_PATTERNS" in line or "COMPILED_PATTERNS" in line:
                    continue
                if 'r"' in line or "r'" in line:
                    continue
                if "assert" in line.lower():
                    continue
                # Skip obvious test/placeholder values and test fixtures
                lower_line = line.lower()
                if any(p in lower_line for p in (
                    "test-", "test_", "fake-", "fake_", "dummy",
                    "example", "placeholder", "changeme", "xxx",
                    "conftest", "fixture", "write_text(", "matched_text",
                    "tmp_path", "mock", "expected",
                )):
                    continue

                result.findings.append(
                    HistoryFinding(
                        commit=current_commit,
                        pattern_name=pattern_name,
                        matched_text=line[1:].strip()[:80],
                    )
                )
                result.passed = False

    return result
