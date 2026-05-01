"""Tests for the git-history secret scanner.

Focuses on documentation-induced false positives: audit markdown notes that
quote the secret regexes themselves used to register as real findings before
the file-aware skip logic was added.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from reporium_security.checks.history import check_history


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


class TestHistoryDocumentationSkip:
    """Regex-quoting markdown notes must not trigger history secret findings."""

    def test_markdown_audit_note_with_regex_quote_is_skipped(self, tmp_path: Path):
        """An audit note that documents the api_key regex must not be flagged."""
        _init_repo(tmp_path)
        audit = tmp_path / ".audit" / "2026-04-26" / "scanner-note.md"
        audit.parent.mkdir(parents=True)
        audit.write_text(
            "# Scanner notes\n"
            "\n"
            "The `(?i)api_key\\s*=\\s*[\"\\'][^\"\\']{4,}[\"\\']` pattern matches\n"
            "documentation lines containing `api_key = \"<value>\"` placeholders.\n"
        )
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "audit: document scanner regex")

        result = check_history(tmp_path)
        assert result.passed, [f.matched_text for f in result.findings]

    def test_markdown_at_repo_root_is_skipped(self, tmp_path: Path):
        """Plain markdown at the repo root is also skipped."""
        _init_repo(tmp_path)
        readme = tmp_path / "NOTES.md"
        readme.write_text(
            "## Examples\n\n"
            'Avoid lines like `password = "hunter22-real"` in your code.\n'
        )
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "docs: add notes")

        result = check_history(tmp_path)
        assert result.passed, [f.matched_text for f in result.findings]

    def test_real_secret_in_python_still_detected(self, tmp_path: Path):
        """Documentation skip must not mask actual secrets in code."""
        _init_repo(tmp_path)
        code = tmp_path / "config.py"
        code.write_text('DB_PASSWORD = "hunter22-real-secret"\n')
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "leak a credential")

        result = check_history(tmp_path)
        assert not result.passed
        assert any("DB_PASSWORD" in f.matched_text for f in result.findings)

    def test_docs_directory_is_skipped(self, tmp_path: Path):
        """Files under docs/ are skipped regardless of extension."""
        _init_repo(tmp_path)
        doc = tmp_path / "docs" / "snippet.yml"
        doc.parent.mkdir()
        doc.write_text('api_key = "documented-example-value-1234"\n')
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "docs: add example snippet")

        result = check_history(tmp_path)
        assert result.passed, [f.matched_text for f in result.findings]

    def test_tests_directory_is_skipped(self, tmp_path: Path):
        """Stub kwarg values in test files must not trigger history findings.

        Regression for the false-positive that turned reporium-api Security
        Scan from A to F after PR #447 added two `_api_key="test"` lines in
        a unit test. Pytest fixtures and parameter stubs are not credentials.
        """
        _init_repo(tmp_path)
        test_file = tmp_path / "tests" / "test_backfill.py"
        test_file.parent.mkdir()
        test_file.write_text(
            'async def test_backfill_invalidates_cache():\n'
            '    result = await backfill(\n'
            '        _api_key="test",\n'
            '        _admin_key=None,\n'
            '    )\n'
        )
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "test: add backfill cache invalidation test")

        result = check_history(tmp_path)
        assert result.passed, [f.matched_text for f in result.findings]

    def test_real_secret_outside_tests_dir_still_detected(self, tmp_path: Path):
        """Tests/ skip must not mask credentials in production code."""
        _init_repo(tmp_path)
        code = tmp_path / "app" / "settings.py"
        code.parent.mkdir()
        code.write_text('api_key = "sk-real-production-credential-here"\n')
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-m", "settings: add api key")

        result = check_history(tmp_path)
        assert not result.passed
        assert any("api_key" in f.matched_text for f in result.findings)
