"""Tests for secret pattern matching."""

import re
import tempfile
from pathlib import Path

from reporium_security.checks.secrets import (
    COMPILED_PATTERNS,
    SECRET_PATTERNS,
    check_secrets,
)


class TestSecretPatterns:
    """Test that secret patterns match known patterns and reject safe strings."""

    def test_github_pat_classic_matches(self):
        pattern = COMPILED_PATTERNS["GitHub PAT classic"]
        assert pattern.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12")

    def test_github_pat_classic_rejects_short(self):
        pattern = COMPILED_PATTERNS["GitHub PAT classic"]
        assert not pattern.search("ghp_short")

    def test_github_pat_fine_grained_matches(self):
        pattern = COMPILED_PATTERNS["GitHub PAT fine-grained"]
        token = "github_pat_" + "a" * 82
        assert pattern.search(token)

    def test_github_pat_fine_grained_rejects_short(self):
        pattern = COMPILED_PATTERNS["GitHub PAT fine-grained"]
        assert not pattern.search("github_pat_tooshort")

    def test_google_api_key_matches(self):
        pattern = COMPILED_PATTERNS["Google API key"]
        assert pattern.search("AIzaSyB-FAKE_KEY_FOR_TESTING_1234567890a")

    def test_google_api_key_rejects_wrong_prefix(self):
        pattern = COMPILED_PATTERNS["Google API key"]
        assert not pattern.search("AIzb_wrong_prefix")

    def test_openai_key_matches(self):
        pattern = COMPILED_PATTERNS["OpenAI key"]
        key = "sk-" + "a" * 48
        assert pattern.search(key)

    def test_openai_key_rejects_short(self):
        pattern = COMPILED_PATTERNS["OpenAI key"]
        assert not pattern.search("sk-tooshort")

    def test_hardcoded_password_matches(self):
        pattern = COMPILED_PATTERNS["Hardcoded password"]
        assert pattern.search('password = "mysecretpass"')
        assert pattern.search("PASSWORD = 'longpass123'")

    def test_hardcoded_password_rejects_short(self):
        pattern = COMPILED_PATTERNS["Hardcoded password"]
        assert not pattern.search('password = "ab"')

    def test_hardcoded_password_rejects_empty(self):
        pattern = COMPILED_PATTERNS["Hardcoded password"]
        assert not pattern.search('password = ""')

    def test_hardcoded_secret_matches(self):
        pattern = COMPILED_PATTERNS["Hardcoded secret"]
        assert pattern.search('secret = "my_secret_value"')

    def test_hardcoded_api_key_matches(self):
        pattern = COMPILED_PATTERNS["Hardcoded API key"]
        assert pattern.search('api_key = "abcdef1234"')

    def test_aws_access_key_matches(self):
        pattern = COMPILED_PATTERNS["AWS access key"]
        assert pattern.search("AKIAIOSFODNN7EXAMPLE")

    def test_aws_access_key_rejects_lowercase(self):
        pattern = COMPILED_PATTERNS["AWS access key"]
        assert not pattern.search("AKIAiosfodnn7example")

    def test_safe_variable_names_not_flagged(self):
        """Variable names containing 'password' without assignment should not match."""
        pattern = COMPILED_PATTERNS["Hardcoded password"]
        assert not pattern.search("password_field = get_password()")
        assert not pattern.search("# Enter your password below")


class TestCheckSecrets:
    """Integration tests for the check_secrets function."""

    def test_clean_repo(self, tmp_path: Path):
        """A repo with no secrets should pass."""
        (tmp_path / "main.py").write_text("print('hello world')\n")
        result = check_secrets(tmp_path)
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_secret_in_python(self, tmp_path: Path):
        """A Python file with a hardcoded password should be flagged."""
        (tmp_path / "config.py").write_text('DB_PASSWORD = "super_secret_123"\n')
        result = check_secrets(tmp_path)
        assert not result.passed
        assert len(result.findings) >= 1

    def test_skips_node_modules(self, tmp_path: Path):
        """Files in node_modules should be skipped."""
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('const secret = "my_secret_value"\n')
        result = check_secrets(tmp_path)
        assert result.passed

    def test_skips_env_example(self, tmp_path: Path):
        """The .env.example file should be skipped."""
        (tmp_path / ".env.example").write_text('PASSWORD = "changeme"\n')
        result = check_secrets(tmp_path)
        assert result.passed

    def test_scans_yaml_files(self, tmp_path: Path):
        """YAML files should be scanned for secrets."""
        (tmp_path / "config.yaml").write_text('api_key = "abcdef1234567890"\n')
        result = check_secrets(tmp_path)
        assert not result.passed

    def test_only_scans_supported_extensions(self, tmp_path: Path):
        """Files with unsupported extensions should not be scanned."""
        (tmp_path / "data.csv").write_text('password = "should_not_flag"\n')
        result = check_secrets(tmp_path)
        assert result.passed
