"""Tests for sensitive file detection."""

import subprocess
from pathlib import Path

from reporium_security.checks.files import check_files


class TestFileExposureDetection:
    """Test that sensitive files are detected correctly."""

    def _init_git(self, tmp_path: Path) -> None:
        """Initialize a git repo and add files."""
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(tmp_path), capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(tmp_path), capture_output=True,
        )

    def test_clean_repo(self, tmp_path: Path):
        """A repo with no sensitive files should pass."""
        self._init_git(tmp_path)
        (tmp_path / "main.py").write_text("print('hello')")
        subprocess.run(
            ["git", "add", "main.py"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_env_file(self, tmp_path: Path):
        """A tracked .env file should be flagged."""
        self._init_git(tmp_path)
        (tmp_path / ".env").write_text("SECRET=value")
        subprocess.run(
            ["git", "add", ".env"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert not result.passed
        assert any(".env" in f.file for f in result.findings)

    def test_detects_pem_file(self, tmp_path: Path):
        """A tracked .pem file should be flagged."""
        self._init_git(tmp_path)
        (tmp_path / "cert.pem").write_text("-----BEGIN CERTIFICATE-----")
        subprocess.run(
            ["git", "add", "cert.pem"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert not result.passed
        assert any(".pem" in f.file for f in result.findings)

    def test_detects_key_file(self, tmp_path: Path):
        """A tracked .key file should be flagged."""
        self._init_git(tmp_path)
        (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----")
        subprocess.run(
            ["git", "add", "server.key"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert not result.passed
        assert any(".key" in f.file for f in result.findings)

    def test_detects_p12_file(self, tmp_path: Path):
        """A tracked .p12 file should be flagged."""
        self._init_git(tmp_path)
        (tmp_path / "cert.p12").write_text("binary content")
        subprocess.run(
            ["git", "add", "cert.p12"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert not result.passed

    def test_detects_pfx_file(self, tmp_path: Path):
        """A tracked .pfx file should be flagged."""
        self._init_git(tmp_path)
        (tmp_path / "cert.pfx").write_text("binary content")
        subprocess.run(
            ["git", "add", "cert.pfx"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert not result.passed

    def test_normal_files_pass(self, tmp_path: Path):
        """Normal code files should not be flagged."""
        self._init_git(tmp_path)
        (tmp_path / "app.py").write_text("print('app')")
        (tmp_path / "README.md").write_text("# README")
        subprocess.run(
            ["git", "add", "app.py", "README.md"],
            cwd=str(tmp_path), capture_output=True,
        )
        result = check_files(tmp_path)
        assert result.passed
