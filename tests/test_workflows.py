"""Tests for GitHub Actions workflow security checks."""

from pathlib import Path

from reporium_security.checks.workflows import check_workflows


class TestWorkflowSHADetection:
    """Test that SHA-pinned vs tag-based actions are correctly identified."""

    def _write_workflow(self, tmp_path: Path, content: str) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "test.yml").write_text(content)

    def test_sha_pinned_action_passes(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
        result = check_workflows(tmp_path)
        assert result.passed

    def test_tag_based_action_warns(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
        result = check_workflows(tmp_path)
        assert not result.passed
        assert any("tag instead of SHA" in f.issue for f in result.findings)

    def test_local_action_not_flagged(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
""")
        result = check_workflows(tmp_path)
        assert result.passed


class TestWorkflowTriggers:
    """Test dangerous trigger detection."""

    def _write_workflow(self, tmp_path: Path, content: str) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "test.yml").write_text(content)

    def test_pull_request_target_flagged(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
        result = check_workflows(tmp_path)
        assert not result.passed
        assert any("pull_request_target" in f.issue for f in result.findings)

    def test_push_trigger_ok(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
        result = check_workflows(tmp_path)
        assert result.passed


class TestWorkflowPermissions:
    """Test overly broad permissions detection."""

    def _write_workflow(self, tmp_path: Path, content: str) -> None:
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "test.yml").write_text(content)

    def test_write_all_flagged(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
        result = check_workflows(tmp_path)
        assert not result.passed
        assert any("write-all" in f.issue for f in result.findings)

    def test_scoped_permissions_ok(self, tmp_path: Path):
        self._write_workflow(tmp_path, """
name: Test
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
        result = check_workflows(tmp_path)
        assert result.passed

    def test_no_workflows_dir_passes(self, tmp_path: Path):
        """A repo with no .github/workflows should pass."""
        result = check_workflows(tmp_path)
        assert result.passed
