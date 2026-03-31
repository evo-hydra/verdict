"""Tests for differ module."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from seraph.core.differ import DiffResult, FileChange, parse_diff, parse_diff_text


class TestParseDiffText:
    def test_parse_new_file(self, sample_diff_text: str):
        result = parse_diff_text(sample_diff_text)
        foo = next(f for f in result.files if f.path == "src/foo.py")
        assert foo.is_new is True
        assert len(foo.added_lines) == 1
        assert foo.added_lines[0] == (1, 10)

    def test_parse_modified_file(self, sample_diff_text: str):
        result = parse_diff_text(sample_diff_text)
        bar = next(f for f in result.files if f.path == "src/bar.py")
        assert bar.is_new is False
        assert len(bar.added_lines) == 1
        assert len(bar.deleted_lines) == 2
        assert bar.deleted_lines[1] == (15, 2)

    def test_file_paths(self, sample_diff_text: str):
        result = parse_diff_text(sample_diff_text)
        assert set(result.file_paths) == {"src/foo.py", "src/bar.py", "README.md"}

    def test_python_files(self, sample_diff_text: str):
        result = parse_diff_text(sample_diff_text)
        assert set(result.python_files) == {"src/foo.py", "src/bar.py"}

    def test_empty_diff(self):
        result = parse_diff_text("")
        assert result.files == []
        assert result.file_paths == []

    def test_single_line_change(self):
        diff = """\
diff --git a/x.py b/x.py
index aaa..bbb 100644
--- a/x.py
+++ b/x.py
@@ -5 +5 @@ context
-old
+new
"""
        result = parse_diff_text(diff)
        assert len(result.files) == 1
        f = result.files[0]
        assert f.added_lines == [(5, 1)]
        assert f.deleted_lines == [(5, 1)]


class TestParseDiffGit:
    def test_parse_diff_with_real_repo(self, tmp_repo):
        from tests.conftest import _git

        # Make a change
        (tmp_repo / "test.py").write_text("def hello():\n    pass\n")
        _git(tmp_repo, "add", "test.py")
        _git(tmp_repo, "commit", "-q", "-m", "add test")

        (tmp_repo / "test.py").write_text("def hello():\n    return 'world'\n")
        _git(tmp_repo, "add", "test.py")
        _git(tmp_repo, "commit", "-q", "-m", "modify test")

        result = parse_diff(tmp_repo, ref_before="HEAD~1", ref_after="HEAD")
        assert len(result.files) == 1
        assert result.files[0].path == "test.py"

    def test_parse_diff_no_changes(self, tmp_repo):
        result = parse_diff(tmp_repo)
        assert result.files == []

    def test_parse_diff_cached_fallback(self, tmp_path):
        """Fresh repo with no commits falls back to --cached diff."""
        from tests.conftest import _git

        _git(tmp_path, "init")
        _git(tmp_path, "config", "user.email", "test@test.com")
        _git(tmp_path, "config", "user.name", "Test")
        (tmp_path / "hello.py").write_text("x = 1\n")
        _git(tmp_path, "add", "hello.py")

        result = parse_diff(tmp_path)
        paths = result.file_paths
        assert "hello.py" in paths

    def test_parse_diff_staged_only_changes(self, tmp_repo):
        """Staged changes (git add without commit) are detected.

        This was the root cause of Seraph returning VACUOUS when the
        protocol calls git add before seraph_assess — git diff HEAD
        only shows unstaged changes, missing staged ones entirely.
        """
        from tests.conftest import _git

        # Make a change and stage it (but don't commit)
        (tmp_repo / "test.py").write_text("def hello():\n    return 'world'\n")
        _git(tmp_repo, "add", "test.py")

        # parse_diff with no refs should find the staged change
        result = parse_diff(tmp_repo)
        assert len(result.files) >= 1
        paths = result.file_paths
        assert "test.py" in paths

    def test_parse_diff_staged_with_ref_before(self, tmp_repo):
        """Staged changes are found even when ref_before is specified."""
        from tests.conftest import _git

        base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(tmp_repo), capture_output=True, text=True,
        ).stdout.strip()

        (tmp_repo / "new_file.py").write_text("x = 1\n")
        _git(tmp_repo, "add", "new_file.py")

        result = parse_diff(tmp_repo, ref_before=base_sha)
        paths = result.file_paths
        assert "new_file.py" in paths

    @patch("seraph.core.differ.subprocess.run")
    def test_parse_diff_timeout_returns_empty(self, mock_run, tmp_path):
        """TimeoutExpired returns an empty DiffResult."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git diff", timeout=30)
        result = parse_diff(tmp_path, ref_before="abc123")
        assert result.files == []
        assert result.ref_before == "abc123"
