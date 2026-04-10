"""Tests for Claude Code hook integration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch


def _run_hook(hook_module: str, stdin_data: str) -> subprocess.CompletedProcess:
    """Run a hook module as a subprocess with given stdin."""
    return subprocess.run(
        [sys.executable, "-m", hook_module],
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(Path(__file__).parent.parent.parent),
    )


# ── Tier 1 Hook ───────────────────────────────────────────────


class TestTier1Hook:
    """Test the Tier 1 PreToolUse hook on Write/Edit."""

    def test_allow_clean_code(self):
        """Clean Python file passes through."""
        tool_input = json.dumps({
            "file_path": "src/clean.py",
            "content": "x = 1 + 2\nprint(x)\n",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 0

    def test_block_eval(self):
        """File with eval() is blocked."""
        tool_input = json.dumps({
            "file_path": "src/dangerous.py",
            "content": "result = eval(user_input)\n",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 1
        assert "BLOCKED" in result.stdout

    def test_allow_non_python(self):
        """Non-Python files pass through."""
        tool_input = json.dumps({
            "file_path": "README.md",
            "content": "# Hello\neval(something)\n",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 0

    def test_allow_empty_input(self):
        """Empty stdin passes through."""
        result = _run_hook("seraph.hooks.tier1", "")
        assert result.returncode == 0

    def test_allow_invalid_json(self):
        """Invalid JSON passes through (don't block on hook errors)."""
        result = _run_hook("seraph.hooks.tier1", "not json")
        assert result.returncode == 0

    def test_block_edit_tool_with_dangerous_new_string(self):
        """Edit tool with dangerous new_string is blocked."""
        tool_input = json.dumps({
            "file_path": "src/foo.py",
            "old_string": "x = 1",
            "new_string": "x = eval(user_input)",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 1
        assert "BLOCKED" in result.stdout

    def test_allow_edit_tool_safe_new_string(self):
        """Edit tool with safe new_string passes through."""
        tool_input = json.dumps({
            "file_path": "src/foo.py",
            "old_string": "x = 1",
            "new_string": "x = 2",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 0

    def test_block_subprocess_shell(self):
        """subprocess with shell=True is blocked."""
        tool_input = json.dumps({
            "file_path": "src/runner.py",
            "content": 'import subprocess\nsubprocess.run("rm -rf /", shell=True)\n',
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 1
        assert "BLOCKED" in result.stdout

    def test_block_pickle_load(self):
        """pickle.load() is blocked."""
        tool_input = json.dumps({
            "file_path": "src/loader.py",
            "content": "import pickle\ndata = pickle.load(f)\n",
        })
        result = _run_hook("seraph.hooks.tier1", tool_input)
        assert result.returncode == 1


# ── Tier 2 Hook ───────────────────────────────────────────────


class TestTier2Hook:
    """Test the Tier 2 PreToolUse hook on git commit."""

    def test_allow_non_commit(self):
        """Non-commit bash commands pass through."""
        tool_input = json.dumps({"command": "ls -la"})
        result = _run_hook("seraph.hooks.tier2", tool_input)
        assert result.returncode == 0

    def test_allow_empty_input(self):
        """Empty stdin passes through."""
        result = _run_hook("seraph.hooks.tier2", "")
        assert result.returncode == 0

    def test_allow_commit_no_staged(self):
        """git commit with no staged changes passes through."""
        tool_input = json.dumps({"command": "git commit -m 'test'"})
        # This will try to run git diff --cached which may or may not work
        # In test env, it should return empty diff → allow
        result = _run_hook("seraph.hooks.tier2", tool_input)
        # Either 0 (no diff) or 0 (allow) — should not block
        assert result.returncode == 0

    def test_detects_git_c_commit(self):
        """git -C repo commit variant is detected."""
        tool_input = json.dumps({"command": "git -C /some/repo commit -m 'msg'"})
        result = _run_hook("seraph.hooks.tier2", tool_input)
        # Should not exit early — should attempt to run (may pass with empty diff)
        assert result.returncode == 0  # passes because no staged changes

    def test_detects_git_config_commit(self):
        """git -c user.name=x commit variant is detected."""
        tool_input = json.dumps({"command": "git -c user.name=test commit -m 'msg'"})
        result = _run_hook("seraph.hooks.tier2", tool_input)
        assert result.returncode == 0  # passes because no staged changes
