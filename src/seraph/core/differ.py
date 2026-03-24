"""Git diff parsing — extract changed files and line ranges."""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FileChange:
    """A single file with its changed line ranges."""

    path: str
    added_lines: list[tuple[int, int]] = field(default_factory=list)  # (start, count)
    deleted_lines: list[tuple[int, int]] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False


@dataclass
class DiffResult:
    """Parsed git diff result."""

    files: list[FileChange] = field(default_factory=list)
    ref_before: str | None = None
    ref_after: str | None = None

    @property
    def file_paths(self) -> list[str]:
        return [f.path for f in self.files]

    @property
    def python_files(self) -> list[str]:
        return [f.path for f in self.files if f.path.endswith(".py")]


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_NEW_FILE_RE = re.compile(r"^new file mode")
_DEL_FILE_RE = re.compile(r"^deleted file mode")


def parse_diff(
    repo_path: Path,
    ref_before: str | None = None,
    ref_after: str | None = None,
    timeout: int = 30,
) -> DiffResult:
    """Parse git diff and return structured file changes.

    If no refs given, diffs HEAD against working tree (staged + unstaged).
    If only ref_before, diffs ref_before..HEAD.
    If both, diffs ref_before..ref_after.
    """
    cmd = ["git", "diff", "--unified=0"]
    if ref_before and ref_after:
        cmd.append(f"{ref_before}..{ref_after}")
    elif ref_before:
        cmd.append(f"{ref_before}..HEAD")
    else:
        cmd.append("HEAD")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # If HEAD doesn't exist yet (fresh repo), fall back to diff of staged files
        if result.returncode != 0 and "HEAD" in result.stderr:
            result = subprocess.run(
                ["git", "diff", "--unified=0", "--cached"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        logger.debug("git diff timed out for %s", repo_path)
        return DiffResult(ref_before=ref_before, ref_after=ref_after)
    except FileNotFoundError:
        logger.warning("git not found on PATH")
        return DiffResult(ref_before=ref_before, ref_after=ref_after)

    return _parse_diff_output(result.stdout, ref_before, ref_after)


def parse_diff_text(diff_text: str) -> DiffResult:
    """Parse raw diff text directly (useful for testing)."""
    return _parse_diff_output(diff_text, None, None)


def _parse_diff_output(
    output: str, ref_before: str | None, ref_after: str | None
) -> DiffResult:
    result = DiffResult(ref_before=ref_before, ref_after=ref_after)
    current_file: FileChange | None = None

    for line in output.splitlines():
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            current_file = FileChange(path=file_match.group(2))
            result.files.append(current_file)
            continue

        if current_file is not None:
            if _NEW_FILE_RE.match(line):
                current_file.is_new = True
                continue
            if _DEL_FILE_RE.match(line):
                current_file.is_deleted = True
                continue

            hunk_match = _HUNK_RE.match(line)
            if hunk_match:
                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2) or "1")
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4) or "1")
                if old_count > 0:
                    current_file.deleted_lines.append((old_start, old_count))
                if new_count > 0:
                    current_file.added_lines.append((new_start, new_count))

    return result
