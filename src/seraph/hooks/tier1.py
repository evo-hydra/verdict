"""Tier 1 hook — PreToolUse on Write/Edit.

Extracts file_path and content from tool input, runs seraph_check,
and blocks if BLOCK verdict is returned.

Claude Code hook protocol:
- Receives tool input as JSON on stdin
- Exit 0 to allow the tool call
- Exit 1 to block, with the reason on stdout
"""

from __future__ import annotations

import json
import sys

from seraph.core.checks import run_checks
from seraph.models.enums import Verdict


def main() -> None:
    """Entry point for Tier 1 hook."""
    try:
        raw = sys.stdin.read()
    except Exception:
        # Can't read stdin — allow (don't block on hook errors)
        sys.exit(0)

    if not raw.strip():
        sys.exit(0)

    try:
        tool_input = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

    # Extract file_path and content from Write/Edit tool input
    file_path = tool_input.get("file_path", "")
    content = tool_input.get("content", "")

    # For Edit tool, check new_string as the content being introduced
    if not content and "new_string" in tool_input:
        content = tool_input["new_string"]

    if not file_path or not content:
        sys.exit(0)

    # Only check Python files (for now)
    if not file_path.endswith(".py"):
        sys.exit(0)

    result = run_checks(
        file_path=file_path,
        content=content,
    )

    if result.verdict == Verdict.BLOCK:
        # Format findings for hook rejection message
        lines = [f"Seraph Tier 1: BLOCKED — {len(result.findings)} finding(s)"]
        for f in result.findings[:5]:  # cap at 5 to keep message readable
            lines.append(f"  {f.check.value} | {f.file}:{f.line} | {f.description}")
            if f.suggestion:
                lines.append(f"    → {f.suggestion}")
        print("\n".join(lines))
        sys.exit(1)

    # ALLOW — pass through silently
    sys.exit(0)


if __name__ == "__main__":
    main()
