"""Tier 2 hook — PreToolUse on Bash containing 'git commit'.

Runs git diff --cached, passes the staged diff to seraph_gate,
and blocks if REJECT verdict is returned.

Claude Code hook protocol:
- Receives tool input as JSON on stdin
- Exit 0 to allow the tool call
- Exit 1 to block, with the reason on stdout
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

from seraph.core.gate import run_gate
from seraph.models.enums import GateVerdict

# Match 'git' followed eventually by 'commit' subcommand,
# handling flags/options between them (e.g., git -C repo commit,
# git -c user.name=x commit, git --no-pager commit)
_GIT_COMMIT_RE = re.compile(r"\bgit\b.*\bcommit\b")


def main() -> None:
    """Entry point for Tier 2 hook."""
    try:
        raw = sys.stdin.read()
    except Exception:
        sys.exit(0)

    if not raw.strip():
        sys.exit(0)

    try:
        tool_input = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)

    # Check if this is a Bash command containing a git commit invocation
    command = tool_input.get("command", "")
    if not _GIT_COMMIT_RE.search(command):
        sys.exit(0)

    # Get staged diff
    try:
        result = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        diff = result.stdout
    except Exception:
        # Can't get diff — allow (don't block on hook errors)
        sys.exit(0)

    if not diff.strip():
        sys.exit(0)

    # Run Tier 2 gate
    gate_result = run_gate(
        repo_path=".",
        diff=diff,
    )

    if gate_result.verdict == GateVerdict.REJECT:
        lines = [
            f"Seraph Tier 2: REJECTED — mutation score {gate_result.mutation_score:.0f}%",
            f"  {gate_result.mutants_survived} surviving mutant(s) out of {gate_result.mutants_tested}",
        ]
        for f in gate_result.findings[:5]:
            lines.append(f"  {f.source.value} | {f.description}")
            if f.suggestion:
                lines.append(f"    → {f.suggestion}")
        print("\n".join(lines))
        sys.exit(1)

    # ACCEPT or ACCEPT_WITH_WARNINGS — pass through
    if gate_result.verdict == GateVerdict.ACCEPT_WITH_WARNINGS:
        # Print warnings but don't block
        lines = [f"Seraph Tier 2: ACCEPT_WITH_WARNINGS ({len(gate_result.findings)} finding(s))"]
        for f in gate_result.findings[:3]:
            lines.append(f"  {f.description}")
        # Print to stderr so it's visible but doesn't block
        print("\n".join(lines), file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
