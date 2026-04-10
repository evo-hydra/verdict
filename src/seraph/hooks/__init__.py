"""Claude Code hook integration for Seraph verification gates.

Tier 1 hook (PreToolUse on Write/Edit): fast checks (<500ms)
Tier 2 hook (PreToolUse on Bash containing git commit): pre-commit gate (<30s)

Hooks call seraph functions directly (not via MCP) for speed.
Configure in .claude/settings.json or via the Claude Code hooks system.
"""
