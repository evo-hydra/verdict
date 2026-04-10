"""Seraph MCP server — FastMCP with stdio transport.

New 5-tool interface (v2):
  seraph_check     — Tier 1 fast pre-write checks
  seraph_gate      — Tier 2 pre-commit verification gate
  seraph_explain   — Detailed explanation of a finding
  seraph_calibrate — Report false positive/negative
  seraph_status    — Gate pass/fail rates, calibration stats
"""

from __future__ import annotations

import os
from pathlib import Path

from seraph.config import SeraphConfig
from seraph.core.checks import run_checks
from seraph.core.gate import run_gate
from seraph.core.store import SeraphStore
from seraph.mcp.formatters import (
    format_calibrate_response,
    format_check_result,
    format_explain,
    format_gate_result,
    format_status,
)
from seraph.models.assessment import Calibration


def _get_repo_path() -> Path:
    """Determine repo path from env or cwd."""
    return Path(os.environ.get("SERAPH_REPO_PATH", os.getcwd())).resolve()


def _get_store(repo_path: Path, config: SeraphConfig | None = None) -> SeraphStore:
    """Create a SeraphStore for the repo (use as context manager)."""
    if config:
        db_path = repo_path / config.pipeline.db_dir / config.pipeline.db_name
    else:
        db_path = repo_path / ".seraph" / "seraph.db"
    return SeraphStore(db_path)


def create_server():
    """Create the Seraph MCP server."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        "seraph",
        instructions="Verification intelligence for AI-generated code",
    )

    @mcp.tool()
    def seraph_check(
        file_path: str,
        content: str,
        diff: str = "",
        task_description: str = "",
        repo_root: str = "",
    ) -> str:
        """Tier 1 fast pre-write checks on a file.

        Runs import validation, security surface scan, escalation detection,
        and spec drift analysis. Returns structured findings or ALLOW verdict.
        Designed for <500ms latency.

        Args:
            file_path: Relative path to the file being checked.
            content: Full file content (after proposed write/edit).
            diff: Optional unified diff of the change.
            task_description: Optional task description for spec drift detection.
            repo_root: Explicit repo path (use when CWD doesn't match git root).
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            result = run_checks(
                file_path=file_path,
                content=content,
                diff=diff,
                task_description=task_description,
            )
            return format_check_result(
                result, max_chars=config.pipeline.max_output_chars,
            )
        except Exception as exc:
            return f"Check failed: {exc}"

    @mcp.tool()
    def seraph_gate(
        diff: str,
        task_description: str = "",
        test_cmd: str = "pytest",
        max_mutants: int = 10,
        repo_root: str = "",
    ) -> str:
        """Tier 2 pre-commit verification gate.

        Runs targeted mutation testing on changed lines and spec compliance
        checks. Returns structured verdict: ACCEPT, ACCEPT_WITH_WARNINGS,
        REJECT, or PARTIAL. Designed for <30s latency.

        Surviving mutants are reported as questions: "Your code still passes
        tests if X is changed to Y. Is that intentional?"

        Args:
            diff: Unified diff of staged changes (from git diff --cached).
            task_description: Task/plan description for spec compliance checks.
            test_cmd: Test command to run (default: pytest).
            max_mutants: Maximum mutants to generate (default: 10).
            repo_root: Explicit repo path (use when CWD doesn't match git root).
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            result = run_gate(
                repo_path=repo_path,
                diff=diff,
                task_description=task_description,
                test_cmd=test_cmd,
                max_mutants=max_mutants,
            )
            return format_gate_result(
                result, max_chars=config.pipeline.max_output_chars,
            )
        except Exception as exc:
            return f"Gate failed: {exc}"

    @mcp.tool()
    def seraph_explain(
        check_category: str,
        description: str,
        file_path: str = "",
        line: int = 0,
        confidence: float = 0.0,
    ) -> str:
        """Explain a finding in detail.

        Given a finding from seraph_check or seraph_gate, returns a detailed
        explanation: what the check detected, why it matters, what the fix
        should look like, and what the confidence score means.

        Args:
            check_category: The check type (e.g., "security_surface", "mutation").
            description: The finding description from the check/gate result.
            file_path: File where the finding was detected.
            line: Line number of the finding.
            confidence: Confidence score of the finding.
        """
        return format_explain(
            check_category=check_category,
            description=description,
            file_path=file_path,
            line=line,
            confidence=confidence,
        )

    @mcp.tool()
    def seraph_calibrate(
        check_category: str,
        finding_description: str,
        is_false_positive: bool = True,
        context: str = "",
        repo_root: str = "",
    ) -> str:
        """Report a false positive or false negative to tune thresholds.

        Over time, checks with high FP rates get their confidence thresholds
        raised automatically.

        Args:
            check_category: The check type (e.g., "security_surface", "mutation").
            finding_description: The finding that was FP/FN.
            is_false_positive: True if false positive, False if false negative.
            context: Optional explanation of why this is FP/FN.
            repo_root: Explicit repo path (use when CWD doesn't match git root).
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            cal = Calibration(
                check_category=check_category,
                finding_description=finding_description,
                is_false_positive=is_false_positive,
                context=context,
            )
            with _get_store(repo_path, config) as store:
                store.save_calibration(cal)
            return format_calibrate_response(
                check_category, is_false_positive,
            )
        except Exception as exc:
            return f"Calibration failed: {exc}"

    @mcp.tool()
    def seraph_status(
        repo_root: str = "",
    ) -> str:
        """Gate pass/fail rates, calibration stats, and system health.

        Returns aggregate statistics on check/gate verdicts and
        FP/FN calibration reports.

        Args:
            repo_root: Explicit repo path (use when CWD doesn't match git root).
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            with _get_store(repo_path, config) as store:
                cal_stats = store.get_calibration_stats()
                table_stats = store.stats()
            return format_status(
                calibration_stats=cal_stats,
                table_stats=table_stats,
            )
        except Exception as exc:
            return f"Status failed: {exc}"

    return mcp


def main():
    """Entry point for seraph-mcp."""
    from seraph.logging_setup import setup_logging

    repo_path = _get_repo_path()
    config = SeraphConfig.load(repo_path)
    setup_logging(config.logging)

    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
