"""Seraph MCP server — FastMCP with stdio transport."""

from __future__ import annotations

import os
from pathlib import Path

from seraph.config import SeraphConfig
from seraph.core.engine import SeraphEngine
from seraph.core.store import SeraphStore
from seraph.mcp.formatters import (
    format_assessment,
    format_feedback_response,
    format_history,
    format_mutations,
)
from seraph.models.assessment import Feedback
from seraph.models.enums import FeedbackOutcome


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
    def seraph_assess(
        ref_before: str = "",
        ref_after: str = "",
        skip_baseline: bool = False,
        skip_mutations: bool = False,
        repo_root: str = "",
    ) -> str:
        """Run full assessment pipeline on current diff or specified refs.

        Analyzes code changes through mutation testing, static analysis,
        and Sentinel project intelligence to produce a multi-metric grade.

        Args:
            ref_before: Git ref before changes (default: HEAD)
            ref_after: Git ref after changes (default: working tree)
            skip_baseline: Skip flakiness baseline (faster)
            skip_mutations: Skip mutation testing (much faster)
            repo_root: Explicit repo path (use when CWD doesn't match git root)
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            with _get_store(repo_path, config) as store:
                engine = SeraphEngine(
                    store,
                    config=config,
                    skip_baseline=skip_baseline,
                    skip_mutations=skip_mutations,
                )
                report = engine.assess(
                    repo_path,
                    ref_before=ref_before or None,
                    ref_after=ref_after or None,
                )
                return format_assessment(
                    report.to_dict(), max_chars=config.pipeline.max_output_chars
                )
        except Exception as exc:
            return f"Assessment failed: {exc}"

    @mcp.tool()
    def seraph_mutate(
        ref_before: str = "",
        ref_after: str = "",
        repo_root: str = "",
    ) -> str:
        """Run mutation testing only on changed files.

        A focused subset of the full assessment that only runs mutmut
        on files in the diff.

        Args:
            ref_before: Git ref before changes (default: HEAD)
            ref_after: Git ref after changes (default: working tree)
            repo_root: Explicit repo path (use when CWD doesn't match git root)
        """
        repo_path = Path(repo_root).resolve() if repo_root else _get_repo_path()
        config = SeraphConfig.load(repo_path)
        try:
            with _get_store(repo_path, config) as store:
                engine = SeraphEngine(store, config=config)
                report = engine.mutate_only(
                    repo_path,
                    ref_before=ref_before or None,
                    ref_after=ref_after or None,
                )
                return format_mutations(
                    report.mutations, report.mutation_score,
                    max_chars=config.pipeline.max_output_chars,
                )
        except Exception as exc:
            return f"Mutation testing failed: {exc}"

    @mcp.tool()
    def seraph_history(
        limit: int = 10,
        offset: int = 0,
    ) -> str:
        """Query past assessments with pagination.

        Args:
            limit: Maximum number of results (default 10)
            offset: Number of results to skip (default 0)
        """
        repo_path = _get_repo_path()
        config = SeraphConfig.load(repo_path)
        with _get_store(repo_path, config) as store:
            assessments = store.get_assessments(limit=limit, offset=offset)
            return format_history(
                assessments, max_chars=config.pipeline.max_output_chars
            )

    @mcp.tool()
    def seraph_feedback(
        assessment_id: str,
        outcome: str,
        context: str = "",
    ) -> str:
        """Submit feedback on an assessment.

        Helps Seraph learn which assessments are useful.

        Args:
            assessment_id: The assessment ID to give feedback on
            outcome: One of: accepted, rejected, modified
            context: Optional explanation
        """
        repo_path = _get_repo_path()
        config = SeraphConfig.load(repo_path)
        with _get_store(repo_path, config) as store:
            # Validate outcome
            try:
                fb_outcome = FeedbackOutcome(outcome)
            except ValueError:
                return f"Invalid outcome '{outcome}'. Must be: accepted, rejected, or modified"

            # Verify assessment exists
            assessment = store.get_assessment(assessment_id)
            if not assessment:
                return f"Assessment '{assessment_id}' not found"

            fb = Feedback(
                assessment_id=assessment_id,
                outcome=fb_outcome,
                context=context,
            )
            store.save_feedback(fb)
            return format_feedback_response(assessment_id, outcome)

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
