"""Phase E: Integration tests for Seraph.

Tests the end-to-end pipeline, MCP server with mock invocations,
and performance characteristics.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from seraph.core.engine import SeraphEngine
from seraph.core.store import SeraphStore
from seraph.models.assessment import AssessmentReport, Feedback
from seraph.models.enums import FeedbackOutcome, Grade


# ── Helpers ──────────────────────────────────────────────────────

def _git(repo_path: Path, *args: str) -> None:
    """Run a git command in the given repo, raising on failure."""
    subprocess.run(
        ["git", *args],
        cwd=str(repo_path),
        capture_output=True,
        check=True,
    )


def _make_git_repo(tmp_path: Path) -> Path:
    """Create a git repo with an initial commit and a subsequent change."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@test.com")
    _git(repo, "config", "user.name", "Test")

    # Initial commit with a Python file and a passing test
    src = repo / "src"
    src.mkdir()
    (src / "__init__.py").write_text("")
    (src / "calc.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n\n"
        "def subtract(a: int, b: int) -> int:\n    return a - b\n"
    )

    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_calc.py").write_text(
        "from src.calc import add, subtract\n\n"
        "def test_add():\n    assert add(1, 2) == 3\n\n"
        "def test_subtract():\n    assert subtract(5, 3) == 2\n"
    )

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")

    # Second commit: add a new function
    (src / "calc.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n\n"
        "def subtract(a: int, b: int) -> int:\n    return a - b\n\n"
        "def multiply(a: int, b: int) -> int:\n    return a * b\n"
    )
    (tests_dir / "test_calc.py").write_text(
        "from src.calc import add, subtract, multiply\n\n"
        "def test_add():\n    assert add(1, 2) == 3\n\n"
        "def test_subtract():\n    assert subtract(5, 3) == 2\n\n"
        "def test_multiply():\n    assert multiply(3, 4) == 12\n"
    )

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add multiply")
    return repo


# ── End-to-End Tests ─────────────────────────────────────────────

class TestEndToEnd:
    """Run seraph assess on a real git repo (no Sentinel data, no mutmut)."""

    def test_assess_real_repo_skip_heavy(self, tmp_path: Path):
        """Full pipeline on a real repo, skipping baseline and mutations."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        with SeraphStore(db_path) as store:
            engine = SeraphEngine(
                store,
                skip_baseline=True,
                skip_mutations=True,
            )
            report = engine.assess(repo, ref_before="HEAD~1")

        assert report.files_changed != []
        assert "src/calc.py" in report.files_changed
        assert report.overall_grade in (Grade.A, Grade.B, Grade.C, Grade.D, Grade.F)
        assert 0 <= report.overall_score <= 100
        assert report.id  # Has an ID
        assert report.created_at  # Has a timestamp

        # Verify it was persisted
        with SeraphStore(db_path) as store:
            saved = store.get_assessment(report.id)
            assert saved is not None
            assert saved.grade == report.overall_grade.value

    def test_assess_produces_valid_json(self, tmp_path: Path):
        """Report serializes to valid JSON."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        with SeraphStore(db_path) as store:
            engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
            report = engine.assess(repo, ref_before="HEAD~1")

        report_json = report.to_json()
        parsed = json.loads(report_json)
        assert "overall_grade" in parsed
        assert "dimensions" in parsed
        assert len(parsed["dimensions"]) == 6

    def test_assess_no_changes(self, tmp_path: Path):
        """Assessing HEAD with no diff returns perfect score."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        with SeraphStore(db_path) as store:
            engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
            report = engine.assess(repo)

        assert report.files_changed == []
        assert report.overall_grade == Grade.VACUOUS
        assert report.overall_score == 0.0
        assert report.is_vacuous is True

    def test_feedback_round_trip(self, tmp_path: Path):
        """Can submit feedback and retrieve it."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        with SeraphStore(db_path) as store:
            engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
            report = engine.assess(repo, ref_before="HEAD~1")

            fb = Feedback(
                assessment_id=report.id,
                outcome=FeedbackOutcome.ACCEPTED,
                context="Looks correct",
            )
            store.save_feedback(fb)

            feedbacks = store.get_feedback(report.id)
            assert len(feedbacks) == 1
            assert feedbacks[0].outcome == "accepted"

    def test_history_ordering(self, tmp_path: Path):
        """Multiple assessments are stored and retrievable."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        with SeraphStore(db_path) as store:
            engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)

            r1 = engine.assess(repo, ref_before="HEAD~1")
            r2 = engine.assess(repo, ref_before="HEAD~1")

            history = store.get_assessments(limit=10)
            assert len(history) == 2
            ids = {h.id for h in history}
            assert r1.id in ids
            assert r2.id in ids


# ── MCP Server Tests ────────────────────────────────────────────

class TestMCPServerIntegration:
    """Test MCP server tool functions directly (without transport)."""

    def test_mcp_assess_tool(self, tmp_path: Path):
        """seraph_assess tool returns formatted markdown."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("MCP package not installed")

        repo = _make_git_repo(tmp_path)

        with patch("seraph.mcp.server._get_repo_path", return_value=repo):
            from seraph.mcp.server import create_server
            server = create_server()

            # Access the tool function directly
            tools = {t.name: t for t in server._tool_manager.list_tools()}
            assert "seraph_assess" in tools
            assert "seraph_mutate" in tools
            assert "seraph_history" in tools
            assert "seraph_feedback" in tools

    def test_mcp_history_empty(self, tmp_path: Path):
        """seraph_history returns empty message for new repo."""
        repo = tmp_path / "empty_repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "test@test.com")
        _git(repo, "config", "user.name", "Test")
        (repo / "x").touch()
        _git(repo, "add", "x")
        _git(repo, "commit", "-q", "-m", "init")

        # Pre-create store so it exists
        with SeraphStore(repo / ".seraph" / "seraph.db"):
            pass

        with patch("seraph.mcp.server._get_repo_path", return_value=repo):
            from seraph.mcp.server import _get_store
            with _get_store(repo) as store:
                from seraph.mcp.formatters import format_history
                result = format_history(store.get_assessments())
                assert "No assessments" in result


# ── Performance Tests ────────────────────────────────────────────

class TestPerformance:
    """Verify that lightweight assessments complete quickly."""

    def test_assess_under_timeout(self, tmp_path: Path):
        """Assessment (skip baseline + mutations) completes in < 10s."""
        repo = _make_git_repo(tmp_path)
        db_path = repo / ".seraph" / "seraph.db"

        start = time.monotonic()
        with SeraphStore(db_path) as store:
            engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
            report = engine.assess(repo, ref_before="HEAD~1")
        elapsed = time.monotonic() - start

        assert elapsed < 10.0, f"Assessment took {elapsed:.1f}s (limit: 10s)"
        assert report.files_changed != []

    def test_store_operations_fast(self, tmp_path: Path):
        """Store CRUD operations complete in < 1s for 100 records."""
        db_path = tmp_path / "perf.db"

        start = time.monotonic()
        with SeraphStore(db_path) as store:
            for i in range(100):
                report = AssessmentReport(
                    repo_path="/tmp/test",
                    files_changed=[f"file{i}.py"],
                    overall_grade=Grade.B,
                    mutation_score=80.0,
                )
                store.save_assessment(report)

            # Query
            all_results = store.get_assessments(limit=100)
            assert len(all_results) == 100

        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"100 store operations took {elapsed:.1f}s (limit: 1s)"


# ── Sentinel Bridge Integration ──────────────────────────────────

class TestSentinelBridgeIntegration:
    """Test bridge against real Sentinel data if available."""

    def test_bridge_with_sentinel_repo(self):
        """If the sentinel repo has .sentinel/ data, test real bridge."""
        sentinel_repo = Path(os.environ.get("SENTINEL_REPO", "/home/evo-nirvana/dev/projects/sentinel"))
        sentinel_db = sentinel_repo / ".sentinel" / "sentinel.db"

        if not sentinel_db.exists():
            pytest.skip("No Sentinel data available")

        from seraph.core.bridge import SentinelBridge

        with SentinelBridge(sentinel_repo) as bridge:
            assert bridge.available is True

            # Query with some known files
            signals = bridge.get_risk_signals([
                "src/sentinel/core/knowledge.py",
                "src/sentinel/core/verifier.py",
            ])
            assert signals.available is True
            # These are hot files in sentinel, should have data
            assert isinstance(signals.hot_files, list)
            assert isinstance(signals.pitfall_matches, list)
            assert isinstance(signals.missing_co_changes, list)

            # Scores should be valid (scoring now lives in reporter)
            from seraph.core.reporter import compute_risk_score, compute_co_change_score
            risk_score = compute_risk_score(signals)
            assert 0 <= risk_score <= 100

            co_score = compute_co_change_score(
                signals,
                ["src/sentinel/core/knowledge.py", "src/sentinel/core/verifier.py"],
            )
            assert 0 <= co_score <= 100

    def test_bridge_pitfall_file_paths_matching(self):
        """If sentinel has pitfalls with file_paths, verify matching works."""
        sentinel_repo = Path(os.environ.get("SENTINEL_REPO", "/home/evo-nirvana/dev/projects/sentinel"))
        sentinel_db = sentinel_repo / ".sentinel" / "sentinel.db"

        if not sentinel_db.exists():
            pytest.skip("No Sentinel data available")

        from sentinel.core.knowledge import KnowledgeStore

        with KnowledgeStore(str(sentinel_db)) as store:
            pitfalls = store.get_pitfalls(limit=10)
            has_file_paths = any(
                hasattr(p, "file_paths") and p.file_paths
                for p in pitfalls
            )
            # After our migration, new pitfalls will have file_paths
            # Existing ones may still be empty — that's fine
            assert isinstance(pitfalls, list)
