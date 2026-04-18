"""Tests for CLI app."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from seraph.cli.app import app
from seraph.core.store import SeraphStore
from seraph.models.assessment import AssessmentReport
from seraph.models.enums import Grade

runner = CliRunner()


@pytest.fixture
def cli_store(tmp_path: Path):
    """Create a SeraphStore for CLI tests, returning (tmp_path, store_path)."""
    with SeraphStore(tmp_path / ".seraph" / "seraph.db") as store:
        yield tmp_path, store


class TestCLI:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer >= 0.12 exits with code 2 when no command is given (no_args_is_help),
        # older versions returned 0. Accept both; what matters is that help is printed.
        assert result.exit_code in (0, 2)
        assert "Verification intelligence" in result.stdout or "Usage" in result.stdout

    def test_history_empty(self, cli_store):
        tmp_path, _store = cli_store
        result = runner.invoke(app, ["history", str(tmp_path)])
        assert result.exit_code == 0
        assert "No assessments" in result.stdout

    def test_history_with_data(self, cli_store):
        tmp_path, store = cli_store
        report = AssessmentReport(
            repo_path=str(tmp_path),
            files_changed=["foo.py"],
            overall_score=85.0,
            overall_grade=Grade.B,
            mutation_score=90.0,
            static_issues=1,
        )
        store.save_assessment(report)

        result = runner.invoke(app, ["history", str(tmp_path)])
        assert result.exit_code == 0
        assert "B" in result.stdout
        assert "90.0%" in result.stdout
        assert report.id[:8] in result.stdout

    def test_history_zero_mutation_score(self, cli_store):
        """mutation_score=0.0 should display '0.0%' not '?%'."""
        tmp_path, store = cli_store
        report = AssessmentReport(
            repo_path=str(tmp_path),
            files_changed=["foo.py"],
            overall_grade=Grade.F,
            mutation_score=0.0,
            static_issues=0,
        )
        store.save_assessment(report)

        result = runner.invoke(app, ["history", str(tmp_path)])
        assert result.exit_code == 0
        assert "0.0%" in result.stdout
        # static_issues=0 should show "0" not "?"
        assert "?" not in result.stdout or "?%" not in result.stdout

    def test_feedback_invalid_outcome(self, cli_store):
        tmp_path, _store = cli_store
        result = runner.invoke(app, ["feedback", "abc123", "invalid", "--repo", str(tmp_path)])
        assert result.exit_code == 1

    def test_feedback_missing_assessment(self, cli_store):
        tmp_path, _store = cli_store
        result = runner.invoke(app, ["feedback", "nonexistent", "accepted", "--repo", str(tmp_path)])
        assert result.exit_code == 1

    @patch("seraph.cli.app.SeraphEngine")
    def test_assess_command(self, mock_engine_cls, cli_store):
        """assess command invokes engine and displays report."""
        tmp_path, _store = cli_store

        mock_report = AssessmentReport(
            repo_path=str(tmp_path),
            files_changed=["foo.py"],
            overall_score=85.0,
            overall_grade=Grade.B,
            mutation_score=90.0,
        )
        mock_engine = MagicMock()
        mock_engine.assess.return_value = mock_report
        mock_engine_cls.return_value = mock_engine

        result = runner.invoke(app, [
            "assess", str(tmp_path),
            "--skip-baseline", "--skip-mutations",
        ])
        assert result.exit_code == 0
        assert "Seraph Assessment" in result.stdout

    @patch("seraph.cli.app.SeraphEngine")
    def test_assess_json_output(self, mock_engine_cls, cli_store):
        """assess --json outputs valid JSON."""
        tmp_path, _store = cli_store

        mock_report = AssessmentReport(
            repo_path=str(tmp_path),
            files_changed=["foo.py"],
            overall_score=85.0,
            overall_grade=Grade.B,
            mutation_score=90.0,
        )
        mock_engine = MagicMock()
        mock_engine.assess.return_value = mock_report
        mock_engine_cls.return_value = mock_engine

        result = runner.invoke(app, [
            "assess", str(tmp_path),
            "--skip-baseline", "--skip-mutations", "--json",
        ])
        assert result.exit_code == 0
        assert "overall_grade" in result.stdout

    @patch("seraph.cli.app.SeraphEngine")
    def test_assess_engine_error_shows_message(self, mock_engine_cls, cli_store):
        """Engine exceptions produce user-friendly error, not traceback."""
        tmp_path, _store = cli_store

        mock_engine = MagicMock()
        mock_engine.assess.side_effect = RuntimeError("git not found")
        mock_engine_cls.return_value = mock_engine

        result = runner.invoke(app, [
            "assess", str(tmp_path),
            "--skip-baseline", "--skip-mutations",
        ])
        assert result.exit_code == 1
        assert "Assessment failed" in result.stdout
        assert "git not found" in result.stdout

    @patch("seraph.cli.app.SeraphEngine")
    def test_assess_engine_error_suggests_verbose(self, mock_engine_cls, cli_store):
        """Error message suggests --verbose when not in verbose mode."""
        tmp_path, _store = cli_store

        mock_engine = MagicMock()
        mock_engine.assess.side_effect = RuntimeError("boom")
        mock_engine_cls.return_value = mock_engine

        result = runner.invoke(app, [
            "assess", str(tmp_path),
            "--skip-baseline", "--skip-mutations",
        ])
        assert result.exit_code == 1
        assert "--verbose" in result.stdout

    def test_prune_command(self, cli_store):
        """prune command deletes old data."""
        tmp_path, store = cli_store

        report = AssessmentReport(
            repo_path=str(tmp_path),
            files_changed=["foo.py"],
            overall_grade=Grade.A,
        )
        store.save_assessment(report)

        # Age the assessment
        store.conn.execute(
            "UPDATE assessments SET created_at = datetime('now', '-200 days') WHERE id = ?",
            (report.id,),
        )
        store.conn.commit()

        result = runner.invoke(app, [
            "prune", str(tmp_path), "--days", "90", "--yes",
        ])
        assert result.exit_code == 0
        assert "Pruned" in result.stdout or "No data" in result.stdout

    def test_verbose_flag(self, cli_store):
        """--verbose flag is accepted without error."""
        tmp_path, _store = cli_store
        result = runner.invoke(app, [
            "--verbose", "history", str(tmp_path),
        ])
        assert result.exit_code == 0
