"""Tests for SeraphStore."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from seraph.core.store import SeraphStore, SCHEMA_VERSION, _MIGRATIONS, _migrate_v1_to_v2
from seraph.models.assessment import (
    AssessmentReport,
    BaselineResult,
    Feedback,
    MutationResult,
)
from seraph.models.enums import FeedbackOutcome, Grade, MutantStatus


class TestSeraphStore:
    def test_open_creates_tables(self, store: SeraphStore):
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row["name"] for row in cur.fetchall()}
        assert "assessments" in tables
        assert "baselines" in tables
        assert "mutation_cache" in tables
        assert "feedback" in tables
        assert "seraph_meta" in tables

    def test_schema_version(self, store: SeraphStore):
        cur = store.conn.execute(
            "SELECT value FROM seraph_meta WHERE key = 'schema_version'"
        )
        assert cur.fetchone()["value"] == str(SCHEMA_VERSION)

    def test_wal_mode(self, store: SeraphStore):
        cur = store.conn.execute("PRAGMA journal_mode")
        assert cur.fetchone()[0] == "wal"

    def test_save_and_get_assessment(self, store: SeraphStore):
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py", "bar.py"],
            overall_score=85.0,
            overall_grade=Grade.B,
            mutation_score=90.0,
            static_issues=2,
        )
        store.save_assessment(report)

        fetched = store.get_assessment(report.id)
        assert fetched is not None
        assert fetched.repo_path == "/tmp/test"
        assert fetched.grade == "B"
        assert fetched.mutation_score == 90.0
        assert fetched.files_changed == ["foo.py", "bar.py"]

    def test_get_assessments_pagination(self, store: SeraphStore):
        for i in range(5):
            report = AssessmentReport(
                repo_path="/tmp/test",
                files_changed=[f"file{i}.py"],
                overall_grade=Grade.A,
            )
            store.save_assessment(report)

        all_results = store.get_assessments(limit=10)
        assert len(all_results) == 5

        page = store.get_assessments(limit=2, offset=0)
        assert len(page) == 2

        page2 = store.get_assessments(limit=2, offset=2)
        assert len(page2) == 2

    def test_get_assessments_repo_path_filter(self, store: SeraphStore):
        for repo in ["/tmp/a", "/tmp/a", "/tmp/b"]:
            report = AssessmentReport(
                repo_path=repo,
                files_changed=["foo.py"],
                overall_grade=Grade.A,
            )
            store.save_assessment(report)

        a_results = store.get_assessments(repo_path="/tmp/a")
        assert len(a_results) == 2

        b_results = store.get_assessments(repo_path="/tmp/b")
        assert len(b_results) == 1

        none_results = store.get_assessments(repo_path="/tmp/nope")
        assert len(none_results) == 0

    def test_save_assessment_with_mutations(self, store: SeraphStore):
        mutations = [
            MutationResult(file_path="foo.py", mutant_id="1", operator="negate", status=MutantStatus.KILLED),
            MutationResult(file_path="foo.py", mutant_id="2", operator="remove", status=MutantStatus.SURVIVED),
        ]
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.B,
            mutations=mutations,
        )
        store.save_assessment(report)

        saved_mutations = store.get_mutations(report.id)
        assert len(saved_mutations) == 2
        statuses = {m.status for m in saved_mutations}
        assert statuses == {"killed", "survived"}

    def test_save_assessment_with_baseline(self, store: SeraphStore):
        baseline = BaselineResult(
            repo_path="/tmp/test",
            flaky_tests=["test_a", "test_b"],
            pass_rate=0.95,
        )
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.C,
            baseline=baseline,
        )
        store.save_assessment(report)

        saved_baseline = store.get_latest_baseline("/tmp/test")
        assert saved_baseline is not None
        assert saved_baseline.pass_rate == 0.95
        assert saved_baseline.flaky_tests == ["test_a", "test_b"]

    def test_save_and_get_feedback(self, store: SeraphStore):
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.A,
        )
        store.save_assessment(report)

        fb = Feedback(
            assessment_id=report.id,
            outcome=FeedbackOutcome.ACCEPTED,
            context="Good assessment",
        )
        store.save_feedback(fb)

        feedbacks = store.get_feedback(report.id)
        assert len(feedbacks) == 1
        assert feedbacks[0].outcome == "accepted"
        assert feedbacks[0].context == "Good assessment"

    def test_stats(self, store: SeraphStore):
        stats = store.stats()
        assert stats["assessments"] == 0
        assert stats["feedback"] == 0

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "test.db"
        with SeraphStore(db_path) as s:
            s.conn.execute("SELECT 1")
        # Should be closed
        assert s._conn is None

    def test_get_nonexistent_assessment(self, store: SeraphStore):
        assert store.get_assessment("nonexistent") is None


class TestMigrationSystem:
    def test_migration_runs_on_version_bump(self, tmp_path):
        """Simulate a schema version bump and verify migrations run."""
        db_path = tmp_path / "migrate.db"

        # Create store at version 1
        with SeraphStore(db_path) as store:
            store.conn.execute(
                "INSERT OR REPLACE INTO seraph_meta (key, value) VALUES ('schema_version', '1')"
            )
            store.conn.commit()

        # Define a migration that adds a column
        migration_ran = []

        def _migrate_v1_to_v2(conn):
            conn.execute("ALTER TABLE assessments ADD COLUMN extra TEXT")
            migration_ran.append(True)

        # Patch SCHEMA_VERSION to 2 and register migration
        with patch("seraph.core.store.SCHEMA_VERSION", 2), \
             patch.dict(_MIGRATIONS, {1: _migrate_v1_to_v2}):
            with SeraphStore(db_path) as store:
                pass

        assert len(migration_ran) == 1

        # Verify the column was actually added
        with SeraphStore(db_path) as store:
            cur = store.conn.execute("PRAGMA table_info(assessments)")
            columns = {row["name"] for row in cur.fetchall()}
            assert "extra" in columns

    def test_no_migration_when_current(self, tmp_path):
        """No migrations run when schema is already at current version."""
        db_path = tmp_path / "current.db"

        migration_ran = []

        def _should_not_run(conn):
            migration_ran.append(True)

        with patch.dict(_MIGRATIONS, {1: _should_not_run}):
            with SeraphStore(db_path) as store:
                pass

        assert len(migration_ran) == 0

    def test_version_updated_after_migration(self, tmp_path):
        """Schema version is updated to SCHEMA_VERSION after migrations."""
        db_path = tmp_path / "version.db"

        # Create at version 1
        with patch("seraph.core.store.SCHEMA_VERSION", 1), \
             patch.dict(_MIGRATIONS, {}, clear=True):
            with SeraphStore(db_path) as store:
                pass

        # Bump to version 2
        with patch("seraph.core.store.SCHEMA_VERSION", 2), \
             patch.dict(_MIGRATIONS, {1: lambda conn: None}, clear=True):
            with SeraphStore(db_path) as store:
                cur = store.conn.execute(
                    "SELECT value FROM seraph_meta WHERE key = 'schema_version'"
                )
                assert cur.fetchone()["value"] == "2"

    def test_migration_v1_to_v2_adds_indices(self, tmp_path):
        """The v1->v2 migration adds the expected indices."""
        import sqlite3

        db_path = tmp_path / "indices.db"

        # Create a v1 database manually (without indices)
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS seraph_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY, repo_path TEXT, ref_before TEXT, ref_after TEXT,
                files_changed TEXT, mutation_score REAL, static_issues INTEGER,
                sentinel_warnings INTEGER, baseline_flaky INTEGER DEFAULT 0,
                grade TEXT, report_json TEXT, created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS baselines (
                id TEXT PRIMARY KEY, repo_path TEXT, test_cmd TEXT,
                run_count INTEGER DEFAULT 3, flaky_tests TEXT, pass_rate REAL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS mutation_cache (
                id TEXT PRIMARY KEY, assessment_id TEXT, file_path TEXT,
                mutant_id TEXT, operator TEXT, line_number INTEGER,
                status TEXT, created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY, assessment_id TEXT, outcome TEXT,
                context TEXT, created_at TEXT DEFAULT (datetime('now'))
            );
            INSERT INTO seraph_meta (key, value) VALUES ('schema_version', '1');
        """)
        conn.close()

        # Open with current code — should run migration
        with SeraphStore(db_path) as store:
            cur = store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
            )
            indices = {row["name"] for row in cur.fetchall()}

        assert "idx_assessments_repo_created" in indices
        assert "idx_assessments_created" in indices
        assert "idx_mutation_cache_assessment" in indices
        assert "idx_baselines_repo_created" in indices
        assert "idx_feedback_assessment" in indices


class TestPrune:
    def test_prune_deletes_old(self, store: SeraphStore):
        """Prune deletes assessments older than retention days."""
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.A,
        )
        store.save_assessment(report)

        # Manually set created_at to 200 days ago
        store.conn.execute(
            "UPDATE assessments SET created_at = datetime('now', '-200 days') WHERE id = ?",
            (report.id,),
        )
        store.conn.commit()

        result = store.prune(retention_days=90)
        assert result["assessments"] == 1

        # Verify it's gone
        assert store.get_assessment(report.id) is None

    def test_prune_preserves_recent(self, store: SeraphStore):
        """Prune does not delete recent assessments."""
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.A,
        )
        store.save_assessment(report)

        result = store.prune(retention_days=90)
        assert result["assessments"] == 0

        # Verify it's still there
        assert store.get_assessment(report.id) is not None

    def test_prune_cascades(self, store: SeraphStore):
        """Prune also deletes feedback and mutations for old assessments."""
        mutations = [
            MutationResult(file_path="foo.py", mutant_id="1", operator="negate", status=MutantStatus.KILLED),
        ]
        report = AssessmentReport(
            repo_path="/tmp/test",
            files_changed=["foo.py"],
            overall_grade=Grade.A,
            mutations=mutations,
        )
        store.save_assessment(report)

        fb = Feedback(
            assessment_id=report.id,
            outcome=FeedbackOutcome.ACCEPTED,
            context="test",
        )
        store.save_feedback(fb)

        # Age the assessment
        store.conn.execute(
            "UPDATE assessments SET created_at = datetime('now', '-200 days') WHERE id = ?",
            (report.id,),
        )
        store.conn.commit()

        result = store.prune(retention_days=90)
        assert result["assessments"] == 1
        assert result["mutation_cache"] == 1
        assert result["feedback"] == 1
