"""SQLite storage for Seraph assessments and results."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from pathlib import Path

from seraph.models.assessment import (
    AssessmentReport,
    BaselineResult,
    Calibration,
    Feedback,
    MutationResult,
    StoredAssessment,
    StoredBaseline,
    StoredCalibration,
    StoredFeedback,
    StoredMutation,
)
from seraph.models.enums import FeedbackOutcome, Grade, MutantStatus

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 3

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS seraph_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
    id              TEXT PRIMARY KEY,
    repo_path       TEXT NOT NULL,
    ref_before      TEXT,
    ref_after       TEXT,
    files_changed   TEXT NOT NULL,
    mutation_score  REAL,
    static_issues   INTEGER,
    sentinel_warnings INTEGER,
    baseline_flaky  INTEGER DEFAULT 0,
    grade           TEXT NOT NULL,
    report_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS baselines (
    id          TEXT PRIMARY KEY,
    repo_path   TEXT NOT NULL,
    test_cmd    TEXT NOT NULL,
    run_count   INTEGER NOT NULL DEFAULT 3,
    flaky_tests TEXT,
    pass_rate   REAL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mutation_cache (
    id              TEXT PRIMARY KEY,
    assessment_id   TEXT NOT NULL REFERENCES assessments(id),
    file_path       TEXT NOT NULL,
    mutant_id       TEXT NOT NULL,
    operator        TEXT NOT NULL,
    line_number     INTEGER,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS feedback (
    id              TEXT PRIMARY KEY,
    assessment_id   TEXT NOT NULL REFERENCES assessments(id),
    outcome         TEXT NOT NULL,
    context         TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_assessments_repo_created ON assessments(repo_path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mutation_cache_assessment ON mutation_cache(assessment_id, file_path);
CREATE INDEX IF NOT EXISTS idx_baselines_repo_created ON baselines(repo_path, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_assessment ON feedback(assessment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS calibrations (
    id                  TEXT PRIMARY KEY,
    check_category      TEXT NOT NULL,
    finding_description TEXT NOT NULL,
    is_false_positive   INTEGER NOT NULL DEFAULT 1,
    context             TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_calibrations_category ON calibrations(check_category, created_at DESC);
"""


# ── Migrations ───────────────────────────────────────────────────

# Add new migrations here as functions, then register in _MIGRATIONS.
# Pattern: def _migrate_vN_to_vN1(conn: sqlite3.Connection) -> None


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Add performance indices for common query patterns."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_repo_created ON assessments(repo_path, created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mutation_cache_assessment ON mutation_cache(assessment_id, file_path)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_repo_created ON baselines(repo_path, created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feedback_assessment ON feedback(assessment_id, created_at DESC)")


def _migrate_v2_to_v3(conn: sqlite3.Connection) -> None:
    """Add calibrations table for FP/FN threshold tuning."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS calibrations (
            id                  TEXT PRIMARY KEY,
            check_category      TEXT NOT NULL,
            finding_description TEXT NOT NULL,
            is_false_positive   INTEGER NOT NULL DEFAULT 1,
            context             TEXT,
            created_at          TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_calibrations_category "
        "ON calibrations(check_category, created_at DESC)"
    )


_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migrate_v1_to_v2,
    2: _migrate_v2_to_v3,
}

_STATS_TABLES = frozenset({"assessments", "baselines", "mutation_cache", "feedback", "calibrations"})


class SeraphStore:
    """SQLite-backed storage for Seraph data."""

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> SeraphStore:
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Store not opened. Call open() or use as context manager.")
        return self._conn

    def _init_schema(self) -> None:
        self.conn.executescript(_SCHEMA_SQL)
        cur = self.conn.execute(
            "SELECT value FROM seraph_meta WHERE key = 'schema_version'"
        )
        row = cur.fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO seraph_meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()
            return

        # Run migrations if needed
        current = int(row["value"])
        if current < SCHEMA_VERSION:
            self._run_migrations(current)

    def _run_migrations(self, current: int) -> None:
        """Run pending schema migrations from current version."""
        for version in range(current, SCHEMA_VERSION):
            migration = _MIGRATIONS.get(version)
            if migration:
                logger.info("Running migration v%d → v%d", version, version + 1)
                migration(self.conn)

        self.conn.execute(
            "INSERT OR REPLACE INTO seraph_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    # ── Assessments ──────────────────────────────────────────────

    def save_assessment(self, report: AssessmentReport) -> None:
        self.conn.execute(
            """INSERT INTO assessments
               (id, repo_path, ref_before, ref_after, files_changed,
                mutation_score, static_issues, sentinel_warnings,
                baseline_flaky, grade, report_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.id,
                report.repo_path,
                report.ref_before,
                report.ref_after,
                json.dumps(report.files_changed),
                report.mutation_score,
                report.static_issues,
                report.sentinel_warnings,
                report.baseline_flaky,
                report.overall_grade.value,
                report.to_json(),
                report.created_at,
            ),
        )
        for m in report.mutations:
            self._save_mutation(m, report.id)
        if report.baseline:
            self._save_baseline(report.baseline)
        self.conn.commit()

    def get_assessment(self, assessment_id: str) -> StoredAssessment | None:
        cur = self.conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_assessment(row)

    def get_assessments(
        self, limit: int = 20, offset: int = 0, repo_path: str | None = None
    ) -> list[StoredAssessment]:
        if repo_path:
            cur = self.conn.execute(
                """SELECT * FROM assessments WHERE repo_path = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (repo_path, limit, offset),
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM assessments ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        return [self._row_to_assessment(r) for r in cur.fetchall()]

    def _row_to_assessment(self, row: sqlite3.Row) -> StoredAssessment:
        return StoredAssessment(
            id=row["id"],
            repo_path=row["repo_path"],
            ref_before=row["ref_before"],
            ref_after=row["ref_after"],
            files_changed=json.loads(row["files_changed"]),
            mutation_score=row["mutation_score"],
            static_issues=row["static_issues"],
            sentinel_warnings=row["sentinel_warnings"],
            baseline_flaky=row["baseline_flaky"],
            grade=row["grade"],
            report_json=row["report_json"],
            created_at=row["created_at"],
        )

    # ── Mutations ────────────────────────────────────────────────

    def _save_mutation(self, m: MutationResult, assessment_id: str) -> None:
        self.conn.execute(
            """INSERT INTO mutation_cache
               (id, assessment_id, file_path, mutant_id, operator,
                line_number, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                m.id,
                assessment_id,
                m.file_path,
                m.mutant_id,
                m.operator,
                m.line_number,
                m.status.value,
                m.created_at,
            ),
        )

    def get_mutations(self, assessment_id: str) -> list[StoredMutation]:
        cur = self.conn.execute(
            "SELECT * FROM mutation_cache WHERE assessment_id = ? ORDER BY file_path",
            (assessment_id,),
        )
        return [
            StoredMutation(
                id=r["id"],
                assessment_id=r["assessment_id"],
                file_path=r["file_path"],
                mutant_id=r["mutant_id"],
                operator=r["operator"],
                line_number=r["line_number"],
                status=r["status"],
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    # ── Baselines ────────────────────────────────────────────────

    def _save_baseline(self, b: BaselineResult) -> None:
        self.conn.execute(
            """INSERT INTO baselines
               (id, repo_path, test_cmd, run_count, flaky_tests, pass_rate, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                b.id,
                b.repo_path,
                b.test_cmd,
                b.run_count,
                json.dumps(b.flaky_tests),
                b.pass_rate,
                b.created_at,
            ),
        )

    def get_latest_baseline(self, repo_path: str) -> StoredBaseline | None:
        cur = self.conn.execute(
            """SELECT * FROM baselines WHERE repo_path = ?
               ORDER BY created_at DESC LIMIT 1""",
            (repo_path,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return StoredBaseline(
            id=row["id"],
            repo_path=row["repo_path"],
            test_cmd=row["test_cmd"],
            run_count=row["run_count"],
            flaky_tests=json.loads(row["flaky_tests"]) if row["flaky_tests"] else [],
            pass_rate=row["pass_rate"],
            created_at=row["created_at"],
        )

    # ── Feedback ─────────────────────────────────────────────────

    def save_feedback(self, fb: Feedback) -> None:
        self.conn.execute(
            """INSERT INTO feedback (id, assessment_id, outcome, context, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (fb.id, fb.assessment_id, fb.outcome.value, fb.context, fb.created_at),
        )
        self.conn.commit()

    def get_feedback(self, assessment_id: str) -> list[StoredFeedback]:
        cur = self.conn.execute(
            "SELECT * FROM feedback WHERE assessment_id = ? ORDER BY created_at DESC",
            (assessment_id,),
        )
        return [
            StoredFeedback(
                id=r["id"],
                assessment_id=r["assessment_id"],
                outcome=r["outcome"],
                context=r["context"] or "",
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    # ── Calibrations ────────────────────────────────────────────

    def save_calibration(self, cal: Calibration) -> None:
        self.conn.execute(
            """INSERT INTO calibrations
               (id, check_category, finding_description, is_false_positive,
                context, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                cal.id,
                cal.check_category,
                cal.finding_description,
                1 if cal.is_false_positive else 0,
                cal.context,
                cal.created_at,
            ),
        )
        self.conn.commit()

    def get_calibration_stats(self) -> dict[str, dict[str, int]]:
        """Get FP/FN counts per check category."""
        cur = self.conn.execute(
            """SELECT check_category, is_false_positive, COUNT(*) as cnt
               FROM calibrations GROUP BY check_category, is_false_positive"""
        )
        stats: dict[str, dict[str, int]] = {}
        for row in cur.fetchall():
            cat = row["check_category"]
            if cat not in stats:
                stats[cat] = {"fp": 0, "fn": 0}
            if row["is_false_positive"]:
                stats[cat]["fp"] = row["cnt"]
            else:
                stats[cat]["fn"] = row["cnt"]
        return stats

    def get_calibrations(
        self, check_category: str | None = None, limit: int = 50
    ) -> list[StoredCalibration]:
        if check_category:
            cur = self.conn.execute(
                """SELECT * FROM calibrations WHERE check_category = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (check_category, limit),
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM calibrations ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        return [
            StoredCalibration(
                id=r["id"],
                check_category=r["check_category"],
                finding_description=r["finding_description"],
                is_false_positive=bool(r["is_false_positive"]),
                context=r["context"] or "",
                created_at=r["created_at"],
            )
            for r in cur.fetchall()
        ]

    # ── Prune ────────────────────────────────────────────────────

    def prune(self, retention_days: int = 90) -> dict[str, int]:
        """Delete data older than retention_days.

        Deletes in dependency order to respect foreign keys.
        Returns {table: rows_deleted}.
        """
        cutoff = f"datetime('now', '-{retention_days} days')"
        result: dict[str, int] = {}

        # Get assessment IDs to delete
        old_ids = self.conn.execute(
            f"SELECT id FROM assessments WHERE created_at < {cutoff}"  # noqa: S608
        ).fetchall()
        old_id_list = [r["id"] for r in old_ids]

        if not old_id_list:
            return {"feedback": 0, "mutation_cache": 0, "baselines": 0, "assessments": 0}

        placeholders = ",".join("?" * len(old_id_list))

        # Delete in dependency order
        cur = self.conn.execute(
            f"DELETE FROM feedback WHERE assessment_id IN ({placeholders})",  # noqa: S608
            old_id_list,
        )
        result["feedback"] = cur.rowcount

        cur = self.conn.execute(
            f"DELETE FROM mutation_cache WHERE assessment_id IN ({placeholders})",  # noqa: S608
            old_id_list,
        )
        result["mutation_cache"] = cur.rowcount

        cur = self.conn.execute(
            f"DELETE FROM baselines WHERE created_at < {cutoff}"  # noqa: S608
        )
        result["baselines"] = cur.rowcount

        cur = self.conn.execute(
            f"DELETE FROM assessments WHERE id IN ({placeholders})",  # noqa: S608
            old_id_list,
        )
        result["assessments"] = cur.rowcount

        self.conn.commit()

        total = sum(result.values())
        if total > 0:
            self.conn.execute("VACUUM")

        return result

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        result = {}
        for table in sorted(_STATS_TABLES):
            cur = self.conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            result[table] = cur.fetchone()[0]
        return result
