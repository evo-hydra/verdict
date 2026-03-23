"""Tests for SeraphEngine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from seraph.config import SeraphConfig, TimeoutConfig, ScoringConfig
from seraph.core.differ import DiffResult, FileChange
from seraph.core.engine import SeraphEngine
from seraph.core.mutator import MutationRunResult
from seraph.core.security import SecurityRunResult
from seraph.core.static import StaticRunResult
from seraph.core.store import SeraphStore
from seraph.models.assessment import MutationResult, BaselineResult, SecurityFinding, StaticFinding
from seraph.models.enums import AnalyzerType, Grade, MutantStatus, Severity


class TestSeraphEngine:
    def test_empty_diff_returns_perfect(self, store: SeraphStore, tmp_repo: Path):
        engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
        report = engine.assess(tmp_repo)
        assert report.overall_grade == Grade.A
        assert report.overall_score == 100.0
        assert report.files_changed == []
        assert all(not d.evaluated for d in report.dimensions)

    def test_empty_diff_is_persisted(self, store: SeraphStore, tmp_repo: Path):
        engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
        report = engine.assess(tmp_repo)
        saved = store.get_assessment(report.id)
        assert saved is not None

    @patch("seraph.core.engine.run_security_analysis")
    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.run_mutations")
    @patch("seraph.core.engine.run_baseline")
    @patch("seraph.core.engine.parse_diff")
    def test_full_pipeline(
        self, mock_diff, mock_baseline, mock_mutate, mock_static, mock_security,
        store: SeraphStore, tmp_repo: Path
    ):
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        mock_baseline.return_value = BaselineResult(
            repo_path=str(tmp_repo),
            flaky_tests=[],
            pass_rate=1.0,
        )
        mock_mutate.return_value = MutationRunResult(
            results=[MutationResult(file_path="src/foo.py", status=MutantStatus.KILLED)],
            tool_available=True,
        )
        mock_static.return_value = StaticRunResult(findings=[], tool_config={"ruff": False, "mypy": False})
        mock_security.return_value = SecurityRunResult(findings=[], tools_available={"bandit": True})

        engine = SeraphEngine(store)
        report = engine.assess(tmp_repo)

        assert report.files_changed == ["src/foo.py"]
        assert report.overall_grade == Grade.A

        # All 6 dimensions should be evaluated
        evaluated = [d for d in report.dimensions if d.evaluated]
        assert len(evaluated) == 6

        # Verify persisted
        saved = store.get_assessment(report.id)
        assert saved is not None

    def test_skip_baseline_and_mutations(self, store: SeraphStore, tmp_repo: Path):
        from tests.conftest import _git

        # Add a file change
        (tmp_repo / "new.py").write_text("x = 1\n")
        _git(tmp_repo, "add", "new.py")
        _git(tmp_repo, "commit", "-q", "-m", "add new")

        engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
        report = engine.assess(tmp_repo, ref_before="HEAD~1")

        assert "new.py" in report.files_changed
        assert report.mutation_score == 100.0  # Skipped = perfect

        # Baseline and mutation should NOT be evaluated
        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Mutation Score" not in evaluated_names
        assert "Test Baseline" not in evaluated_names
        # Static, sentinel, co-change should still be evaluated
        assert "Static Cleanliness" in evaluated_names
        assert "Sentinel Risk" in evaluated_names
        assert "Co-change Coverage" in evaluated_names

    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.parse_diff")
    def test_non_python_only_skips_heavy_steps(
        self, mock_diff, mock_static,
        store: SeraphStore, tmp_repo: Path
    ):
        """Only non-Python files changed: baseline, mutation, static are skipped."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="README.md")],
        )

        engine = SeraphEngine(store, skip_baseline=False, skip_mutations=False)
        report = engine.assess(tmp_repo)

        assert report.files_changed == ["README.md"]
        # Static analysis should not have been called (no py_files)
        mock_static.assert_not_called()
        # Baseline and mutation not evaluated (no py_files)
        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Mutation Score" not in evaluated_names
        assert "Test Baseline" not in evaluated_names

    @patch("seraph.core.engine.run_mutations")
    @patch("seraph.core.engine.parse_diff")
    def test_mutate_only(self, mock_diff, mock_mutate, store: SeraphStore, tmp_repo: Path):
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="foo.py")],
        )
        mock_mutate.return_value = MutationRunResult(
            results=[
                MutationResult(status=MutantStatus.KILLED),
                MutationResult(status=MutantStatus.SURVIVED),
            ],
            tool_available=True,
        )

        engine = SeraphEngine(store)
        report = engine.mutate_only(tmp_repo)

        assert report.mutation_score == 50.0

        # Only mutation dimension should be evaluated
        evaluated = [d for d in report.dimensions if d.evaluated]
        assert len(evaluated) == 1
        assert evaluated[0].name == "Mutation Score"

    def test_engine_accepts_config(self, store: SeraphStore, tmp_repo: Path):
        """SeraphEngine works with a custom SeraphConfig."""
        config = SeraphConfig(
            timeouts=TimeoutConfig(mutation_per_file=60, static_analysis=30),
            scoring=ScoringConfig(mutation_weight=0.50, static_weight=0.10),
        )
        engine = SeraphEngine(store, config=config, skip_baseline=True, skip_mutations=True)
        report = engine.assess(tmp_repo)
        # Should still work (empty diff = grade A)
        assert report.overall_grade == Grade.A

    @patch("seraph.core.engine.run_security_analysis")
    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.run_baseline")
    @patch("seraph.core.engine.parse_diff")
    def test_step_failure_doesnt_crash_pipeline(
        self, mock_diff, mock_baseline, mock_static, mock_security,
        store: SeraphStore, tmp_repo: Path
    ):
        """A single step failure doesn't crash the entire pipeline."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        # Baseline raises, but pipeline should continue
        mock_baseline.side_effect = RuntimeError("baseline boom")
        mock_static.return_value = StaticRunResult(findings=[], tool_config={"ruff": False, "mypy": False})
        mock_security.return_value = SecurityRunResult(findings=[], tools_available={"bandit": True})

        engine = SeraphEngine(store, skip_mutations=True)
        report = engine.assess(tmp_repo)

        # Pipeline should still produce a report
        assert report is not None
        assert report.overall_grade is not None
        # Baseline should NOT be in evaluated dimensions (since it failed)
        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Test Baseline" not in evaluated_names

    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.run_mutations")
    @patch("seraph.core.engine.parse_diff")
    def test_empty_mutations_marks_na(
        self, mock_diff, mock_mutate, mock_static,
        store: SeraphStore, tmp_repo: Path
    ):
        """mutmut available but no results → mutation not in evaluated."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        mock_mutate.return_value = MutationRunResult(
            results=[], tool_available=True,
        )
        mock_static.return_value = StaticRunResult(
            findings=[], tool_config={"ruff": False, "mypy": False},
        )

        engine = SeraphEngine(store, skip_baseline=True)
        report = engine.assess(tmp_repo)

        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Mutation Score" not in evaluated_names

    @patch("seraph.core.engine.run_security_analysis")
    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.parse_diff")
    def test_security_failure_doesnt_crash(
        self, mock_diff, mock_static, mock_security,
        store: SeraphStore, tmp_repo: Path
    ):
        """Security step exception doesn't crash the pipeline."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        mock_static.return_value = StaticRunResult(findings=[], tool_config={"ruff": False, "mypy": False})
        mock_security.side_effect = RuntimeError("security boom")

        engine = SeraphEngine(store, skip_baseline=True, skip_mutations=True)
        report = engine.assess(tmp_repo)

        assert report is not None
        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Security" not in evaluated_names

    @patch("seraph.core.engine.run_security_analysis")
    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.run_mutations")
    @patch("seraph.core.engine.parse_diff")
    def test_full_pipeline_with_security_findings(
        self, mock_diff, mock_mutate, mock_static, mock_security,
        store: SeraphStore, tmp_repo: Path
    ):
        """Pipeline with security findings produces 6 evaluated dimensions."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        mock_mutate.return_value = MutationRunResult(
            results=[MutationResult(status=MutantStatus.KILLED)],
            tool_available=True,
        )
        mock_static.return_value = StaticRunResult(findings=[], tool_config={"ruff": False, "mypy": False})
        mock_security.return_value = SecurityRunResult(
            findings=[
                SecurityFinding(code="B608", cwe_id="CWE-89", severity=Severity.HIGH),
            ],
            tools_available={"bandit": True},
        )

        engine = SeraphEngine(store, skip_baseline=True)
        report = engine.assess(tmp_repo)

        evaluated_names = {d.name for d in report.dimensions if d.evaluated}
        assert "Security" in evaluated_names
        # Security score should be below 100 due to findings
        security_dim = next(d for d in report.dimensions if d.name == "Security")
        assert security_dim.raw_score < 100.0
        assert len(report.security_findings) == 1

    @patch("seraph.core.engine.run_static_analysis")
    @patch("seraph.core.engine.run_mutations")
    @patch("seraph.core.engine.parse_diff")
    def test_unconfigured_mypy_excluded_from_score(
        self, mock_diff, mock_mutate, mock_static,
        store: SeraphStore, tmp_repo: Path
    ):
        """mypy findings present but config False → static score based on ruff only."""
        mock_diff.return_value = DiffResult(
            files=[FileChange(path="src/foo.py")],
        )
        mock_mutate.return_value = MutationRunResult(
            results=[MutationResult(status=MutantStatus.KILLED)],
            tool_available=True,
        )
        # 1 ruff finding (LOW=1), 10 mypy findings (HIGH=5 each)
        ruff_findings = [StaticFinding(severity=Severity.LOW, analyzer=AnalyzerType.RUFF)]
        mypy_findings = [
            StaticFinding(severity=Severity.HIGH, analyzer=AnalyzerType.MYPY)
            for _ in range(10)
        ]
        mock_static.return_value = StaticRunResult(
            findings=ruff_findings + mypy_findings,
            tool_config={"ruff": True, "mypy": False},
        )

        engine = SeraphEngine(store, skip_baseline=True)
        report = engine.assess(tmp_repo)

        # Static score should be based on ruff only (1 LOW finding, weight=1, 1 file)
        # 100 / (1 + 1/10) = 90.9
        static_dim = next(d for d in report.dimensions if d.name == "Static Cleanliness")
        assert static_dim.raw_score == 90.9
