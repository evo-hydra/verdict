"""Data models for Seraph assessments."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from seraph.models.enums import (
    AnalyzerType,
    CheckCategory,
    FeedbackOutcome,
    GateSource,
    GateVerdict,
    Grade,
    MutantStatus,
    Severity,
    Verdict,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _new_id() -> str:
    return uuid.uuid4().hex


# ── Tier 1 Check Types ──────────────────────────────────────────


@dataclass
class CheckFinding:
    """A single finding from a Tier 1 fast check."""

    check: CheckCategory = CheckCategory.SECURITY_SURFACE
    file: str = ""
    line: int = 0
    description: str = ""
    suggestion: str = ""
    confidence: float = 0.9


@dataclass
class CheckResult:
    """Result of Tier 1 pre-write checks."""

    verdict: Verdict = Verdict.ALLOW
    findings: list[CheckFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "findings": [
                {
                    "check": f.check.value,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "suggestion": f.suggestion,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Tier 2 Gate Types ──────────────────────────────────────────


@dataclass
class GateFinding:
    """A single finding from a Tier 2 gate check."""

    source: GateSource = GateSource.MUTATION
    file: str = ""
    line: int = 0
    description: str = ""
    suggestion: str = ""
    confidence: float = 0.9
    mutant_code: str = ""  # for mutation findings: the mutated line


@dataclass
class GateResult:
    """Result of Tier 2 pre-commit gate."""

    verdict: GateVerdict = GateVerdict.ACCEPT
    findings: list[GateFinding] = field(default_factory=list)
    mutation_score: float = 100.0
    mutants_tested: int = 0
    mutants_survived: int = 0
    attempt: int = 1  # trajectory tracking

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "findings": [
                {
                    "source": f.source.value,
                    "file": f.file,
                    "line": f.line,
                    "description": f.description,
                    "suggestion": f.suggestion,
                    "confidence": f.confidence,
                    "mutant_code": f.mutant_code,
                }
                for f in self.findings
            ],
            "mutation_score": round(self.mutation_score, 1),
            "mutants_tested": self.mutants_tested,
            "mutants_survived": self.mutants_survived,
            "attempt": self.attempt,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Core Result Types ────────────────────────────────────────────


@dataclass
class MutationResult:
    """Result of a single mutation test."""

    id: str = field(default_factory=_new_id)
    assessment_id: str = ""
    file_path: str = ""
    mutant_id: str = ""
    operator: str = ""
    line_number: int | None = None
    status: MutantStatus = MutantStatus.SURVIVED
    created_at: str = field(default_factory=_utcnow)


@dataclass
class StaticFinding:
    """A single finding from static analysis."""

    file_path: str = ""
    line_number: int = 0
    column: int = 0
    code: str = ""
    message: str = ""
    severity: Severity = Severity.MEDIUM
    analyzer: AnalyzerType = AnalyzerType.RUFF


@dataclass
class SecurityFinding:
    """A single finding from security analysis (bandit/semgrep/detect-secrets)."""

    file_path: str = ""
    line_number: int = 0
    column: int = 0
    code: str = ""
    message: str = ""
    severity: Severity = Severity.MEDIUM
    analyzer: AnalyzerType = AnalyzerType.BANDIT
    cwe_id: str = ""
    confidence: str = ""
    source_line: str = ""


@dataclass
class BaselineResult:
    """Result of flakiness baseline testing."""

    id: str = field(default_factory=_new_id)
    repo_path: str = ""
    test_cmd: str = "pytest"
    run_count: int = 3
    flaky_tests: list[str] = field(default_factory=list)
    pass_rate: float = 1.0
    created_at: str = field(default_factory=_utcnow)


# ── Typed Sentinel Signal Models ─────────────────────────────────


@dataclass
class PitfallMatch:
    """A Sentinel pitfall matched against a changed file."""

    pitfall_id: str = ""
    description: str = ""
    severity: str = "medium"
    how_to_prevent: str = ""
    matched_file: str = ""
    match_type: str = "code_pattern"  # "file_path" or "code_pattern"


@dataclass
class HotFileInfo:
    """Hot file data from Sentinel for a changed file."""

    file_path: str = ""
    churn_score: float = 0.0
    change_count: int = 0
    bug_fix_count: int = 0
    revert_count: int = 0


@dataclass
class MissingCoChange:
    """A co-change partner that wasn't included in the diff."""

    source_file: str = ""
    partner_file: str = ""
    change_count: int = 0


@dataclass
class SentinelSignals:
    """Risk signals from Sentinel integration."""

    available: bool = False
    pitfall_matches: list[PitfallMatch] = field(default_factory=list)
    hot_files: list[HotFileInfo] = field(default_factory=list)
    missing_co_changes: list[MissingCoChange] = field(default_factory=list)


# ── Scoring ──────────────────────────────────────────────────────


@dataclass
class DimensionScore:
    """Score for a single assessment dimension."""

    name: str = ""
    raw_score: float = 0.0
    weight: float = 0.0
    weighted_score: float = 0.0
    grade: Grade = Grade.F
    details: str = ""
    evaluated: bool = True


# ── Report ───────────────────────────────────────────────────────


@dataclass
class AssessmentReport:
    """Complete multi-metric assessment report."""

    id: str = field(default_factory=_new_id)
    repo_path: str = ""
    ref_before: str | None = None
    ref_after: str | None = None
    files_changed: list[str] = field(default_factory=list)
    dimensions: list[DimensionScore] = field(default_factory=list)
    overall_score: float = 0.0
    overall_grade: Grade = Grade.F
    mutation_score: float = 0.0
    static_issues: int = 0
    sentinel_warnings: int = 0
    baseline_flaky: int = 0
    gaps: list[str] = field(default_factory=list)
    mutations: list[MutationResult] = field(default_factory=list)
    static_findings: list[StaticFinding] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    baseline: BaselineResult | None = None
    sentinel_signals: SentinelSignals = field(default_factory=SentinelSignals)
    created_at: str = field(default_factory=_utcnow)

    @property
    def is_vacuous(self) -> bool:
        """True when no dimensions were evaluated — grade is meaningless."""
        return self.overall_grade == Grade.VACUOUS

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "id": self.id,
            "repo_path": self.repo_path,
            "ref_before": self.ref_before,
            "ref_after": self.ref_after,
            "files_changed": self.files_changed,
            "overall_score": round(self.overall_score, 1),
            "overall_grade": self.overall_grade.value,
            "dimensions": [
                {
                    "name": d.name,
                    "raw_score": round(d.raw_score, 1),
                    "weight": d.weight,
                    "weighted_score": round(d.weighted_score, 1),
                    "grade": d.grade.value,
                    "details": d.details,
                    "evaluated": d.evaluated,
                }
                for d in self.dimensions
            ],
            "mutation_score": round(self.mutation_score, 1),
            "static_issues": self.static_issues,
            "sentinel_warnings": self.sentinel_warnings,
            "baseline_flaky": self.baseline_flaky,
            "security_issues": len(self.security_findings),
            "gaps": self.gaps,
            "is_vacuous": self.is_vacuous,
            "evaluated_count": sum(1 for d in self.dimensions if d.evaluated),
            "dimension_count": len(self.dimensions),
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ── Stored Data Models (returned by SeraphStore) ────────────────


@dataclass
class StoredAssessment:
    """An assessment as persisted in SQLite."""

    id: str = ""
    repo_path: str = ""
    ref_before: str | None = None
    ref_after: str | None = None
    files_changed: list[str] = field(default_factory=list)
    mutation_score: float | None = None
    static_issues: int | None = None
    sentinel_warnings: int | None = None
    baseline_flaky: int = 0
    grade: str = ""
    report_json: str = ""
    created_at: str = ""


@dataclass
class StoredMutation:
    """A mutation cache entry as persisted in SQLite."""

    id: str = ""
    assessment_id: str = ""
    file_path: str = ""
    mutant_id: str = ""
    operator: str = ""
    line_number: int | None = None
    status: str = ""
    created_at: str = ""


@dataclass
class StoredBaseline:
    """A baseline entry as persisted in SQLite."""

    id: str = ""
    repo_path: str = ""
    test_cmd: str = ""
    run_count: int = 3
    flaky_tests: list[str] = field(default_factory=list)
    pass_rate: float | None = None
    created_at: str = ""


@dataclass
class StoredFeedback:
    """A feedback entry as persisted in SQLite."""

    id: str = ""
    assessment_id: str = ""
    outcome: str = ""
    context: str = ""
    created_at: str = ""


@dataclass
class Feedback:
    """User feedback on an assessment."""

    id: str = field(default_factory=_new_id)
    assessment_id: str = ""
    outcome: FeedbackOutcome = field(default=FeedbackOutcome.ACCEPTED)
    context: str = ""
    created_at: str = field(default_factory=_utcnow)
