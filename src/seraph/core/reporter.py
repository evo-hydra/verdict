"""Tier 3 report generation — background learning signal only.

Computes multi-metric scores across 6 dimensions for retrospective
analysis. NOT used as a gate (gates are in checks.py and gate.py).
Individual score functions (compute_*_score) are reused by Tier 1/2.

All scoring logic is consolidated here — baseline, mutation, static,
security, sentinel risk, and co-change coverage scores are all computed
in this module.
"""

from __future__ import annotations

import logging

from seraph.config import ScoringConfig
from seraph.models.assessment import (
    AssessmentReport,
    BaselineResult,
    DimensionScore,
    MutationResult,
    SecurityFinding,
    SentinelSignals,
    StaticFinding,
)
from seraph.core.security import cwe_weight
from seraph.models.enums import Grade, MutantStatus, Severity

logger = logging.getLogger(__name__)

# ── Weight Configuration (defaults — overridden by ScoringConfig) ──

DIMENSION_WEIGHTS = {
    "mutation": 0.25,
    "static": 0.20,
    "baseline": 0.10,
    "sentinel_risk": 0.20,
    "co_change": 0.10,
    "security": 0.15,
}

# ── Scoring Constants (defaults — overridden by ScoringConfig) ─────

BASELINE_DEDUCTION_PER_FLAKY = 10.0
RISK_DEDUCTION_PER_PITFALL = 5.0
RISK_DEDUCTION_PER_MISSING_CO_CHANGE = 3.0
RISK_HOT_FILE_CHURN_DIVISOR = 5.0
RISK_HOT_FILE_MAX_DEDUCTION = 10.0
STATIC_ISSUE_THRESHOLD = 10.0

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


# ── Score Computation Functions ───────────────────────────────


def compute_baseline_score(
    baseline: BaselineResult, scoring: ScoringConfig | None = None
) -> float:
    """Convert baseline result to a 0-100 score."""
    flaky_count = len(baseline.flaky_tests)
    if flaky_count == 0:
        return 100.0
    deduction = scoring.baseline_deduction_per_flaky if scoring else BASELINE_DEDUCTION_PER_FLAKY
    return max(0.0, 100.0 - flaky_count * deduction)


def compute_mutation_score(results: list[MutationResult]) -> float:
    """Compute mutation score as percentage of killed mutants."""
    if not results:
        return 100.0
    total = len(results)
    killed = sum(1 for r in results if r.status == MutantStatus.KILLED)
    return round((killed / total) * 100, 1)


def compute_static_score(
    findings: list[StaticFinding], file_count: int, scoring: ScoringConfig | None = None
) -> float:
    """Compute static cleanliness score (0-100).

    Uses an asymptotic curve: 100 / (1 + issues_per_file / threshold).
    This never hits 0% — even projects with many issues get a nonzero signal.
    """
    if file_count == 0:
        return 100.0

    sev_weights = _get_severity_weights(scoring)
    weighted_issues = sum(sev_weights.get(f.severity, 1) for f in findings)
    issues_per_file = weighted_issues / file_count

    threshold = scoring.static_issue_threshold if scoring else STATIC_ISSUE_THRESHOLD
    score = 100.0 / (1.0 + issues_per_file / threshold)
    return round(score, 1)


def compute_security_score(
    findings: list[SecurityFinding], file_count: int, scoring: ScoringConfig | None = None
) -> float:
    """Compute security score (0-100) with CWE tier weighting.

    Uses the same asymptotic curve as static score but applies CWE tier
    multipliers so critical vulnerability classes (SQLi, XSS) deduct more.
    """
    if file_count == 0:
        return 100.0

    sev_weights = _get_severity_weights(scoring)
    weighted_issues = sum(
        sev_weights.get(f.severity, 1) * cwe_weight(f.cwe_id)
        for f in findings
    )
    issues_per_file = weighted_issues / file_count

    threshold = scoring.security_issue_threshold if scoring else 5.0
    score = 100.0 / (1.0 + issues_per_file / threshold)
    return round(score, 1)


def compute_risk_score(
    signals: SentinelSignals, scoring: ScoringConfig | None = None
) -> float:
    """Compute Sentinel risk score (0-100, higher = safer)."""
    if not signals.available:
        return 100.0

    max_ded = scoring.risk_hot_file_max_deduction if scoring else RISK_HOT_FILE_MAX_DEDUCTION
    divisor = scoring.risk_hot_file_churn_divisor if scoring else RISK_HOT_FILE_CHURN_DIVISOR
    pitfall_ded = scoring.risk_deduction_per_pitfall if scoring else RISK_DEDUCTION_PER_PITFALL
    co_ded = scoring.risk_deduction_per_missing_co_change if scoring else RISK_DEDUCTION_PER_MISSING_CO_CHANGE

    deductions = 0.0
    for hf in signals.hot_files:
        deductions += min(max_ded, hf.churn_score / divisor)

    deductions += len(signals.pitfall_matches) * pitfall_ded
    deductions += len(signals.missing_co_changes) * co_ded

    return round(max(0.0, 100.0 - deductions), 1)


def _get_severity_weights(scoring: ScoringConfig | None) -> dict:
    """Get severity weights from config or module defaults."""
    if scoring:
        return {
            Severity.CRITICAL: scoring.severity_critical,
            Severity.HIGH: scoring.severity_high,
            Severity.MEDIUM: scoring.severity_medium,
            Severity.LOW: scoring.severity_low,
            Severity.INFO: scoring.severity_info,
        }
    return SEVERITY_WEIGHTS


def compute_co_change_score(signals: SentinelSignals, changed_files: list[str]) -> float:
    """Compute co-change coverage score (0-100).

    Measures whether all expected co-change partners are included in the diff.
    """
    if not signals.available:
        return 100.0

    missing = len(signals.missing_co_changes)
    if not missing and not changed_files:
        return 100.0

    total_partners = len(changed_files) + missing
    if total_partners == 0:
        return 100.0

    coverage = len(changed_files) / total_partners
    return round(coverage * 100, 1)


# ── Report Builder ────────────────────────────────────────────


def build_report(
    *,
    repo_path: str,
    ref_before: str | None,
    ref_after: str | None,
    files_changed: list[str],
    mutation_score: float,
    static_score: float,
    baseline_score: float,
    sentinel_risk_score: float,
    co_change_score: float,
    security_score: float = 100.0,
    mutations: list[MutationResult],
    static_findings: list[StaticFinding],
    security_findings: list[SecurityFinding] | None = None,
    baseline: BaselineResult | None,
    sentinel_signals: SentinelSignals,
    evaluated_dimensions: set[str] | None = None,
    scoring: ScoringConfig | None = None,
    mutation_tool_available: bool = True,
    tool_config: dict[str, bool] | None = None,
) -> AssessmentReport:
    """Build a complete assessment report from individual dimension scores.

    Args:
        evaluated_dimensions: Set of dimension keys that were actually evaluated.
            If None, all dimensions are considered evaluated.
            Valid keys: "mutation", "static", "baseline", "sentinel_risk", "co_change", "security"
        scoring: Optional scoring configuration. Uses module defaults if None.
    """
    all_dims = {"mutation", "static", "baseline", "sentinel_risk", "co_change", "security"}
    evaluated = evaluated_dimensions if evaluated_dimensions is not None else all_dims
    weights = scoring.dimension_weights if scoring else DIMENSION_WEIGHTS
    thresholds = scoring.grade_thresholds if scoring else None
    sec_findings = security_findings or []

    dimensions = [
        _score_dimension("Mutation Score", mutation_score, weights["mutation"],
                         _mutation_details(mutations, tool_available=mutation_tool_available),
                         "mutation" in evaluated, thresholds),
        _score_dimension("Static Cleanliness", static_score, weights["static"],
                         _static_details(static_findings, tool_config=tool_config),
                         "static" in evaluated, thresholds),
        _score_dimension("Test Baseline", baseline_score, weights["baseline"],
                         _baseline_details(baseline), "baseline" in evaluated, thresholds),
        _score_dimension("Sentinel Risk", sentinel_risk_score, weights["sentinel_risk"],
                         _sentinel_details(sentinel_signals), "sentinel_risk" in evaluated, thresholds),
        _score_dimension("Co-change Coverage", co_change_score, weights["co_change"],
                         _cochange_details(sentinel_signals), "co_change" in evaluated, thresholds),
        _score_dimension("Security", security_score, weights["security"],
                         _security_details(sec_findings), "security" in evaluated, thresholds),
    ]

    # Overall score only considers evaluated dimensions, re-weighted
    evaluated_dims = [d for d in dimensions if d.evaluated]
    min_dimensions = scoring.min_evaluated_dimensions if scoring else 3
    if evaluated_dims:
        total_weight = sum(d.weight for d in evaluated_dims)
        if total_weight > 0:
            overall_score = sum(d.raw_score * (d.weight / total_weight) for d in evaluated_dims)
        else:
            overall_score = 0.0
        overall_grade = Grade.from_score(overall_score, thresholds)
        # When too few dimensions evaluated, mark as INCOMPLETE rather
        # than capping at D. D implies "bad code" — INCOMPLETE means
        # "can't assess." This prevents config-only changes (JSON, YAML)
        # from getting scary grades that train operators to ignore Seraph.
        if len(evaluated_dims) < min_dimensions:
            logger.warning(
                "Only %d/%d dimensions evaluated — grade set to INCOMPLETE (score was %.1f, grade was %s)",
                len(evaluated_dims), len(all_dims), overall_score, overall_grade.value,
            )
            overall_grade = Grade.INCOMPLETE
    else:
        overall_score = 0.0
        overall_grade = Grade.VACUOUS
    gaps = _identify_gaps(dimensions)

    return AssessmentReport(
        repo_path=repo_path,
        ref_before=ref_before,
        ref_after=ref_after,
        files_changed=files_changed,
        dimensions=dimensions,
        overall_score=round(overall_score, 1),
        overall_grade=overall_grade,
        mutation_score=mutation_score,
        static_issues=sum(
            1 for f in static_findings
            if tool_config is None or tool_config.get(f.analyzer.value, True)
        ),
        sentinel_warnings=len(sentinel_signals.pitfall_matches) + len(sentinel_signals.hot_files),
        baseline_flaky=len(baseline.flaky_tests) if baseline else 0,
        gaps=gaps,
        mutations=mutations,
        static_findings=static_findings,
        security_findings=sec_findings,
        baseline=baseline,
        sentinel_signals=sentinel_signals,
    )


def _score_dimension(
    name: str,
    raw_score: float,
    weight: float,
    details: str,
    evaluated: bool,
    thresholds: tuple[float, float, float, float] | None = None,
) -> DimensionScore:
    if not evaluated:
        return DimensionScore(
            name=name,
            raw_score=raw_score,
            weight=weight,
            weighted_score=0.0,
            grade=Grade.from_score(raw_score, thresholds),
            details="Not evaluated",
            evaluated=False,
        )
    return DimensionScore(
        name=name,
        raw_score=round(raw_score, 1),
        weight=weight,
        weighted_score=round(raw_score * weight, 1),
        grade=Grade.from_score(raw_score, thresholds),
        details=details,
        evaluated=True,
    )


def _identify_gaps(dimensions: list[DimensionScore]) -> list[str]:
    """Identify dimensions that need attention (grade C or below)."""
    gaps: list[str] = []
    for d in dimensions:
        if not d.evaluated:
            continue
        if d.grade in (Grade.C, Grade.D, Grade.F):
            gaps.append(f"{d.name}: {d.grade.value} ({d.raw_score}%) — {d.details}")
    return gaps


# ── Detail Formatters ─────────────────────────────────────────

def _mutation_details(
    mutations: list[MutationResult], *, tool_available: bool = True
) -> str:
    if not mutations:
        if tool_available:
            return "No mutable code in changed files"
        return "mutmut not available"
    total = len(mutations)
    killed = sum(1 for m in mutations if m.status == MutantStatus.KILLED)
    survived = total - killed
    return f"{killed}/{total} killed, {survived} survived"


def _static_details(
    findings: list[StaticFinding],
    *,
    tool_config: dict[str, bool] | None = None,
) -> str:
    if not findings:
        return "No issues found"
    by_analyzer: dict[str, int] = {}
    for f in findings:
        by_analyzer[f.analyzer.value] = by_analyzer.get(f.analyzer.value, 0) + 1
    parts: list[str] = []
    for k, v in sorted(by_analyzer.items()):
        label = f"{v} {k}"
        if tool_config is not None and not tool_config.get(k, True):
            label += " (not configured)"
        parts.append(label)
    return ", ".join(parts)


def _baseline_details(baseline: BaselineResult | None) -> str:
    if not baseline:
        return "Baseline not run"
    flaky = len(baseline.flaky_tests)
    if flaky == 0:
        return f"All stable across {baseline.run_count} runs"
    return f"{flaky} flaky test(s) detected across {baseline.run_count} runs"


def _sentinel_details(signals: SentinelSignals) -> str:
    if not signals.available:
        return "Sentinel data not available"
    parts: list[str] = []
    if signals.pitfall_matches:
        parts.append(f"{len(signals.pitfall_matches)} pitfall match(es)")
    if signals.hot_files:
        parts.append(f"{len(signals.hot_files)} hot file(s)")
    if not parts:
        return "No risk signals"
    return ", ".join(parts)


def _security_details(findings: list[SecurityFinding]) -> str:
    if not findings:
        return "No security issues found"
    by_analyzer: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    for f in findings:
        by_analyzer[f.analyzer.value] = by_analyzer.get(f.analyzer.value, 0) + 1
        if f.cwe_id:
            cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1
    parts: list[str] = []
    for k, v in sorted(by_analyzer.items()):
        parts.append(f"{v} {k}")
    detail = ", ".join(parts)
    if cwe_counts:
        top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        cwe_str = ", ".join(f"{c}({n})" for c, n in top_cwes)
        detail += f" | top CWEs: {cwe_str}"
    return detail


def _cochange_details(signals: SentinelSignals) -> str:
    if not signals.available:
        return "Sentinel data not available"
    missing = signals.missing_co_changes
    if not missing:
        return "All co-change partners included"
    files = [m.partner_file for m in missing[:3]]
    suffix = f" (+{len(missing) - 3} more)" if len(missing) > 3 else ""
    return f"Missing: {', '.join(files)}{suffix}"
