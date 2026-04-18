"""LLM-friendly output formatting with 4K token cap."""

from __future__ import annotations

# Approximate 4K tokens ≈ 16K chars
MAX_OUTPUT_CHARS = 16_000


def format_assessment(report_dict: dict, *, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Format an assessment report for LLM consumption."""
    # Early return for vacuous assessments — no grade card, hard error
    if report_dict.get("is_vacuous", False):
        return (
            "## Seraph Assessment: VACUOUS\n\n"
            "**0 dimensions evaluated. No files in diff.**\n\n"
            "Seraph cannot grade this change. "
            "Treat as SERAPH_UNAVAILABLE.\n\n"
            "Common causes:\n"
            "- No changes between ref_before and ref_after\n"
            "- Wrong repo_root (CWD doesn't match git root)\n"
            "- Changes not staged (`git add` before assess)\n\n"
            f"ID: {report_dict.get('id', '?')}"
        )

    lines: list[str] = []

    lines.append(f"## Seraph Assessment: {report_dict.get('overall_grade', '?')}")
    lines.append(f"Score: {report_dict.get('overall_score', 0)}/100")
    lines.append(f"Files: {len(report_dict.get('files_changed', []))}")

    dim_count = report_dict.get("dimension_count", 6)
    evaluated = report_dict.get("evaluated_count", dim_count)
    if evaluated < dim_count:
        lines.append(f"Evaluated: {evaluated}/{dim_count} dimensions")
    lines.append("")

    # Dimensions
    lines.append("### Dimensions")
    for dim in report_dict.get("dimensions", []):
        if dim.get("evaluated", True):
            lines.append(
                f"- **{dim.get('name', '?')}**: {dim.get('grade', '?')} "
                f"({dim.get('raw_score', '?')}%) — {dim.get('details', '')}"
            )
        else:
            lines.append(f"- **{dim.get('name', '?')}**: N/A (not evaluated)")
    lines.append("")

    # Gaps
    gaps = report_dict.get("gaps", [])
    if gaps:
        lines.append("### Gaps (Need Attention)")
        for gap in gaps:
            lines.append(f"- {gap}")
        lines.append("")

    # Files
    files = report_dict.get("files_changed", [])
    if files:
        lines.append("### Changed Files")
        for f in files[:20]:
            lines.append(f"- {f}")
        if len(files) > 20:
            lines.append(f"- ... and {len(files) - 20} more")
        lines.append("")

    lines.append(f"ID: {report_dict.get('id', '?')}")
    lines.append(f"Created: {report_dict.get('created_at', '?')}")

    return _truncate("\n".join(lines), max_chars=max_chars)


def format_history(
    assessments: list, *, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    """Format assessment history for LLM consumption.

    Accepts list of StoredAssessment dataclasses.
    """
    if not assessments:
        return "No assessments found."

    lines: list[str] = []
    lines.append(f"## Assessment History ({len(assessments)} results)")
    lines.append("")

    for a in assessments:
        file_count = len(a.files_changed) if a.files_changed else 0
        mutation_display = f"{a.mutation_score}%" if a.mutation_score is not None else "?%"
        static_display = f"{a.static_issues} issues" if a.static_issues is not None else "? issues"
        lines.append(
            f"- **{a.grade or '?'}** | "
            f"mutation={mutation_display} | "
            f"static={static_display} | "
            f"{file_count} files | "
            f"{a.created_at or '?'} | "
            f"id={a.id[:8] if a.id else '?'}"
        )

    return _truncate("\n".join(lines), max_chars=max_chars)


def format_mutations(
    mutations: list, score: float, *, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    """Format mutation results for LLM consumption.

    Accepts list of MutationResult dataclasses.
    """
    if not mutations:
        return "No mutation results. Score: 100%"

    lines: list[str] = []
    lines.append(f"## Mutation Testing Results")
    lines.append(f"Score: {score}%")
    lines.append(f"Total mutants: {len(mutations)}")
    lines.append("")

    # Group by status
    by_status: dict[str, list] = {}
    for m in mutations:
        status = m.status.value
        by_status.setdefault(status, []).append(m)

    for status, muts in sorted(by_status.items()):
        lines.append(f"### {status.title()} ({len(muts)})")
        for m in muts[:10]:
            lines.append(f"- {m.file_path}:{m.line_number or '?'} [{m.operator}]")
        if len(muts) > 10:
            lines.append(f"- ... and {len(muts) - 10} more")
        lines.append("")

    return _truncate("\n".join(lines), max_chars=max_chars)


def format_gate_result(
    result, *, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    """Format a Tier 2 gate result for LLM consumption.

    Accepts a GateResult dataclass.
    """
    lines: list[str] = []

    lines.append(f"## Seraph Gate: {result.verdict.value}")
    # When no mutants were generated, the score is vacuous — 100% of zero.
    # Report N/A instead of lying about a perfect score on a non-mutable diff.
    if result.mutants_tested == 0:
        lines.append("Mutation score: N/A — no mutable code in staged diff")
        lines.append("Mutants: 0 tested")
    else:
        lines.append(f"Mutation score: {result.mutation_score:.1f}%")
        lines.append(
            f"Mutants: {result.mutants_tested} tested, "
            f"{result.mutants_survived} survived"
        )
    if result.attempt > 1:
        lines.append(f"Attempt: {result.attempt}")
    lines.append("")

    if not result.findings:
        lines.append("No findings — all mutants killed, spec compliant.")
        return _truncate("\n".join(lines), max_chars=max_chars)

    # Group findings by source
    by_source: dict[str, list] = {}
    for f in result.findings:
        by_source.setdefault(f.source.value, []).append(f)

    for source, findings in sorted(by_source.items()):
        lines.append(f"### {source.replace('_', ' ').title()} ({len(findings)})")
        for f in findings:
            loc = f"| `{f.file}:{f.line}` " if f.file else ""
            lines.append(f"- {loc}confidence={f.confidence:.0%}")
            lines.append(f"  {f.description}")
            if f.suggestion:
                lines.append(f"  → {f.suggestion}")
            if f.mutant_code:
                lines.append(f"  Mutated: `{f.mutant_code}`")
            lines.append("")

    return _truncate("\n".join(lines), max_chars=max_chars)


def format_check_result(
    result, *, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    """Format a Tier 1 check result for LLM consumption.

    Accepts a CheckResult dataclass.
    """
    lines: list[str] = []

    if not result.findings:
        lines.append(f"## Seraph Check: {result.verdict.value}")
        lines.append("")
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append(f"## Seraph Check: {result.verdict.value}")
    lines.append(f"Findings: {len(result.findings)}")
    lines.append("")

    for f in result.findings:
        lines.append(
            f"- **{f.check.value}** | `{f.file}:{f.line}` | "
            f"confidence={f.confidence:.0%}"
        )
        lines.append(f"  {f.description}")
        if f.suggestion:
            lines.append(f"  → {f.suggestion}")
        lines.append("")

    return _truncate("\n".join(lines), max_chars=max_chars)


# ── Explain ────────────────────────────────────────────────────

_CHECK_EXPLANATIONS: dict[str, str] = {
    "import_validation": (
        "**Import Validation** checks whether imported modules exist and are "
        "importable. A failing import means the code will crash at runtime with "
        "a ModuleNotFoundError. Common causes: typo in module name, missing "
        "dependency in requirements, or referencing a package not installed in "
        "the current environment."
    ),
    "security_surface": (
        "**Security Surface** detects dangerous function calls that could lead "
        "to code injection, command injection, or credential leaks. These "
        "patterns (eval, exec, subprocess shell=True, pickle, hardcoded secrets) "
        "are commonly exploited attack vectors."
    ),
    "escalation": (
        "**Escalation Detection** flags code that accesses privileged resources: "
        "/proc filesystem, credential files, file permission changes, privilege "
        "escalation (setuid/setgid), native library loading, or unexpected "
        "network connections. These may indicate sandbox escape attempts."
    ),
    "spec_drift": (
        "**Spec Drift** detects capabilities in the code that weren't mentioned "
        "in the task description. This catches unsolicited additions — code that "
        "does more than what was asked for. This is a safety feature: the most "
        "capable models can also be the most creative in acquiring capabilities."
    ),
    "mutation": (
        "**Mutation Testing** generates modified versions of your code (mutants) "
        "and checks if your tests catch the changes. A surviving mutant means "
        "your tests pass even when the code is wrong — indicating a gap in test "
        "coverage. The mutation-as-question format asks: 'Is it intentional that "
        "tests pass when X is changed to Y?'"
    ),
    "spec_compliance": (
        "**Spec Compliance** compares the code change against the task description "
        "to detect misinterpretation (addressing a different problem) or "
        "unsolicited additions (doing more than asked). This is the #1 LLM "
        "mistake category at 20.77%."
    ),
}


def format_explain(
    check_category: str,
    description: str,
    file_path: str = "",
    line: int = 0,
    confidence: float = 0.0,
) -> str:
    """Format a detailed explanation of a finding."""
    lines: list[str] = []

    lines.append(f"## Finding Explanation: {check_category}")
    if file_path:
        lines.append(f"Location: `{file_path}:{line}`")
    lines.append(f"Confidence: {confidence:.0%}")
    lines.append("")

    lines.append(f"**What was detected:** {description}")
    lines.append("")

    explanation = _CHECK_EXPLANATIONS.get(
        check_category,
        "No detailed explanation available for this check category.",
    )
    lines.append(f"**Why it matters:**\n{explanation}")
    lines.append("")

    # Confidence interpretation
    if confidence >= 0.90:
        conf_text = "Very high confidence — this is almost certainly a real issue."
    elif confidence >= 0.75:
        conf_text = "High confidence — likely a real issue, but verify the context."
    elif confidence >= 0.60:
        conf_text = "Moderate confidence — may be a false positive. Check the context."
    else:
        conf_text = "Low confidence — this is heuristic and may be a false positive."

    lines.append(f"**Confidence meaning:** {conf_text}")
    lines.append("")
    lines.append(
        "If this is a false positive, report it with `seraph_calibrate` to "
        "improve future accuracy."
    )

    return "\n".join(lines)


def format_calibrate_response(
    check_category: str,
    is_false_positive: bool,
) -> str:
    """Format calibration confirmation."""
    report_type = "false positive" if is_false_positive else "false negative"
    return (
        f"Calibration recorded: {report_type} for '{check_category}'. "
        f"This will be used to tune confidence thresholds over time."
    )


def format_status(
    calibration_stats: dict[str, dict[str, int]],
    table_stats: dict[str, int],
) -> str:
    """Format system status with calibration and table stats."""
    lines: list[str] = []

    lines.append("## Seraph Status")
    lines.append("")

    # Table stats
    lines.append("### Storage")
    for table, count in sorted(table_stats.items()):
        lines.append(f"- {table}: {count} rows")
    lines.append("")

    # Calibration stats
    if calibration_stats:
        lines.append("### Calibration (FP/FN Reports)")
        total_fp = sum(v["fp"] for v in calibration_stats.values())
        total_fn = sum(v["fn"] for v in calibration_stats.values())
        lines.append(f"Total: {total_fp} false positives, {total_fn} false negatives")
        lines.append("")
        for cat, counts in sorted(calibration_stats.items()):
            lines.append(f"- **{cat}**: {counts['fp']} FP, {counts['fn']} FN")
    else:
        lines.append("### Calibration")
        lines.append("No calibration data yet.")

    return "\n".join(lines)


def format_feedback_response(assessment_id: str, outcome: str) -> str:
    """Format feedback confirmation."""
    return f"Feedback recorded: {outcome} for assessment {assessment_id[:8]}"


def _truncate(text: str, *, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Truncate to stay within token budget."""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 50] + "\n\n... (output truncated)"
