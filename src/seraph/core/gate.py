"""Tier 2 pre-commit verification gate — <30s budget.

Orchestrates mutation testing + spec compliance checks on staged
changes. Returns structured verdict with findings.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from seraph.core.mutations import (
    MutationTestResult,
    run_mutation_testing,
)
from seraph.models.assessment import GateFinding, GateResult
from seraph.models.enums import GateSource, GateVerdict

logger = logging.getLogger(__name__)

# ── Default thresholds ─────────────────────────────────────────

# Mutation score below this → REJECT
MUTATION_REJECT_THRESHOLD = 60.0

# Mutation score below this but above reject → ACCEPT_WITH_WARNINGS
MUTATION_WARN_THRESHOLD = 80.0

# Maximum spec compliance findings before REJECT
SPEC_REJECT_THRESHOLD = 3

# Maximum total findings before REJECT
TOTAL_REJECT_THRESHOLD = 5


# ── Spec Compliance ────────────────────────────────────────────


def _check_spec_compliance(
    diff: str,
    task_description: str,
) -> list[GateFinding]:
    """Compare diff against task description for misinterpretation and unsolicited additions.

    Two categories:
    1. Misinterpretation: diff addresses a different problem than described
    2. Unsolicited additions: diff does MORE than the task asked for
    """
    if not task_description or not diff:
        return []

    findings: list[GateFinding] = []
    task_lower = task_description.lower()

    # Extract added files from diff
    added_files: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            added_files.append(line[6:])

    # Extract added code lines
    added_code: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_code.append(line[1:])

    added_text = "\n".join(added_code).lower()

    # Detect unsolicited network capabilities
    _UNSOLICITED_CAPS: list[tuple[str, str, str]] = [
        (
            r"\bsubprocess\b",
            "subprocess execution",
            "Code adds subprocess execution not mentioned in task",
        ),
        (
            r"\brequests\.(?:get|post|put|delete|patch)\b",
            "HTTP requests",
            "Code makes HTTP requests not mentioned in task",
        ),
        (
            r"\bsmtplib\b",
            "email",
            "Code adds email capability not mentioned in task",
        ),
        (
            r"\bos\.(?:remove|unlink)\b|\bshutil\.rmtree\b",
            "file deletion",
            "Code performs file deletion not mentioned in task",
        ),
    ]

    for pattern_str, cap_name, description in _UNSOLICITED_CAPS:
        pattern = re.compile(pattern_str)
        # Check both full name and first word (e.g., "subprocess execution" and "subprocess")
        cap_keyword = cap_name.split()[0]
        if pattern.search(added_text) and cap_name not in task_lower and cap_keyword not in task_lower:
            findings.append(GateFinding(
                source=GateSource.SPEC_COMPLIANCE,
                description=description,
                suggestion=f"Verify that {cap_name} is required for this task",
                confidence=0.65,
            ))

    # Detect large scope creep: if the task mentions specific files but
    # the diff touches many more
    mentioned_files = re.findall(r'[\w/]+\.\w+', task_description)
    if mentioned_files and len(added_files) > len(mentioned_files) * 3:
        findings.append(GateFinding(
            source=GateSource.SPEC_COMPLIANCE,
            description=(
                f"Task mentions {len(mentioned_files)} file(s) but diff touches "
                f"{len(added_files)} — possible scope creep"
            ),
            suggestion="Verify all changed files are necessary for this task",
            confidence=0.55,
        ))

    return findings


# ── Trajectory Tracking ────────────────────────────────────────


class GateTrajectory:
    """Track successive gate attempts for convergence detection.

    If 3+ non-converging rejections occur, the gate should change
    its feedback strategy.
    """

    def __init__(self) -> None:
        self._attempts: list[GateResult] = []

    @property
    def attempt_count(self) -> int:
        return len(self._attempts)

    def record(self, result: GateResult) -> None:
        self._attempts.append(result)

    def is_non_converging(self) -> bool:
        """True if last 3 attempts show no improvement in mutation score."""
        if len(self._attempts) < 3:
            return False
        recent = self._attempts[-3:]
        scores = [r.mutation_score for r in recent]
        # Non-converging: scores haven't improved by more than 5%
        return max(scores) - min(scores) < 5.0

    @property
    def feedback_hint(self) -> str:
        """Suggest a different approach if non-converging."""
        if self.is_non_converging():
            return (
                "3 non-converging attempts detected. Try a different approach: "
                "add targeted tests for surviving mutants rather than modifying "
                "the implementation."
            )
        return ""


# ── Gate Orchestrator ──────────────────────────────────────────


def run_gate(
    repo_path: str | Path,
    diff: str,
    task_description: str = "",
    test_cmd: str = "pytest",
    max_mutants: int = 10,
    timeout_per_mutant: int = 10,
    trajectory: GateTrajectory | None = None,
    mutation_reject_threshold: float = MUTATION_REJECT_THRESHOLD,
    mutation_warn_threshold: float = MUTATION_WARN_THRESHOLD,
) -> GateResult:
    """Run the Tier 2 pre-commit verification gate.

    Steps:
    1. Mutation testing on changed lines
    2. Spec compliance check
    3. Verdict determination

    Args:
        repo_path: Path to the repository root.
        diff: Unified diff of staged changes.
        task_description: Optional task/plan description for spec compliance.
        test_cmd: Test command (default: pytest).
        max_mutants: Maximum mutants to generate.
        timeout_per_mutant: Timeout per mutant test run.
        trajectory: Optional trajectory tracker for convergence detection.
        mutation_reject_threshold: Mutation score below this → REJECT.
        mutation_warn_threshold: Mutation score below this → ACCEPT_WITH_WARNINGS.

    Returns:
        GateResult with verdict and findings.
    """
    repo = Path(repo_path).resolve()
    all_findings: list[GateFinding] = []
    attempt = (trajectory.attempt_count + 1) if trajectory else 1

    # Step 1: Mutation testing
    mutation_result = MutationTestResult()
    try:
        mutation_result = run_mutation_testing(
            repo, diff, test_cmd, max_mutants, timeout_per_mutant,
        )
        # Convert surviving mutants to findings
        for mutant in mutation_result.survived:
            all_findings.append(GateFinding(
                source=GateSource.MUTATION,
                file=mutant.file_path,
                line=mutant.line,
                description=(
                    f"Tests still pass when {mutant.description.lower()}. "
                    f"Is that intentional?"
                ),
                suggestion=(
                    f"Add a test that fails when line {mutant.line} is changed "
                    f"from `{mutant.original}` to `{mutant.mutated}`"
                ),
                confidence=0.85,
                mutant_code=mutant.mutated,
            ))
    except Exception:
        logger.exception("Step 1 (Mutation Testing) failed")

    # Step 2: Spec compliance
    try:
        spec_findings = _check_spec_compliance(diff, task_description)
        all_findings.extend(spec_findings)
    except Exception:
        logger.exception("Step 2 (Spec Compliance) failed")

    # Step 3: Determine verdict
    verdict = _determine_verdict(
        mutation_result, all_findings,
        mutation_reject_threshold, mutation_warn_threshold,
    )

    result = GateResult(
        verdict=verdict,
        findings=all_findings,
        mutation_score=mutation_result.score,
        mutants_tested=len(mutation_result.killed) + len(mutation_result.survived),
        mutants_survived=len(mutation_result.survived),
        attempt=attempt,
    )

    # Record trajectory
    if trajectory:
        trajectory.record(result)
        hint = trajectory.feedback_hint
        if hint:
            logger.warning(hint)
            # Add trajectory hint as a finding
            all_findings.append(GateFinding(
                source=GateSource.SPEC_COMPLIANCE,
                description=hint,
                suggestion="Consider adding tests instead of changing code",
                confidence=0.50,
            ))

    return result


def _determine_verdict(
    mutation_result: MutationTestResult,
    findings: list[GateFinding],
    reject_threshold: float,
    warn_threshold: float,
) -> GateVerdict:
    """Determine gate verdict based on mutation score and findings."""
    spec_findings = [f for f in findings if f.source == GateSource.SPEC_COMPLIANCE]

    tested = len(mutation_result.killed) + len(mutation_result.survived)

    # No mutants generated = no test coverage signal → ACCEPT
    if tested == 0 and not spec_findings:
        return GateVerdict.ACCEPT

    # REJECT conditions
    if mutation_result.score < reject_threshold:
        return GateVerdict.REJECT

    if len(spec_findings) >= SPEC_REJECT_THRESHOLD:
        return GateVerdict.REJECT

    if len(findings) >= TOTAL_REJECT_THRESHOLD:
        return GateVerdict.REJECT

    # ACCEPT_WITH_WARNINGS
    if mutation_result.score < warn_threshold or findings:
        return GateVerdict.ACCEPT_WITH_WARNINGS

    # Clean pass
    return GateVerdict.ACCEPT
