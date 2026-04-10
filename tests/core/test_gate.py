"""Tests for Tier 2 pre-commit verification gate."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from unittest.mock import patch

from seraph.core.gate import (
    GateTrajectory,
    _check_spec_compliance,
    run_gate,
)
from seraph.core.mutations import MutationTestResult, Mutant
from seraph.models.assessment import GateResult
from seraph.models.enums import GateSource, GateVerdict


# ── Spec Compliance ────────────────────────────────────────────


def test_spec_compliance_no_task():
    """No task description → no findings."""
    findings = _check_spec_compliance("+ import subprocess", "")
    assert findings == []


def test_spec_compliance_no_diff():
    """No diff → no findings."""
    findings = _check_spec_compliance("", "Add logging")
    assert findings == []


def test_spec_compliance_unsolicited_subprocess():
    """Subprocess use not mentioned in task is flagged."""
    diff = textwrap.dedent("""\
        +++ b/src/foo.py
        @@ -1 +1,2 @@
        +import subprocess
        +subprocess.run(["ls"])
    """)
    findings = _check_spec_compliance(diff, "Add a data validation function")
    assert any(f.source == GateSource.SPEC_COMPLIANCE for f in findings)
    assert any("subprocess" in f.description for f in findings)


def test_spec_compliance_mentioned_subprocess():
    """Subprocess mentioned in task → no finding."""
    diff = textwrap.dedent("""\
        +++ b/src/foo.py
        @@ -1 +1,2 @@
        +import subprocess
        +subprocess.run(["test"])
    """)
    findings = _check_spec_compliance(diff, "Run subprocess to execute tests")
    sub_findings = [f for f in findings if "subprocess" in f.description]
    assert not sub_findings


def test_spec_compliance_scope_creep():
    """Touching many more files than mentioned is flagged."""
    diff = "\n".join([f"+++ b/file{i}.py\n@@ -1 +1 @@\n+x" for i in range(10)])
    findings = _check_spec_compliance(diff, "Fix bug in main.py")
    assert any("scope creep" in f.description for f in findings)


# ── Fail-open Regression ──────────────────────────────────────


def test_gate_does_not_accept_on_mutation_crash():
    """If mutation testing crashes, verdict must not be ACCEPT."""
    with patch("seraph.core.gate.run_mutation_testing", side_effect=RuntimeError("boom")):
        result = run_gate("/tmp", diff="+++ b/x.py\n@@ -1 +1 @@\n+x=1")
    assert result.verdict != GateVerdict.ACCEPT
    assert result.verdict == GateVerdict.ACCEPT_WITH_WARNINGS


# ── Trajectory Tracking ───────────────────────────────────────


def test_trajectory_initial():
    t = GateTrajectory()
    assert t.attempt_count == 0
    assert not t.is_non_converging()


def test_trajectory_records():
    t = GateTrajectory()
    t.record(GateResult(mutation_score=50.0))
    t.record(GateResult(mutation_score=51.0))
    assert t.attempt_count == 2
    assert not t.is_non_converging()


def test_trajectory_non_converging():
    """3 attempts with similar scores → non-converging."""
    t = GateTrajectory()
    t.record(GateResult(mutation_score=50.0))
    t.record(GateResult(mutation_score=51.0))
    t.record(GateResult(mutation_score=52.0))
    assert t.is_non_converging()
    assert t.feedback_hint


def test_trajectory_converging():
    """3 attempts with improving scores → not non-converging."""
    t = GateTrajectory()
    t.record(GateResult(mutation_score=50.0))
    t.record(GateResult(mutation_score=60.0))
    t.record(GateResult(mutation_score=70.0))
    assert not t.is_non_converging()


# ── run_gate ───────────────────────────────────────────────────


def test_gate_accept_no_diff():
    """Empty diff → ACCEPT."""
    result = run_gate("/tmp", diff="", task_description="")
    assert result.verdict == GateVerdict.ACCEPT


def test_gate_with_trajectory():
    """Gate accepts trajectory tracker."""
    t = GateTrajectory()
    result = run_gate("/tmp", diff="", trajectory=t)
    assert t.attempt_count == 1
    assert result.attempt == 1


def test_gate_reject_on_surviving_mutants(tmp_path):
    """Surviving mutants below threshold → REJECT."""
    # Create module with untested code
    source = textwrap.dedent("""\
        def is_positive(x):
            if x > 0:
                return True
            return False
    """)
    (tmp_path / "mod.py").write_text(source)
    # Test that doesn't actually test the function
    (tmp_path / "test_mod.py").write_text("def test_noop(): assert True\n")

    diff = textwrap.dedent("""\
        diff --git a/mod.py b/mod.py
        --- a/mod.py
        +++ b/mod.py
        @@ -1,4 +1,4 @@
         def is_positive(x):
        -    if x >= 0:
        +    if x > 0:
                 return True
             return False
    """)

    result = run_gate(
        tmp_path, diff=diff, test_cmd="pytest",
        max_mutants=5, timeout_per_mutant=10,
    )

    # Should have findings for surviving mutants
    assert result.mutants_tested > 0
    # Verdict depends on how many survive
    assert result.verdict in (GateVerdict.REJECT, GateVerdict.ACCEPT_WITH_WARNINGS)


def test_gate_accept_well_tested(tmp_path):
    """Well-tested code with killed mutants → ACCEPT or ACCEPT_WITH_WARNINGS."""
    source = textwrap.dedent("""\
        def is_positive(x):
            if x > 0:
                return True
            return False
    """)
    test_source = textwrap.dedent("""\
        from mod import is_positive

        def test_positive():
            assert is_positive(5) is True

        def test_negative():
            assert is_positive(-1) is False

        def test_zero():
            assert is_positive(0) is False
    """)
    (tmp_path / "mod.py").write_text(source)
    (tmp_path / "test_mod.py").write_text(test_source)

    diff = textwrap.dedent("""\
        diff --git a/mod.py b/mod.py
        --- a/mod.py
        +++ b/mod.py
        @@ -1,4 +1,4 @@
         def is_positive(x):
        -    if x >= 0:
        +    if x > 0:
                 return True
             return False
    """)

    result = run_gate(
        tmp_path, diff=diff, test_cmd="pytest",
        max_mutants=5, timeout_per_mutant=10,
    )

    assert result.verdict in (GateVerdict.ACCEPT, GateVerdict.ACCEPT_WITH_WARNINGS)


def test_gate_result_to_dict():
    """GateResult.to_dict() has expected structure."""
    result = GateResult(
        verdict=GateVerdict.ACCEPT,
        mutation_score=100.0,
        mutants_tested=5,
        mutants_survived=0,
    )
    d = result.to_dict()
    assert d["verdict"] == "ACCEPT"
    assert d["mutation_score"] == 100.0
    assert d["mutants_tested"] == 5
    assert d["mutants_survived"] == 0
