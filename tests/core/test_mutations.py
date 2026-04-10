"""Tests for targeted AST-based mutation testing."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from seraph.core.mutations import (
    Mutant,
    MutationTestResult,
    generate_mutants,
    parse_changed_lines,
    run_mutation_testing,
    run_mutant_test,
)


# ── parse_changed_lines ───────────────────────────────────────


def test_parse_changed_lines_single_file():
    diff = textwrap.dedent("""\
        diff --git a/src/foo.py b/src/foo.py
        --- a/src/foo.py
        +++ b/src/foo.py
        @@ -10,3 +10,4 @@
         unchanged
        +added line 11
        +added line 12
         unchanged
    """)
    result = parse_changed_lines(diff)
    assert "src/foo.py" in result
    assert 11 in result["src/foo.py"]
    assert 12 in result["src/foo.py"]


def test_parse_changed_lines_multiple_files():
    diff = textwrap.dedent("""\
        diff --git a/a.py b/a.py
        --- a/a.py
        +++ b/a.py
        @@ -1,1 +1,2 @@
         old
        +new in a
        diff --git a/b.py b/b.py
        --- a/b.py
        +++ b/b.py
        @@ -5,1 +5,2 @@
         old
        +new in b
    """)
    result = parse_changed_lines(diff)
    assert "a.py" in result
    assert "b.py" in result


def test_parse_changed_lines_empty_diff():
    assert parse_changed_lines("") == {}


# ── generate_mutants ──────────────────────────────────────────


def test_generate_comparison_mutants():
    """Comparison operators produce mutants."""
    source = textwrap.dedent("""\
        def check(x):
            if x > 10:
                return True
            return False
    """)
    mutants = generate_mutants(source, "test.py", {2})
    assert len(mutants) > 0
    assert any("Gt" in m.operator for m in mutants)


def test_generate_boolop_mutants():
    """Boolean operators (and/or) produce mutants."""
    source = textwrap.dedent("""\
        def check(a, b):
            if a and b:
                return True
    """)
    mutants = generate_mutants(source, "test.py", {2})
    assert any("bool" in m.operator for m in mutants)


def test_generate_return_bool_mutants():
    """Return True/False produces mutants."""
    source = textwrap.dedent("""\
        def check():
            return True
    """)
    mutants = generate_mutants(source, "test.py", {2})
    assert any("return" in m.operator for m in mutants)


def test_generate_binop_mutants():
    """Arithmetic operators produce mutants."""
    source = textwrap.dedent("""\
        def calc(x):
            return x + 1
    """)
    mutants = generate_mutants(source, "test.py", {2})
    assert any("arith" in m.operator for m in mutants)


def test_no_mutants_for_unchanged_lines():
    """Only changed lines get mutated."""
    source = textwrap.dedent("""\
        def check(x):
            if x > 10:
                return True
            return False
    """)
    mutants = generate_mutants(source, "test.py", {4})  # only line 4 changed
    # Line 2 has the comparison, but it's not in changed_lines
    cmp_mutants = [m for m in mutants if "Gt" in m.operator]
    assert not cmp_mutants


def test_max_mutants_respected():
    """max_mutants limits the output."""
    source = textwrap.dedent("""\
        def check(x):
            if x > 10 and x < 20:
                if x > 12 and x < 18:
                    return True
            return False
    """)
    mutants = generate_mutants(source, "test.py", {2, 3, 4, 5}, max_mutants=2)
    assert len(mutants) <= 2


def test_syntax_error_returns_empty():
    """Unparseable source returns no mutants."""
    source = "def broken(\n"
    mutants = generate_mutants(source, "test.py", {1})
    assert mutants == []


def test_mutant_has_mutated_source():
    """Each mutant includes the full mutated source."""
    source = textwrap.dedent("""\
        def check(x):
            if x > 10:
                return True
            return False
    """)
    mutants = generate_mutants(source, "test.py", {2})
    for m in mutants:
        assert m.mutated_source
        assert m.mutated_source != source


# ── test_mutant ────────────────────────────────────────────────


def test_run_mutant_test_killed(tmp_path):
    """Mutant is killed when tests fail."""
    # Create a simple module and test
    (tmp_path / "mod.py").write_text("def add(a, b): return a + b\n")
    (tmp_path / "test_mod.py").write_text(
        "from mod import add\ndef test_add(): assert add(1, 2) == 3\n"
    )
    original = "def add(a, b): return a + b\n"
    mutated = "def add(a, b): return a - b\n"  # + → -

    result = run_mutant_test(tmp_path, "mod.py", original, mutated, "pytest", timeout=10)
    assert result == "killed"

    # Verify original is restored
    assert (tmp_path / "mod.py").read_text() == original


def test_run_mutant_test_survived(tmp_path):
    """Mutant survives when tests still pass."""
    (tmp_path / "mod.py").write_text("def greet(): return 'hello'\n")
    (tmp_path / "test_mod.py").write_text(
        "def test_always_pass(): assert True\n"
    )
    original = "def greet(): return 'hello'\n"
    mutated = "def greet(): return 'goodbye'\n"

    result = run_mutant_test(tmp_path, "mod.py", original, mutated, "pytest", timeout=10)
    assert result == "survived"


def test_run_mutant_test_missing_file(tmp_path):
    """Missing file returns error."""
    result = run_mutant_test(tmp_path, "nonexistent.py", "a", "b", "pytest")
    assert result == "error"


# ── run_mutation_testing ───────────────────────────────────────


def test_run_mutation_testing_full(tmp_path):
    """Full mutation testing run with a simple module."""
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

    result = run_mutation_testing(
        tmp_path, diff, test_cmd="pytest", max_mutants=5, timeout_per_mutant=10,
    )

    assert isinstance(result, MutationTestResult)
    assert result.mutants  # should have generated at least one mutant
    assert 0 <= result.score <= 100


def test_run_mutation_testing_no_python_files():
    """Non-Python diffs produce empty results."""
    diff = "+++ b/README.md\n@@ -1 +1,2 @@\n+new line\n"
    result = run_mutation_testing(Path("/tmp"), diff)
    assert result.mutants == []
    assert result.score == 100.0
