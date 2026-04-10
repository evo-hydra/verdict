"""Targeted AST-based mutation testing for changed lines only.

Generates behaviorally realistic mutants scoped to the diff, then
runs the test suite to detect surviving mutations. Designed for
<30s total budget (shared with other gate checks).
"""

from __future__ import annotations

import ast
import copy
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Mutation Operators ─────────────────────────────────────────

# Comparison operator swaps
_CMP_SWAPS: dict[type, list[type]] = {
    ast.Gt: [ast.GtE, ast.Lt],
    ast.GtE: [ast.Gt, ast.Lt],
    ast.Lt: [ast.LtE, ast.Gt],
    ast.LtE: [ast.Lt, ast.Gt],
    ast.Eq: [ast.NotEq],
    ast.NotEq: [ast.Eq],
}

# Boolean operator swaps
_BOOL_SWAPS: dict[type, type] = {
    ast.And: ast.Or,
    ast.Or: ast.And,
}

# Unary operator swaps
_UNARY_SWAPS: dict[type, type] = {
    ast.Not: ast.UAdd,  # not x → +x (identity)
    ast.UAdd: ast.USub,
    ast.USub: ast.UAdd,
}

# Binary operator swaps (arithmetic boundary mutations)
_BIN_SWAPS: dict[type, list[type]] = {
    ast.Add: [ast.Sub],
    ast.Sub: [ast.Add],
    ast.Mult: [ast.FloorDiv],
    ast.FloorDiv: [ast.Mult],
}


@dataclass
class Mutant:
    """A single mutation applied to the source code."""

    file_path: str
    line: int
    description: str
    original: str  # original line text
    mutated: str   # mutated line text
    operator: str  # mutation operator name
    mutated_source: str = ""  # full mutated file content


@dataclass
class MutationTestResult:
    """Result of testing all mutants against the test suite."""

    mutants: list[Mutant] = field(default_factory=list)
    killed: list[Mutant] = field(default_factory=list)
    survived: list[Mutant] = field(default_factory=list)
    errors: list[Mutant] = field(default_factory=list)
    score: float = 100.0  # % killed


# ── Mutant Generation ──────────────────────────────────────────


def generate_mutants(
    source: str,
    file_path: str,
    changed_lines: set[int],
    max_mutants: int = 10,
) -> list[Mutant]:
    """Generate AST-based mutants for changed lines only.

    Args:
        source: Full file source code.
        file_path: Relative file path.
        changed_lines: Set of line numbers that were modified in the diff.
        max_mutants: Maximum number of mutants to generate.

    Returns:
        List of Mutant objects with mutated source code.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.debug("Cannot parse %s for mutation — syntax error", file_path)
        return []

    mutants: list[Mutant] = []
    source_lines = source.splitlines(keepends=True)

    for node in ast.walk(tree):
        if len(mutants) >= max_mutants:
            break

        if not hasattr(node, "lineno") or node.lineno not in changed_lines:
            continue

        # Comparison mutations
        if isinstance(node, ast.Compare):
            mutants.extend(_mutate_compare(node, source_lines, file_path, source, tree))

        # Boolean mutations
        elif isinstance(node, ast.BoolOp):
            mutants.extend(_mutate_boolop(node, source_lines, file_path, source, tree))

        # Return True/False mutations
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, bool):
                mutants.extend(_mutate_return_bool(node, source_lines, file_path, source, tree))

        # Arithmetic boundary mutations
        elif isinstance(node, ast.BinOp) and type(node.op) in _BIN_SWAPS:
            mutants.extend(_mutate_binop(node, source_lines, file_path, source, tree))

        # Unary Not removal
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            mutants.extend(_mutate_unary_not(node, source_lines, file_path, source, tree))

        if len(mutants) >= max_mutants:
            break

    return mutants[:max_mutants]


def _apply_mutation(tree: ast.AST, source: str, node: ast.AST, mutator) -> str | None:
    """Apply a mutation to a copy of the AST and return the mutated source."""
    tree_copy = copy.deepcopy(tree)
    # Find the corresponding node in the copy by line/col
    for copied_node in ast.walk(tree_copy):
        if (
            type(copied_node) is type(node)
            and hasattr(copied_node, "lineno")
            and copied_node.lineno == node.lineno
            and getattr(copied_node, "col_offset", -1) == getattr(node, "col_offset", -2)
        ):
            mutator(copied_node)
            try:
                return ast.unparse(tree_copy)
            except Exception:
                return None
    return None


def _mutate_compare(
    node: ast.Compare, source_lines: list[str], file_path: str,
    source: str, tree: ast.AST,
) -> list[Mutant]:
    mutants = []
    for i, op in enumerate(node.ops):
        swaps = _CMP_SWAPS.get(type(op), [])
        for swap_type in swaps:
            def do_mutate(n, idx=i, st=swap_type):
                n.ops[idx] = st()

            mutated = _apply_mutation(tree, source, node, do_mutate)
            if mutated and mutated != source:
                original_line = source_lines[node.lineno - 1].rstrip() if node.lineno <= len(source_lines) else ""
                op_name = type(op).__name__
                swap_name = swap_type.__name__
                mutants.append(Mutant(
                    file_path=file_path,
                    line=node.lineno,
                    description=f"Changed {op_name} to {swap_name} on line {node.lineno}",
                    original=original_line,
                    mutated=_get_line(mutated, node.lineno),
                    operator=f"cmp_{op_name}_to_{swap_name}",
                    mutated_source=mutated,
                ))
    return mutants


def _mutate_boolop(
    node: ast.BoolOp, source_lines: list[str], file_path: str,
    source: str, tree: ast.AST,
) -> list[Mutant]:
    swap_type = _BOOL_SWAPS.get(type(node.op))
    if not swap_type:
        return []

    def do_mutate(n, st=swap_type):
        n.op = st()

    mutated = _apply_mutation(tree, source, node, do_mutate)
    if mutated and mutated != source:
        original_line = source_lines[node.lineno - 1].rstrip() if node.lineno <= len(source_lines) else ""
        return [Mutant(
            file_path=file_path,
            line=node.lineno,
            description=f"Changed {type(node.op).__name__} to {swap_type.__name__} on line {node.lineno}",
            original=original_line,
            mutated=_get_line(mutated, node.lineno),
            operator=f"bool_{type(node.op).__name__}_to_{swap_type.__name__}",
            mutated_source=mutated,
        )]
    return []


def _mutate_return_bool(
    node: ast.Return, source_lines: list[str], file_path: str,
    source: str, tree: ast.AST,
) -> list[Mutant]:
    original_val = node.value.value

    def do_mutate(n):
        n.value.value = not n.value.value

    mutated = _apply_mutation(tree, source, node, do_mutate)
    if mutated and mutated != source:
        original_line = source_lines[node.lineno - 1].rstrip() if node.lineno <= len(source_lines) else ""
        return [Mutant(
            file_path=file_path,
            line=node.lineno,
            description=f"Changed return {original_val} to return {not original_val} on line {node.lineno}",
            original=original_line,
            mutated=_get_line(mutated, node.lineno),
            operator=f"return_{original_val}_to_{not original_val}",
            mutated_source=mutated,
        )]
    return []


def _mutate_binop(
    node: ast.BinOp, source_lines: list[str], file_path: str,
    source: str, tree: ast.AST,
) -> list[Mutant]:
    mutants = []
    swaps = _BIN_SWAPS.get(type(node.op), [])
    for swap_type in swaps:
        def do_mutate(n, st=swap_type):
            n.op = st()

        mutated = _apply_mutation(tree, source, node, do_mutate)
        if mutated and mutated != source:
            original_line = source_lines[node.lineno - 1].rstrip() if node.lineno <= len(source_lines) else ""
            op_name = type(node.op).__name__
            swap_name = swap_type.__name__
            mutants.append(Mutant(
                file_path=file_path,
                line=node.lineno,
                description=f"Changed {op_name} to {swap_name} on line {node.lineno}",
                original=original_line,
                mutated=_get_line(mutated, node.lineno),
                operator=f"arith_{op_name}_to_{swap_name}",
                mutated_source=mutated,
            ))
    return mutants


def _mutate_unary_not(
    node: ast.UnaryOp, source_lines: list[str], file_path: str,
    source: str, tree: ast.AST,
) -> list[Mutant]:
    """Remove a `not` operator."""
    def do_mutate(n):
        # Replace UnaryOp(Not, x) with just x — need parent context
        # Simpler: change Not to UAdd (identity for booleans)
        n.op = ast.UAdd()

    mutated = _apply_mutation(tree, source, node, do_mutate)
    if mutated and mutated != source:
        original_line = source_lines[node.lineno - 1].rstrip() if node.lineno <= len(source_lines) else ""
        return [Mutant(
            file_path=file_path,
            line=node.lineno,
            description=f"Removed 'not' operator on line {node.lineno}",
            original=original_line,
            mutated=_get_line(mutated, node.lineno),
            operator="remove_not",
            mutated_source=mutated,
        )]
    return []


def _get_line(source: str, lineno: int) -> str:
    """Get a specific line from source code."""
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ""


# ── Diff Parsing ───────────────────────────────────────────────


def parse_changed_lines(diff: str) -> dict[str, set[int]]:
    """Extract changed line numbers per file from a unified diff.

    Returns:
        Dict mapping file paths to sets of changed (added) line numbers.
    """
    result: dict[str, set[int]] = {}
    current_file = ""
    line_num = 0

    for raw_line in diff.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            if current_file not in result:
                result[current_file] = set()
        elif raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)", raw_line)
            if match:
                line_num = int(match.group(1)) - 1
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_num += 1
            if current_file:
                result[current_file].add(line_num)
        elif not raw_line.startswith("-"):
            line_num += 1

    return result


# ── Test Runner ────────────────────────────────────────────────


def run_mutant_test(
    repo_path: Path,
    file_path: str,
    original_source: str,
    mutated_source: str,
    test_cmd: str = "pytest",
    timeout: int = 10,
) -> str:
    """Test a single mutant by temporarily writing it and running tests.

    Returns:
        "killed" if tests fail (mutant detected),
        "survived" if tests pass (mutant NOT detected),
        "error" if something went wrong.
    """
    target = repo_path / file_path
    if not target.exists():
        return "error"

    # Write mutant
    try:
        target.write_text(mutated_source, encoding="utf-8")
    except OSError:
        return "error"

    try:
        result = subprocess.run(
            test_cmd.split(),
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return "killed" if result.returncode != 0 else "survived"
    except subprocess.TimeoutExpired:
        return "killed"  # timeout = test hung = mutant likely detected
    except Exception:
        return "error"
    finally:
        # Restore original
        try:
            target.write_text(original_source, encoding="utf-8")
        except OSError:
            logger.error("Failed to restore %s after mutation — file may be corrupted", file_path)


def run_mutation_testing(
    repo_path: Path,
    diff: str,
    test_cmd: str = "pytest",
    max_mutants: int = 10,
    timeout_per_mutant: int = 10,
) -> MutationTestResult:
    """Generate and test mutants for changed lines in the diff.

    Args:
        repo_path: Path to the repository root.
        diff: Unified diff string.
        test_cmd: Test command to run.
        max_mutants: Maximum total mutants across all files.
        timeout_per_mutant: Timeout per test run in seconds.

    Returns:
        MutationTestResult with killed/survived/error lists and score.
    """
    changed = parse_changed_lines(diff)
    all_mutants: list[Mutant] = []
    killed: list[Mutant] = []
    survived: list[Mutant] = []
    errors: list[Mutant] = []

    for file_path, lines in changed.items():
        if not file_path.endswith(".py"):
            continue

        target = repo_path / file_path
        if not target.exists():
            continue

        source = target.read_text(encoding="utf-8")
        mutants = generate_mutants(source, file_path, lines, max_mutants - len(all_mutants))

        for mutant in mutants:
            all_mutants.append(mutant)
            result = run_mutant_test(
                repo_path, file_path, source, mutant.mutated_source,
                test_cmd, timeout_per_mutant,
            )
            if result == "killed":
                killed.append(mutant)
            elif result == "survived":
                survived.append(mutant)
            else:
                errors.append(mutant)

            if len(all_mutants) >= max_mutants:
                break

        if len(all_mutants) >= max_mutants:
            break

    total = len(killed) + len(survived)
    score = (len(killed) / total * 100.0) if total > 0 else 100.0

    return MutationTestResult(
        mutants=all_mutants,
        killed=killed,
        survived=survived,
        errors=errors,
        score=score,
    )
