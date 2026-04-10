"""Tier 1 fast pre-write checks — regex/AST-based, <500ms budget."""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from seraph.models.assessment import CheckFinding, CheckResult
from seraph.models.enums import CheckCategory, Verdict

logger = logging.getLogger(__name__)


# ── Import Validation ──────────────────────────────────────────

def _check_imports(content: str, file_path: str) -> list[CheckFinding]:
    """Validate that imported modules exist (stdlib + installed packages).

    Uses AST to extract imports, then checks if the top-level module
    is importable. Only flags top-level modules to avoid false positives
    on lazy imports or conditional availability.
    """
    findings: list[CheckFinding] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Can't parse — other checks will still run on regex
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_module = alias.name.split(".")[0]
                if not _module_exists(top_module):
                    findings.append(CheckFinding(
                        check=CheckCategory.IMPORT_VALIDATION,
                        file=file_path,
                        line=node.lineno,
                        description=f"Import '{alias.name}' — module '{top_module}' not found",
                        suggestion=f"Verify '{top_module}' is installed or spelled correctly",
                        confidence=0.85,
                    ))
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:  # skip relative imports
                top_module = node.module.split(".")[0]
                if not _module_exists(top_module):
                    findings.append(CheckFinding(
                        check=CheckCategory.IMPORT_VALIDATION,
                        file=file_path,
                        line=node.lineno,
                        description=f"from '{node.module}' import — module '{top_module}' not found",
                        suggestion=f"Verify '{top_module}' is installed or spelled correctly",
                        confidence=0.85,
                    ))
    return findings


def _module_exists(module_name: str) -> bool:
    """Check if a top-level module is importable without executing it."""
    import importlib.util
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ModuleNotFoundError, ValueError):
        return False


# ── Security Surface Scan ──────────────────────────────────────

# Patterns with (description, suggestion, confidence)
_SECURITY_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
    (
        re.compile(r"\beval\s*\("),
        "eval() call — arbitrary code execution risk",
        "Replace with ast.literal_eval() or a safe parser",
        0.95,
    ),
    (
        re.compile(r"\bexec\s*\("),
        "exec() call — arbitrary code execution risk",
        "Avoid exec(); use structured dispatch or importlib instead",
        0.95,
    ),
    (
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
        "subprocess with shell=True — command injection risk",
        "Use subprocess.run([...], shell=False) with explicit args",
        0.90,
    ),
    (
        re.compile(r"os\.system\s*\("),
        "os.system() call — command injection risk",
        "Use subprocess.run([...]) instead",
        0.95,
    ),
    (
        re.compile(r"os\.popen\s*\("),
        "os.popen() call — command injection risk",
        "Use subprocess.run([...], capture_output=True) instead",
        0.95,
    ),
    (
        re.compile(r"__import__\s*\("),
        "__import__() call — dynamic import risk",
        "Use importlib.import_module() for controlled dynamic imports",
        0.80,
    ),
    (
        re.compile(r"pickle\.loads?\s*\("),
        "pickle.load/loads() — arbitrary code execution via deserialization",
        "Use json or a safe serialization format",
        0.90,
    ),
    (
        re.compile(r"yaml\.(?:unsafe_)?load\s*\([^)]*(?!Loader)"),
        "yaml.load() without SafeLoader — arbitrary code execution",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        0.85,
    ),
    (
        re.compile(r"marshal\.loads?\s*\("),
        "marshal.load/loads() — unsafe deserialization",
        "Use json or a safe serialization format",
        0.90,
    ),
]

# Hardcoded secret patterns
_SECRET_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
    (
        re.compile(
            r"""(?:password|passwd|secret|api_?key|token|auth)\s*=\s*["'][^"']{8,}["']""",
            re.IGNORECASE,
        ),
        "Possible hardcoded secret or credential",
        "Use environment variables or a secrets manager",
        0.75,
    ),
    (
        re.compile(r"""["'](?:sk-|pk-|ghp_|gho_|github_pat_|xox[bpsar]-)\w{10,}["']"""),
        "Possible API key or token literal",
        "Use environment variables or a secrets manager",
        0.95,
    ),
]


def _check_security_surface(content: str, file_path: str) -> list[CheckFinding]:
    """Scan for dangerous function calls and hardcoded secrets."""
    findings: list[CheckFinding] = []
    lines = content.splitlines()

    for pattern, description, suggestion, confidence in _SECURITY_PATTERNS:
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            # Skip comments
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                # Suppress subprocess shell=True in hardcoded list context
                if "shell" in description and _is_hardcoded_subprocess(line):
                    continue
                findings.append(CheckFinding(
                    check=CheckCategory.SECURITY_SURFACE,
                    file=file_path,
                    line=i,
                    description=description,
                    suggestion=suggestion,
                    confidence=confidence,
                ))

    for pattern, description, suggestion, confidence in _SECRET_PATTERNS:
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                # Suppress common false positives
                if _is_credential_false_positive(line):
                    continue
                findings.append(CheckFinding(
                    check=CheckCategory.SECURITY_SURFACE,
                    file=file_path,
                    line=i,
                    description=description,
                    suggestion=suggestion,
                    confidence=confidence,
                ))

    return findings


# Reuse CWE-78 hardcoded list pattern from security.py
_HARDCODED_LIST_RE = re.compile(
    r"\["
    r"(?:\s*[\"'][^\"']*[\"']\s*,?\s*)*"
    r"\]"
)

# Credential false-positive suppression (mirrors security.py _CWE259_FP_RE)
_CREDENTIAL_FP_RE = re.compile(
    r"[!=]="
    r"|\.get\s*\("
    r"|\.pop\s*\("
    r"|getenv\s*\("
    r"|environ\b"
    r"|=\s*[\"'][\"']"
    r"|=\s*None\b"
    r"|\bif\s+"
    r"|\bassert\b",
    re.IGNORECASE,
)


def _is_hardcoded_subprocess(line: str) -> bool:
    """True if the subprocess call uses only hardcoded string literals."""
    return bool(_HARDCODED_LIST_RE.search(line))


def _is_credential_false_positive(line: str) -> bool:
    """True if the line is a non-credential context (comparison, env read, etc.)."""
    return bool(_CREDENTIAL_FP_RE.search(line))


# ── Escalation Scan (Mythos-informed) ──────────────────────────

_ESCALATION_PATTERNS: list[tuple[re.Pattern, str, str, float]] = [
    (
        re.compile(r"""open\s*\(\s*["']/proc/"""),
        "/proc/ filesystem access — potential sandbox escape or info leak",
        "Verify this /proc access is necessary; avoid reading sensitive proc entries",
        0.85,
    ),
    (
        re.compile(r"""open\s*\(\s*["'](?:/etc/passwd|/etc/shadow|~/.ssh/)"""),
        "Credential file read — potential credential exfiltration",
        "Avoid reading system credential files directly",
        0.95,
    ),
    (
        re.compile(r"\bos\.chmod\s*\("),
        "chmod call — modifying file permissions",
        "Verify permission changes are necessary and minimal",
        0.80,
    ),
    (
        re.compile(r"\bos\.chown\s*\("),
        "chown call — modifying file ownership",
        "Verify ownership changes are necessary and authorized",
        0.85,
    ),
    (
        re.compile(r"\bos\.setuid\s*\(|\bos\.setgid\s*\("),
        "setuid/setgid — privilege escalation",
        "Avoid changing process UID/GID unless explicitly required",
        0.95,
    ),
    (
        re.compile(r"\bctypes\.cdll\b|\bctypes\.CDLL\b"),
        "Native library loading via ctypes — potential sandbox escape",
        "Verify native library loading is necessary and the library is trusted",
        0.80,
    ),
    (
        re.compile(
            r"(?:socket|urllib|requests|httpx|aiohttp)\."
            r"(?:connect|get|post|put|delete|patch|request|urlopen)\s*\(",
        ),
        "Network call — unexpected outbound connection",
        "Verify this network call is expected for the task",
        0.70,
    ),
    (
        re.compile(r"\bos\.unlink\s*\(|\bos\.remove\s*\(|\bshutil\.rmtree\s*\("),
        "File/directory deletion — destructive operation",
        "Verify deletion target is correct and expected",
        0.70,
    ),
]


def _check_escalation(content: str, file_path: str) -> list[CheckFinding]:
    """Scan for Mythos-informed escalation indicators."""
    findings: list[CheckFinding] = []
    lines = content.splitlines()

    for pattern, description, suggestion, confidence in _ESCALATION_PATTERNS:
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                findings.append(CheckFinding(
                    check=CheckCategory.ESCALATION,
                    file=file_path,
                    line=i,
                    description=description,
                    suggestion=suggestion,
                    confidence=confidence,
                ))

    return findings


# ── Spec Drift Detection ───────────────────────────────────────

# Capabilities that should be flagged if they appear in code but weren't
# mentioned in the task description
_CAPABILITY_MARKERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsubprocess\b"), "subprocess execution"),
    (re.compile(r"\bsocket\b"), "network socket access"),
    (re.compile(r"\brequests\b|\bhttpx\b|\burllib\b|\baiohttp\b"), "HTTP client"),
    (re.compile(r"\bos\.environ\b|\bgetenv\b"), "environment variable access"),
    (re.compile(r"\bopen\s*\("), "file I/O"),
    (re.compile(r"\bsqlite3\b|\bsqlalchemy\b"), "database access"),
    (re.compile(r"\bsmtplib\b|\bemail\b"), "email sending"),
    (re.compile(r"\bos\.system\b|\bos\.popen\b"), "shell execution"),
]


def _check_spec_drift(
    diff: str,
    task_description: str,
    file_path: str,
) -> list[CheckFinding]:
    """Flag capabilities in the diff that the task description didn't mention.

    This is a heuristic pass — it looks for capability markers (network,
    file I/O, subprocess, etc.) in newly added lines that don't appear
    in the task description context. Not LLM-based (stretch goal deferred).
    """
    if not task_description or not diff:
        return []

    findings: list[CheckFinding] = []
    task_lower = task_description.lower()

    # Extract only added lines from diff
    added_lines: list[tuple[int, str]] = []
    line_num = 0
    for raw_line in diff.splitlines():
        if raw_line.startswith("@@"):
            # Parse hunk header for line number
            match = re.search(r"\+(\d+)", raw_line)
            if match:
                line_num = int(match.group(1)) - 1
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_num += 1
            added_lines.append((line_num, raw_line[1:]))
        elif not raw_line.startswith("-"):
            line_num += 1

    for pattern, capability_name in _CAPABILITY_MARKERS:
        # Skip if the task description mentions this capability
        if pattern.search(task_lower) or capability_name.lower() in task_lower:
            continue

        for line_num, line in added_lines:
            if pattern.search(line):
                findings.append(CheckFinding(
                    check=CheckCategory.SPEC_DRIFT,
                    file=file_path,
                    line=line_num,
                    description=(
                        f"New '{capability_name}' capability not mentioned in task description"
                    ),
                    suggestion=(
                        f"Verify that {capability_name} is needed for this task"
                    ),
                    confidence=0.65,
                ))
                # One finding per capability type per file is enough
                break

    return findings


# ── Orchestrator ───────────────────────────────────────────────


def run_checks(
    file_path: str,
    content: str,
    diff: str = "",
    task_description: str = "",
    block_confidence: float = 0.80,
) -> CheckResult:
    """Run all Tier 1 fast checks on a file.

    Args:
        file_path: Relative path to the file being checked.
        content: Full file content (after proposed write).
        diff: Optional unified diff of the change.
        task_description: Optional task description for spec drift detection.
        block_confidence: Minimum confidence to trigger BLOCK verdict.

    Returns:
        CheckResult with ALLOW or BLOCK verdict and any findings.
    """
    all_findings: list[CheckFinding] = []

    # Only run AST-based checks on Python files
    if file_path.endswith(".py"):
        all_findings.extend(_check_imports(content, file_path))
        all_findings.extend(_check_security_surface(content, file_path))
        all_findings.extend(_check_escalation(content, file_path))

    if diff and task_description:
        all_findings.extend(_check_spec_drift(diff, task_description, file_path))

    # Determine verdict: BLOCK if any finding meets confidence threshold
    verdict = Verdict.ALLOW
    if any(f.confidence >= block_confidence for f in all_findings):
        verdict = Verdict.BLOCK

    return CheckResult(verdict=verdict, findings=all_findings)
