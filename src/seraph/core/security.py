"""Security analysis — bandit + semgrep + detect-secrets on changed files."""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import PurePath, Path

from seraph.config import SecurityConfig
from seraph.core.paths import to_relative
from seraph.models.assessment import SecurityFinding
from seraph.models.enums import AnalyzerType, Severity

logger = logging.getLogger(__name__)

# ── CWE Tier Weighting ──────────────────────────────────────────

# Tier 0 (0.1x): noise CWEs that are almost always false positives
_CWE_TIER_0 = frozenset({"CWE-703", "CWE-390"})

# Tier 1 (3x): input validation, XSS, SQLi, log injection
_CWE_TIER_1 = frozenset({
    "CWE-20", "CWE-79", "CWE-89", "CWE-117",
})

# Tier 2 (2x): OS cmd injection, code injection, hardcoded creds, broken crypto
_CWE_TIER_2 = frozenset({
    "CWE-78", "CWE-94", "CWE-259", "CWE-798", "CWE-327",
})


def cwe_weight(cwe_id: str) -> float:
    """Return multiplier for a CWE ID based on tier."""
    if cwe_id in _CWE_TIER_0:
        return 0.1
    if cwe_id in _CWE_TIER_1:
        return 3
    if cwe_id in _CWE_TIER_2:
        return 2
    return 1


# ── Bandit CWE Map ──────────────────────────────────────────────

BANDIT_CWE_MAP: dict[str, str] = {
    # Injection
    "B608": "CWE-89",   # SQL injection
    "B609": "CWE-78",   # wildcard injection
    "B602": "CWE-78",   # subprocess popen with shell=True
    "B603": "CWE-78",   # subprocess without shell
    "B604": "CWE-78",   # function call with shell=True
    "B605": "CWE-78",   # start process with shell
    "B606": "CWE-78",   # start process with no shell
    "B607": "CWE-78",   # start process with partial path
    "B601": "CWE-94",   # paramiko exec_command
    # Crypto
    "B303": "CWE-327",  # insecure hash (md5/sha1)
    "B304": "CWE-327",  # insecure cipher
    "B305": "CWE-327",  # insecure cipher mode
    # Hardcoded credentials
    "B105": "CWE-259",  # hardcoded password string
    "B106": "CWE-259",  # hardcoded password func arg
    "B107": "CWE-259",  # hardcoded password default
    # Other secrets
    "B104": "CWE-798",  # bind all interfaces
    "B108": "CWE-798",  # hardcoded tmp directory
    # XSS / template injection
    "B701": "CWE-79",   # jinja2 autoescape false
    "B702": "CWE-79",   # use of mako templates
    "B703": "CWE-79",   # django mark_safe
    # Input validation
    "B301": "CWE-20",   # pickle
    "B302": "CWE-20",   # marshal
    "B308": "CWE-20",   # mark_safe
    "B611": "CWE-20",   # unvalidated XML input
    # YAML
    "B506": "CWE-20",   # yaml load
    # Exec
    "B102": "CWE-94",   # exec used
    "B307": "CWE-94",   # eval used
    # Random
    "B311": "CWE-330",  # pseudo-random generator
    # Try/except pass
    "B110": "CWE-390",  # try/except/pass
    # Assert
    "B101": "CWE-703",  # assert used
}

# Bandit severity mapping
_BANDIT_SEVERITY: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Semgrep severity mapping
_SEMGREP_SEVERITY: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# detect-secrets severity mapping by secret type
_DETECT_SECRETS_SEVERITY: dict[str, Severity] = {
    "Private Key": Severity.HIGH,
    "Secret Keyword": Severity.HIGH,
    "Basic Auth Credentials": Severity.HIGH,
    "JSON Web Token": Severity.HIGH,
    "Hex High Entropy String": Severity.MEDIUM,
    "Base64 High Entropy String": Severity.MEDIUM,
    "Twilio API Key": Severity.HIGH,
    "AWS Access Key": Severity.HIGH,
    "Slack Token": Severity.HIGH,
    "Stripe API Key": Severity.HIGH,
    "Artifactory Credentials": Severity.HIGH,
    "Mailchimp Access Key": Severity.HIGH,
    "IBM Cloud IAM Key": Severity.HIGH,
    "SendGrid API Key": Severity.HIGH,
    "Square OAuth Secret": Severity.HIGH,
}


@dataclass
class SecurityRunResult:
    """Wrapper for security analysis output."""

    findings: list[SecurityFinding] = field(default_factory=list)
    tools_available: dict[str, bool] = field(default_factory=dict)


# ── Subprocess Runners ──────────────────────────────────────────


def _run_bandit(
    repo_path: Path, abs_files: list[str], timeout: int,
) -> tuple[list[SecurityFinding], bool]:
    """Run bandit and parse JSON output. Returns (findings, tool_available)."""
    findings: list[SecurityFinding] = []
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", *abs_files],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or result.stderr
        if output:
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                logger.debug("Failed to parse bandit JSON output")
                return findings, True

            for issue in data.get("results", []):
                test_id = issue.get("test_id", "")
                findings.append(
                    SecurityFinding(
                        file_path=to_relative(issue.get("filename", ""), repo_path),
                        line_number=issue.get("line_number", 0),
                        column=issue.get("col_offset", 0),
                        code=test_id,
                        message=issue.get("issue_text", ""),
                        severity=_BANDIT_SEVERITY.get(
                            issue.get("issue_severity", "MEDIUM"), Severity.MEDIUM,
                        ),
                        analyzer=AnalyzerType.BANDIT,
                        cwe_id=BANDIT_CWE_MAP.get(test_id, ""),
                        confidence=issue.get("issue_confidence", ""),
                        source_line=issue.get("code", "").strip(),
                    )
                )
        return findings, True
    except subprocess.TimeoutExpired:
        logger.warning("bandit timed out after %ds", timeout)
        return findings, True
    except FileNotFoundError:
        logger.warning("bandit not found on PATH — install with: pip install bandit")
        return [], False


def _extract_semgrep_cwe(result: dict) -> str:
    """Extract the first CWE ID from a semgrep result dict.

    Semgrep reports CWEs in two forms:
    - Dict: {"id": "CWE-94", ...}
    - String: "CWE-94: Code Injection"
    """
    cwe_raw = result.get("extra", {}).get("metadata", {}).get("cwe", [])
    if not isinstance(cwe_raw, list):
        return ""
    for item in cwe_raw:
        if isinstance(item, dict):
            cwe_id = item.get("id", "")
            if cwe_id:
                return cwe_id
        elif isinstance(item, str) and item.startswith("CWE-"):
            return item.split(":")[0]
    return ""


def _run_semgrep(
    repo_path: Path, abs_files: list[str], timeout: int, rules: str = "auto",
) -> tuple[list[SecurityFinding], bool]:
    """Run semgrep and parse JSON output. Returns (findings, tool_available)."""
    findings: list[SecurityFinding] = []
    try:
        result = subprocess.run(
            ["semgrep", "--json", "--config", rules, *abs_files],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stdout:
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.debug("Failed to parse semgrep JSON output")
                return findings, True

            for r in data.get("results", []):
                cwe_id = _extract_semgrep_cwe(r)
                findings.append(
                    SecurityFinding(
                        file_path=to_relative(r.get("path", ""), repo_path),
                        line_number=r.get("start", {}).get("line", 0),
                        column=r.get("start", {}).get("col", 0),
                        code=r.get("check_id", ""),
                        message=r.get("extra", {}).get("message", ""),
                        severity=_SEMGREP_SEVERITY.get(
                            r.get("extra", {}).get("severity", "WARNING"), Severity.MEDIUM,
                        ),
                        analyzer=AnalyzerType.SEMGREP,
                        cwe_id=cwe_id,
                    )
                )
        return findings, True
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out after %ds", timeout)
        return findings, True
    except FileNotFoundError:
        logger.warning("semgrep not found on PATH — install with: pip install semgrep")
        return [], False


def _run_detect_secrets(
    repo_path: Path, abs_files: list[str], timeout: int,
) -> tuple[list[SecurityFinding], bool]:
    """Run detect-secrets scan and parse JSON output. Returns (findings, tool_available)."""
    findings: list[SecurityFinding] = []
    try:
        result = subprocess.run(
            ["detect-secrets", "scan", *abs_files],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.stdout:
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.debug("Failed to parse detect-secrets JSON output")
                return findings, True

            for file_path, secrets in data.get("results", {}).items():
                for secret in secrets:
                    secret_type = secret.get("type", "")
                    findings.append(
                        SecurityFinding(
                            file_path=to_relative(file_path, repo_path),
                            line_number=secret.get("line_number", 0),
                            code=secret_type,
                            message=f"Possible secret: {secret_type or 'unknown'}",
                            severity=_DETECT_SECRETS_SEVERITY.get(
                                secret_type, Severity.HIGH,
                            ),
                            analyzer=AnalyzerType.DETECT_SECRETS,
                            cwe_id="CWE-798",
                        )
                    )
        return findings, True
    except subprocess.TimeoutExpired:
        logger.warning("detect-secrets timed out after %ds", timeout)
        return findings, True
    except FileNotFoundError:
        logger.warning("detect-secrets not found on PATH — install with: pip install detect-secrets")
        return [], False


# ── Post-Filters ───────────────────────────────────────────────

# Bandit test IDs for hardcoded password checks (CWE-259)
_CWE259_CODES = frozenset({"B105", "B106", "B107"})

# Bandit test IDs for OS command injection (CWE-78)
_CWE78_CODES = frozenset({"B602", "B603", "B604", "B605", "B606", "B607", "B609"})

# Subprocess calls with ONLY hardcoded string literals in a list are safe.
# Matches: subprocess.run(["ruff", "--select", "F401"]) or ["git", "rev-list"]
# Rejects: subprocess.run([cmd, arg]) or subprocess.run(f"rm {path}")
_CWE78_HARDCODED_LIST_RE = re.compile(
    r"\["                   # opening bracket
    r"(?:\s*[\"'][^\"']*[\"']\s*,?\s*)*"  # zero or more quoted string literals
    r"\]"                   # closing bracket
)

# Patterns in source_line that indicate non-hardcoded-credential contexts:
# comparison checks, dict lookups, env reads, empty/None defaults
_CWE259_FP_RE = re.compile(
    r"[!=]="              # == or != comparison
    r"|\.get\s*\("        # dict .get() lookup
    r"|\.pop\s*\("        # dict .pop() with default
    r"|\.setdefault\s*\(" # dict .setdefault()
    r"|getenv\s*\("       # os.getenv() fallback
    r"|environ\b"         # os.environ access
    r"|=\s*[\"'][\"']"    # empty string assignment: = "" or = ''
    r"|=\s*None\b"        # None default: = None
    r"|\bif\s+"           # truthiness check: if password:
    r"|\bassert\b"        # assertion about the value
    r"|\braise\b"         # raising with the value
    r"|\blen\s*\(",       # length check: len(password)
    re.IGNORECASE,
)

# Context words that indicate non-cryptographic use of random()
_RANDOM_BENIGN_CONTEXT = re.compile(r"jitter|retry|backoff|sleep", re.IGNORECASE)

# File-name patterns indicating demo/test/seed data
_RANDOM_BENIGN_FILES = re.compile(r"(^|/)demo|seed|test", re.IGNORECASE)


def _matches_any_pattern(file_path: str, patterns: tuple[str, ...]) -> bool:
    """Check if file_path matches any of the glob patterns.

    Handles directory prefixes (ending with /) by converting to wildcard
    patterns. Also supports standard fnmatch/PurePath patterns.
    """
    pure = PurePath(file_path)
    for pattern in patterns:
        # Directory prefix: "tests/" → "tests/*", "**/alembic/" → "**/alembic/*"
        effective = pattern + "*" if pattern.endswith("/") else pattern
        if fnmatch.fnmatch(file_path, effective) or pure.match(effective):
            return True
        # PurePath.match with **/ prefix requires ≥1 parent dir; also try
        # the pattern without the **/ prefix for root-level matches.
        if effective.startswith("**/"):
            stripped = effective[3:]
            if fnmatch.fnmatch(file_path, stripped) or pure.match(stripped):
                return True
    return False


def _filter_findings(
    findings: list[SecurityFinding],
    config: SecurityConfig,
) -> list[SecurityFinding]:
    """Remove false-positive findings based on source context and config."""
    filtered: list[SecurityFinding] = []
    for f in findings:
        # bandit_skip: drop any finding whose test_id is in the skip list
        if f.code in config.bandit_skip:
            continue

        # CWE-259 suppression: drop B105/B106/B107 where source indicates
        # non-credential context (comparisons, lookups, empty defaults, etc.)
        if f.code in _CWE259_CODES and _CWE259_FP_RE.search(f.source_line):
            continue

        # CWE-78 suppression: drop B602-B607/B609 where the source line
        # contains only hardcoded string literals in a list (internal tool
        # invocations like subprocess.run(["ruff", "--select", "F401"]))
        if f.code in _CWE78_CODES and _CWE78_HARDCODED_LIST_RE.search(f.source_line):
            continue

        # CWE-330 non-crypto suppression: drop B311 in demo/test files or
        # when source line contains benign context (jitter/retry/backoff/sleep)
        if f.code == "B311":
            if _RANDOM_BENIGN_FILES.search(f.file_path):
                continue
            if _RANDOM_BENIGN_CONTEXT.search(f.source_line):
                continue

        filtered.append(f)
    return filtered


def _filter_files_for_detect_secrets(
    abs_files: list[str],
    repo_path: Path,
    exclude_patterns: tuple[str, ...],
) -> list[str]:
    """Remove files matching exclude patterns before passing to detect-secrets."""
    if not exclude_patterns:
        return abs_files
    result = []
    for abs_file in abs_files:
        rel = to_relative(abs_file, repo_path)
        if not _matches_any_pattern(rel, exclude_patterns):
            result.append(abs_file)
    return result


# ── Orchestrator ────────────────────────────────────────────────


def run_security_analysis(
    repo_path: Path,
    files: list[str],
    security_config: SecurityConfig | None = None,
) -> SecurityRunResult:
    """Run all enabled security analyzers on the specified files."""
    config = security_config or SecurityConfig()
    timeout = config.timeout

    abs_files = [str(repo_path / f) for f in files if f.endswith(".py")]
    if not abs_files:
        return SecurityRunResult()

    all_findings: list[SecurityFinding] = []
    tools_available: dict[str, bool] = {}

    if config.bandit_enabled:
        findings, available = _run_bandit(repo_path, abs_files, timeout)
        all_findings.extend(findings)
        tools_available["bandit"] = available

    if config.semgrep_enabled:
        findings, available = _run_semgrep(repo_path, abs_files, timeout, config.semgrep_rules)
        all_findings.extend(findings)
        tools_available["semgrep"] = available

    if config.detect_secrets_enabled:
        ds_files = _filter_files_for_detect_secrets(
            abs_files, repo_path, config.detect_secrets_exclude,
        )
        if ds_files:
            findings, available = _run_detect_secrets(repo_path, ds_files, timeout)
            all_findings.extend(findings)
            tools_available["detect-secrets"] = available
        else:
            tools_available["detect-secrets"] = True

    all_findings = _filter_findings(all_findings, config)
    return SecurityRunResult(findings=all_findings, tools_available=tools_available)


