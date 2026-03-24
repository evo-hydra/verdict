"""Tests for Seraph security analysis module."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from seraph.config import ScoringConfig, SecurityConfig
from seraph.core.reporter import compute_security_score
from seraph.core.security import (
    BANDIT_CWE_MAP,
    SecurityRunResult,
    _DETECT_SECRETS_SEVERITY,
    _extract_semgrep_cwe,
    _filter_findings,
    _run_bandit,
    _run_detect_secrets,
    _run_semgrep,
    cwe_weight,
    run_security_analysis,
)
from seraph.models.assessment import SecurityFinding
from seraph.models.enums import AnalyzerType, Severity


class TestCweWeight:
    def test_tier_1_returns_3(self):
        assert cwe_weight("CWE-89") == 3   # SQLi
        assert cwe_weight("CWE-79") == 3   # XSS
        assert cwe_weight("CWE-20") == 3   # input validation
        assert cwe_weight("CWE-117") == 3  # log injection

    def test_tier_2_returns_2(self):
        assert cwe_weight("CWE-78") == 2   # OS cmd injection
        assert cwe_weight("CWE-94") == 2   # code injection
        assert cwe_weight("CWE-798") == 2  # hardcoded creds
        assert cwe_weight("CWE-327") == 2  # broken crypto

    def test_tier_0_returns_low(self):
        assert cwe_weight("CWE-703") == 0.1  # assert — noise
        assert cwe_weight("CWE-390") == 0.1  # try/except/pass — noise

    def test_other_returns_1(self):
        assert cwe_weight("CWE-330") == 1  # pseudo-random
        assert cwe_weight("") == 1         # unmapped
        assert cwe_weight("CWE-999") == 1  # unknown


class TestExtractSemgrepCwe:
    def test_string_form(self):
        result = {"extra": {"metadata": {"cwe": ["CWE-94: Code Injection"]}}}
        assert _extract_semgrep_cwe(result) == "CWE-94"

    def test_dict_form(self):
        result = {"extra": {"metadata": {"cwe": [{"id": "CWE-89"}]}}}
        assert _extract_semgrep_cwe(result) == "CWE-89"

    def test_empty_cwe_list(self):
        result = {"extra": {"metadata": {"cwe": []}}}
        assert _extract_semgrep_cwe(result) == ""

    def test_no_metadata(self):
        result = {"extra": {}}
        assert _extract_semgrep_cwe(result) == ""


class TestRunBandit:
    @patch("seraph.core.security.subprocess.run")
    def test_parses_json(self, mock_run, tmp_path: Path):
        bandit_output = {
            "results": [
                {
                    "filename": str(tmp_path / "foo.py"),
                    "line_number": 10,
                    "col_offset": 5,
                    "test_id": "B608",
                    "issue_text": "Possible SQL injection",
                    "issue_severity": "HIGH",
                    "issue_confidence": "MEDIUM",
                },
                {
                    "filename": str(tmp_path / "bar.py"),
                    "line_number": 20,
                    "test_id": "B105",
                    "issue_text": "Hardcoded password",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                },
            ],
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=json.dumps(bandit_output), stderr="",
        )

        findings, available = _run_bandit(tmp_path, [str(tmp_path / "foo.py")], 60)

        assert available is True
        assert len(findings) == 2
        assert findings[0].code == "B608"
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == AnalyzerType.BANDIT
        assert findings[1].cwe_id == "CWE-259"

    @patch("seraph.core.security.subprocess.run")
    def test_not_installed(self, mock_run, tmp_path: Path):
        mock_run.side_effect = FileNotFoundError()
        findings, available = _run_bandit(tmp_path, ["foo.py"], 60)
        assert findings == []
        assert available is False

    @patch("seraph.core.security.subprocess.run")
    def test_timeout(self, mock_run, tmp_path: Path):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="bandit", timeout=60)
        findings, available = _run_bandit(tmp_path, ["foo.py"], 60)
        assert findings == []
        assert available is True


class TestRunSemgrep:
    @patch("seraph.core.security.subprocess.run")
    def test_parses_json(self, mock_run, tmp_path: Path):
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": str(tmp_path / "foo.py"),
                    "start": {"line": 5, "col": 1},
                    "extra": {
                        "message": "Detected use of eval()",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-94: Code Injection"],
                        },
                    },
                },
            ],
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(semgrep_output), stderr="",
        )

        findings, available = _run_semgrep(tmp_path, [str(tmp_path / "foo.py")], 60)

        assert available is True
        assert len(findings) == 1
        assert findings[0].code == "python.lang.security.audit.eval-detected"
        assert findings[0].cwe_id == "CWE-94"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == AnalyzerType.SEMGREP

    @patch("seraph.core.security.subprocess.run")
    def test_not_installed(self, mock_run, tmp_path: Path):
        mock_run.side_effect = FileNotFoundError()
        findings, available = _run_semgrep(tmp_path, ["foo.py"], 60)
        assert findings == []
        assert available is False


class TestRunDetectSecrets:
    @patch("seraph.core.security.subprocess.run")
    def test_parses_json(self, mock_run, tmp_path: Path):
        ds_output = {
            "results": {
                str(tmp_path / "config.py"): [
                    {
                        "type": "Secret Keyword",
                        "line_number": 15,
                    },
                ],
            },
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(ds_output), stderr="",
        )

        findings, available = _run_detect_secrets(tmp_path, [str(tmp_path / "config.py")], 60)

        assert available is True
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-798"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == AnalyzerType.DETECT_SECRETS


class TestDetectSecretsSeverity:
    def test_known_types_mapped(self):
        assert _DETECT_SECRETS_SEVERITY["Private Key"] == Severity.HIGH
        assert _DETECT_SECRETS_SEVERITY["Hex High Entropy String"] == Severity.MEDIUM

    @patch("seraph.core.security.subprocess.run")
    def test_uses_type_severity(self, mock_run, tmp_path: Path):
        ds_output = {
            "results": {
                str(tmp_path / "config.py"): [
                    {"type": "Hex High Entropy String", "line_number": 15},
                ],
            },
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(ds_output), stderr="",
        )
        findings, _ = _run_detect_secrets(tmp_path, [str(tmp_path / "config.py")], 60)
        assert findings[0].severity == Severity.MEDIUM


class TestComputeSecurityScore:
    def test_clean_returns_100(self):
        assert compute_security_score([], 5) == 100.0

    def test_zero_files_returns_100(self):
        assert compute_security_score([SecurityFinding()], 0) == 100.0

    def test_cwe_tier_weighting(self):
        """Tier 1 CWE findings should deduct more than unmapped findings."""
        tier1_finding = SecurityFinding(
            severity=Severity.HIGH, cwe_id="CWE-89",
        )
        unmapped_finding = SecurityFinding(
            severity=Severity.HIGH, cwe_id="",
        )

        # Same severity, different CWE tier
        score_tier1 = compute_security_score([tier1_finding], 1)
        score_unmapped = compute_security_score([unmapped_finding], 1)

        # Tier 1 (3x multiplier) should produce a lower score
        assert score_tier1 < score_unmapped

    def test_multiple_findings(self):
        findings = [
            SecurityFinding(severity=Severity.HIGH, cwe_id="CWE-89"),
            SecurityFinding(severity=Severity.MEDIUM, cwe_id="CWE-327"),
            SecurityFinding(severity=Severity.LOW, cwe_id=""),
        ]
        score = compute_security_score(findings, 3)
        assert 0 < score < 100

    def test_uses_config_threshold(self):
        finding = SecurityFinding(severity=Severity.HIGH, cwe_id="")
        scoring = ScoringConfig(security_issue_threshold=100.0)
        score = compute_security_score([finding], 1, scoring)
        # High threshold → more lenient scoring
        assert score > 90


class TestRunSecurityAnalysis:
    @patch("seraph.core.security._run_detect_secrets")
    @patch("seraph.core.security._run_semgrep")
    @patch("seraph.core.security._run_bandit")
    def test_orchestrates_all_tools(self, mock_bandit, mock_semgrep, mock_ds, tmp_path: Path):
        mock_bandit.return_value = (
            [SecurityFinding(code="B608", cwe_id="CWE-89")], True,
        )
        mock_semgrep.return_value = (
            [SecurityFinding(code="eval-detected")], True,
        )
        mock_ds.return_value = ([], True)

        result = run_security_analysis(tmp_path, ["foo.py"])

        assert len(result.findings) == 2
        assert result.tools_available == {
            "bandit": True, "semgrep": True, "detect-secrets": True,
        }

    def test_no_py_files_returns_empty(self, tmp_path: Path):
        result = run_security_analysis(tmp_path, ["README.md"])
        assert result.findings == []
        assert result.tools_available == {}


class TestFilterFindings:
    """Tests for the _filter_findings post-filter."""

    def _config(self, **kwargs) -> SecurityConfig:
        return SecurityConfig(**kwargs)

    def test_drops_comparison_cwe259(self):
        """B105/B106/B107 with == or != in source_line should be dropped."""
        finding = SecurityFinding(
            code="B105", cwe_id="CWE-259",
            source_line="if pw == 'default':",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_keeps_assignment_cwe259(self):
        """B105 with assignment (no comparison) should be kept."""
        finding = SecurityFinding(
            code="B105", cwe_id="CWE-259",
            source_line="pw = 'secret'",
        )
        result = _filter_findings([finding], self._config())
        assert len(result) == 1

    def test_drops_demo_cwe330(self):
        """B311 in demo files should be dropped."""
        finding = SecurityFinding(
            code="B311", cwe_id="CWE-330",
            file_path="demo.py", source_line="random.random()",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_retry_cwe330(self):
        """B311 with jitter/retry/backoff context should be dropped."""
        finding = SecurityFinding(
            code="B311", cwe_id="CWE-330",
            file_path="auth.py",
            source_line="sleep(random.random() * jitter)",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_keeps_crypto_cwe330(self):
        """B311 in auth code without benign context should be kept."""
        finding = SecurityFinding(
            code="B311", cwe_id="CWE-330",
            file_path="auth.py",
            source_line="token = random.random()",
        )
        result = _filter_findings([finding], self._config())
        assert len(result) == 1

    def test_bandit_skip_config(self):
        """Findings with code in bandit_skip should be dropped."""
        findings = [
            SecurityFinding(code="B101", cwe_id="CWE-703"),
            SecurityFinding(code="B608", cwe_id="CWE-89"),
        ]
        result = _filter_findings(findings, self._config(bandit_skip=("B101",)))
        assert len(result) == 1
        assert result[0].code == "B608"

    def test_drops_test_file_cwe330(self):
        """B311 in test files should be dropped."""
        finding = SecurityFinding(
            code="B311", cwe_id="CWE-330",
            file_path="tests/test_utils.py",
            source_line="random.random()",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_ne_comparison_cwe259(self):
        """B106 with != in source_line should be dropped."""
        finding = SecurityFinding(
            code="B106", cwe_id="CWE-259",
            source_line="if password != '':",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_get_lookup_cwe259(self):
        """B105 with .get() dict lookup should be dropped."""
        finding = SecurityFinding(
            code="B105", cwe_id="CWE-259",
            source_line="password = config.get('db_password', '')",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_getenv_cwe259(self):
        """B106 with getenv should be dropped."""
        finding = SecurityFinding(
            code="B106", cwe_id="CWE-259",
            source_line="connect(password=os.getenv('DB_PASS', 'fallback'))",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_empty_default_cwe259(self):
        """B107 with empty string default should be dropped."""
        finding = SecurityFinding(
            code="B107", cwe_id="CWE-259",
            source_line="def connect(password=''):",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_none_default_cwe259(self):
        """B107 with None default should be dropped."""
        finding = SecurityFinding(
            code="B107", cwe_id="CWE-259",
            source_line="def connect(password=None):",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_truthiness_check_cwe259(self):
        """B105 in an if-check context should be dropped."""
        finding = SecurityFinding(
            code="B105", cwe_id="CWE-259",
            source_line="if password:",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_hardcoded_subprocess_cwe78(self):
        """B603 with hardcoded string list should be dropped."""
        finding = SecurityFinding(
            code="B603", cwe_id="CWE-78",
            source_line='subprocess.run(["ruff", "--select", "F401"])',
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_drops_hardcoded_git_command_cwe78(self):
        """B603 with hardcoded git command should be dropped."""
        finding = SecurityFinding(
            code="B603", cwe_id="CWE-78",
            source_line="safe_git_command(['rev-list', '--count', 'HEAD'])",
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_keeps_variable_subprocess_cwe78(self):
        """B603 with variable args should be kept."""
        finding = SecurityFinding(
            code="B603", cwe_id="CWE-78",
            source_line="subprocess.run([cmd, arg1, arg2])",
        )
        result = _filter_findings([finding], self._config())
        assert len(result) == 1

    def test_keeps_fstring_subprocess_cwe78(self):
        """B602 with f-string should be kept."""
        finding = SecurityFinding(
            code="B602", cwe_id="CWE-78",
            source_line='subprocess.run(f"rm -rf {path}", shell=True)',
        )
        result = _filter_findings([finding], self._config())
        assert len(result) == 1

    def test_drops_b607_hardcoded_partial_path_cwe78(self):
        """B607 with hardcoded partial path in list should be dropped."""
        finding = SecurityFinding(
            code="B607", cwe_id="CWE-78",
            source_line='subprocess.Popen(["mypy", "--strict", "src/"])',
        )
        result = _filter_findings([finding], self._config())
        assert result == []

    def test_keeps_mixed_list_cwe78(self):
        """B603 with mix of hardcoded and variable args should be kept."""
        finding = SecurityFinding(
            code="B603", cwe_id="CWE-78",
            source_line='subprocess.run(["ruff", file_path])',
        )
        result = _filter_findings([finding], self._config())
        assert len(result) == 1

    def test_default_bandit_skip_drops_b101_b110(self):
        """Default config skips B101 (assert) and B110 (try/except/pass)."""
        findings = [
            SecurityFinding(code="B101", cwe_id="CWE-703"),
            SecurityFinding(code="B110", cwe_id="CWE-390"),
            SecurityFinding(code="B608", cwe_id="CWE-89"),
        ]
        # Default config now includes B101, B110 in bandit_skip
        result = _filter_findings(findings, self._config())
        assert len(result) == 1
        assert result[0].code == "B608"


class TestDetectSecretsExclusion:
    """Tests for detect-secrets path exclusion."""

    @patch("seraph.core.security._run_detect_secrets")
    @patch("seraph.core.security._run_bandit")
    def test_excludes_patterns(self, mock_bandit, mock_ds, tmp_path: Path):
        """Files matching detect_secrets_exclude patterns should not reach detect-secrets."""
        mock_bandit.return_value = ([], True)
        mock_ds.return_value = ([], True)

        config = SecurityConfig(
            semgrep_enabled=False,
            detect_secrets_exclude=("tests/", "**/alembic/versions/"),
        )
        # All files match exclusion patterns — detect-secrets should not be called
        result = run_security_analysis(
            tmp_path,
            ["tests/test_auth.py", "alembic/versions/abc123.py"],
            security_config=config,
        )

        mock_ds.assert_not_called()
        assert result.tools_available.get("detect-secrets") is True

    @patch("seraph.core.security._run_detect_secrets")
    @patch("seraph.core.security._run_bandit")
    def test_passes_non_excluded_files(self, mock_bandit, mock_ds, tmp_path: Path):
        """Non-excluded files should still be passed to detect-secrets."""
        mock_bandit.return_value = ([], True)
        mock_ds.return_value = ([], True)

        config = SecurityConfig(
            semgrep_enabled=False,
            detect_secrets_exclude=("tests/",),
        )
        run_security_analysis(
            tmp_path,
            ["src/auth.py", "tests/test_auth.py"],
            security_config=config,
        )

        mock_ds.assert_called_once()
        ds_files = mock_ds.call_args[0][1]
        assert len(ds_files) == 1
        assert "src/auth.py" in ds_files[0]


class TestRunBanditSourceLine:
    """Tests for source_line capture in _run_bandit."""

    @patch("seraph.core.security.subprocess.run")
    def test_captures_source_line(self, mock_run, tmp_path: Path):
        bandit_output = {
            "results": [
                {
                    "filename": str(tmp_path / "foo.py"),
                    "line_number": 10,
                    "col_offset": 0,
                    "test_id": "B105",
                    "issue_text": "Hardcoded password",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                    "code": "  password = 'zado123'\n",
                },
            ],
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=json.dumps(bandit_output), stderr="",
        )

        findings, _ = _run_bandit(tmp_path, [str(tmp_path / "foo.py")], 60)

        assert len(findings) == 1
        assert findings[0].source_line == "password = 'zado123'"
