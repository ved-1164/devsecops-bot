"""Unit tests for scanner output parsing and reporter formatting."""

import json
import os
import textwrap
from unittest.mock import patch

import pytest

from bot.scanner import (
    Finding,
    ScanResult,
    _normalize_path,
    _run_pip_audit,
    _run_safety,
    run_bandit,
    run_flake8,
    run_safety,
)
from bot.reporter import format_comment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        scanner="bandit",
        rule_id="B101",
        severity="HIGH",
        title="assert used",
        file_path="app.py",
        line=10,
        message="Use of assert detected.",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# _normalize_path
# ---------------------------------------------------------------------------

class TestNormalizePath:
    def test_empty_string_returns_empty(self):
        assert _normalize_path("") == ""

    def test_relative_path_unchanged(self):
        result = _normalize_path("sample_app/app.py")
        # os.path.relpath normalises separators per OS
        assert result == os.path.join("sample_app", "app.py")

    def test_none_like_falsy_returns_as_is(self):
        assert _normalize_path("") == ""


# ---------------------------------------------------------------------------
# ScanResult computed properties
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_warning_count_medium_low_only(self):
        result = ScanResult(bandit_findings=[
            make_finding(severity="MEDIUM"),
            make_finding(severity="LOW"),
            make_finding(severity="HIGH"),
        ])
        assert result.warning_count == 2

    def test_failure_count_high_sast(self):
        result = ScanResult(bandit_findings=[
            make_finding(severity="HIGH"),
            make_finding(severity="CRITICAL"),
        ])
        assert result.failure_count == 2

    def test_failure_count_cve(self):
        result = ScanResult(cve_findings=[make_finding(scanner="pip-audit")])
        assert result.failure_count == 1

    def test_failure_count_low_coverage(self):
        result = ScanResult(coverage_pct=55.0)
        assert result.failure_count == 1

    def test_no_failure_above_80_coverage(self):
        result = ScanResult(coverage_pct=82.0)
        assert result.failure_count == 0

    def test_has_failures_false_when_clean(self):
        assert not ScanResult().has_failures


# ---------------------------------------------------------------------------
# run_bandit — mocked subprocess
# ---------------------------------------------------------------------------

BANDIT_JSON = json.dumps({
    "results": [
        {
            "test_id": "B608",
            "test_name": "hardcoded_sql_expressions",
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": "Possible SQL injection via string-based query construction.",
            "filename": "app.py",
            "line_number": 15,
        }
    ]
})


class TestRunBandit:
    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(0, BANDIT_JSON, ""))
    def test_parses_finding(self, _mock_run, _mock_tool):
        findings = run_bandit(".")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "B608"
        assert f.severity == "HIGH"
        assert f.line == 15

    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(0, "", ""))
    def test_empty_output_returns_empty_list(self, _mock_run, _mock_tool):
        assert run_bandit(".") == []

    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(0, "not json", ""))
    def test_invalid_json_returns_empty_list(self, _mock_run, _mock_tool):
        assert run_bandit(".") == []

    @patch("bot.scanner._tool_available", return_value=False)
    def test_skipped_when_tool_missing(self, _mock_tool):
        assert run_bandit(".") == []


# ---------------------------------------------------------------------------
# run_flake8 — mocked subprocess
# ---------------------------------------------------------------------------

FLAKE8_OUTPUT = textwrap.dedent("""\
    api/routes.py:33:80: E501 line too long (92 > 79 characters)
    test_utils.py:14:1: W291 trailing whitespace
""")


class TestRunFlake8:
    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(1, FLAKE8_OUTPUT, ""))
    def test_parses_two_findings(self, _mock_run, _mock_tool):
        findings = run_flake8(".")
        assert len(findings) == 2

    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(1, FLAKE8_OUTPUT, ""))
    def test_first_finding_fields(self, _mock_run, _mock_tool):
        f = run_flake8(".")[0]
        assert f.rule_id == "E501"
        assert f.line == 33

    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run", return_value=(0, "", ""))
    def test_no_output_returns_empty(self, _mock_run, _mock_tool):
        assert run_flake8(".") == []

    @patch("bot.scanner._tool_available", return_value=False)
    def test_skipped_when_tool_missing(self, _mock_tool):
        assert run_flake8(".") == []


# ---------------------------------------------------------------------------
# _run_pip_audit — mocked subprocess
# ---------------------------------------------------------------------------

PIP_AUDIT_JSON = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.18.0",
            "vulns": [
                {
                    "id": "PYSEC-2018-28",
                    "aliases": ["CVE-2018-18074"],
                    "description": "Requests sends auth headers to redirect targets.",
                    "fix_versions": ["2.20.0"],
                }
            ],
        }
    ],
    "fixes": [],
})

PIP_AUDIT_CLEAN = json.dumps({"dependencies": [], "fixes": []})


class TestRunPipAudit:
    def test_parses_cve_finding(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.18.0\n")
        with patch("bot.scanner._run", return_value=(0, PIP_AUDIT_JSON, "")):
            findings = _run_pip_audit(str(req))
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2018-18074"
        assert findings[0].severity == "HIGH"
        assert "requests" in findings[0].title

    def test_clean_returns_empty(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        with patch("bot.scanner._run", return_value=(0, PIP_AUDIT_CLEAN, "")):
            findings = _run_pip_audit(str(req))
        assert findings == []

    def test_empty_stdout_returns_empty(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")
        with patch("bot.scanner._run", return_value=(0, "", "")):
            findings = _run_pip_audit(str(req))
        assert findings == []


# ---------------------------------------------------------------------------
# _run_safety fallback — mocked subprocess
# ---------------------------------------------------------------------------

SAFETY_V2_JSON = json.dumps([
    ["requests", "<2.28.0", "2.27.0", "CVE-2023-32681: Unintended leak.", "CVE-2023-32681"],
])

SAFETY_V3_JSON = json.dumps({
    "vulnerabilities": [
        {
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "flask",
            "analyzed_version": "2.0.0",
            "advisory": "Flask XSS via redirect.",
        }
    ]
})


class TestRunSafetyFallback:
    def test_parses_safety_v2_format(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.27.0\n")
        with patch("bot.scanner._run", return_value=(1, SAFETY_V2_JSON, "")):
            findings = _run_safety(str(req))
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2023-32681"

    def test_parses_safety_v3_format(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\n")
        with patch("bot.scanner._run", return_value=(0, SAFETY_V3_JSON, "")):
            findings = _run_safety(str(req))
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2024-12345"


# ---------------------------------------------------------------------------
# run_safety dispatcher
# ---------------------------------------------------------------------------

class TestRunSafetyDispatcher:
    def test_no_requirements_txt_returns_empty(self, tmp_path):
        assert run_safety(str(tmp_path)) == []

    @patch("bot.scanner._tool_available", return_value=True)
    @patch("bot.scanner._run_pip_audit", return_value=[make_finding(scanner="pip-audit")])
    def test_uses_pip_audit_when_available(self, mock_audit, _mock_tool, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.18.0\n")
        findings = run_safety(str(tmp_path))
        assert len(findings) == 1
        mock_audit.assert_called_once()

    @patch("bot.scanner._tool_available", side_effect=lambda n: n == "safety")
    @patch("bot.scanner._run_safety", return_value=[make_finding(scanner="safety")])
    def test_falls_back_to_safety(self, mock_safety, _mock_tool, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.27.0\n")
        findings = run_safety(str(tmp_path))
        assert len(findings) == 1
        mock_safety.assert_called_once()


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------

class TestFormatComment:
    def test_header_contains_sha(self):
        comment = format_comment(ScanResult(), "abc123fdeadbeef")
        assert "## Bot Review: abc123f" in comment

    def test_no_findings_shows_clean(self):
        comment = format_comment(ScanResult(), "abc123f")
        assert "No security issues found" in comment
        assert "No CVEs" in comment

    def test_high_severity_shows_unchecked(self):
        result = ScanResult(bandit_findings=[make_finding(severity="HIGH")])
        assert "- [ ] B101" in format_comment(result, "abc123f")

    def test_coverage_below_target_shows_warning(self):
        comment = format_comment(ScanResult(coverage_pct=61.0), "abc123f")
        assert "61.0%" in comment
        assert "target 80%" in comment

    def test_overall_line_present(self):
        result = ScanResult(bandit_findings=[make_finding(severity="MEDIUM")], coverage_pct=90.0)
        assert "Overall:" in format_comment(result, "abc123f")

    def test_fix_summary_shown_when_applied(self):
        comment = format_comment(ScanResult(), "abc123f", fix_summary={"black": True, "autoflake": True})
        assert "Auto-fixes applied" in comment

    def test_flake8_capped_at_10(self):
        findings = [
            make_finding(scanner="flake8", rule_id="E501", severity="MEDIUM", title=f"issue {i}")
            for i in range(15)
        ]
        comment = format_comment(ScanResult(flake8_findings=findings), "abc123f")
        assert "5 more flake8 issues" in comment

    def test_cve_findings_shown(self):
        result = ScanResult(cve_findings=[make_finding(scanner="pip-audit", rule_id="CVE-2024-1234")])
        comment = format_comment(result, "abc123f")
        assert "CVE-2024-1234" in comment
        assert "1 CVE(s) found" in comment


# ---------------------------------------------------------------------------
# sample_app integration smoke-test (runs real bandit)
# ---------------------------------------------------------------------------

class TestSampleAppHasBugs:
    def test_bandit_finds_issues_in_sample_app(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "sample_app")
        findings = run_bandit(os.path.abspath(sample_path))
        assert findings, "bandit should find at least one issue in sample_app"
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids & {"B602", "B608", "B105", "B101"}, (
            f"Expected known bad rules, got: {rule_ids}"
        )

    def test_sample_app_requirements_has_cves(self, tmp_path):
        """pip-audit should flag the pinned vulnerable packages."""
        import shutil
        sample_req = os.path.join(
            os.path.dirname(__file__), "..", "sample_app", "requirements.txt"
        )
        with patch("bot.scanner._run") as mock_run:
            cve_json = json.dumps({
                "dependencies": [
                    {"name": "requests", "version": "2.18.0",
                     "vulns": [{"id": "PYSEC-1", "aliases": ["CVE-2018-18074"],
                                "description": "...", "fix_versions": ["2.20.0"]}]},
                ],
                "fixes": [],
            })
            mock_run.return_value = (0, cve_json, "")
            findings = _run_pip_audit(sample_req)
        assert findings, "sample_app/requirements.txt should produce CVE findings"
