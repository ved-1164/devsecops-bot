"""Unit tests for scanner output parsing and reporter formatting."""

import json
import os
import textwrap
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from bot.scanner import (
    Finding,
    ScanResult,
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
# ScanResult computed properties
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_warning_count_medium_low_only(self):
        result = ScanResult(bandit_findings=[
            make_finding(severity="MEDIUM"),
            make_finding(severity="LOW"),
            make_finding(severity="HIGH"),   # should NOT count as warning
        ])
        assert result.warning_count == 2

    def test_failure_count_high_sast(self):
        result = ScanResult(bandit_findings=[
            make_finding(severity="HIGH"),
            make_finding(severity="CRITICAL"),
        ])
        assert result.failure_count == 2

    def test_failure_count_cve(self):
        result = ScanResult(cve_findings=[make_finding(scanner="safety")])
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
    @patch("bot.scanner._run", return_value=(0, BANDIT_JSON, ""))
    def test_parses_finding(self, _mock):
        findings = run_bandit(".")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "B608"
        assert f.severity == "HIGH"
        assert f.file_path == "app.py"
        assert f.line == 15

    @patch("bot.scanner._run", return_value=(0, "", ""))
    def test_empty_output_returns_empty_list(self, _mock):
        assert run_bandit(".") == []

    @patch("bot.scanner._run", return_value=(0, "not json", ""))
    def test_invalid_json_returns_empty_list(self, _mock):
        assert run_bandit(".") == []


# ---------------------------------------------------------------------------
# run_flake8 — mocked subprocess
# ---------------------------------------------------------------------------

FLAKE8_OUTPUT = textwrap.dedent("""\
    api/routes.py:33:80: E501 line too long (92 > 79 characters)
    test_utils.py:14:1: W291 trailing whitespace
""")


class TestRunFlake8:
    @patch("bot.scanner._run", return_value=(1, FLAKE8_OUTPUT, ""))
    def test_parses_two_findings(self, _mock):
        findings = run_flake8(".")
        assert len(findings) == 2

    @patch("bot.scanner._run", return_value=(1, FLAKE8_OUTPUT, ""))
    def test_first_finding_fields(self, _mock):
        f = run_flake8(".")[0]
        assert f.rule_id == "E501"
        assert f.file_path == "api/routes.py"
        assert f.line == 33

    @patch("bot.scanner._run", return_value=(0, "", ""))
    def test_no_output_returns_empty(self, _mock):
        assert run_flake8(".") == []


# ---------------------------------------------------------------------------
# run_safety — mocked subprocess
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


class TestRunSafety:
    def test_no_requirements_txt_returns_empty(self, tmp_path):
        findings = run_safety(str(tmp_path))
        assert findings == []

    @patch("bot.scanner._run", return_value=(1, SAFETY_V2_JSON, ""))
    def test_parses_safety_v2_format(self, _mock, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.27.0\n")
        findings = run_safety(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2023-32681"
        assert findings[0].severity == "HIGH"

    @patch("bot.scanner._run", return_value=(0, SAFETY_V3_JSON, ""))
    def test_parses_safety_v3_format(self, _mock, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.0.0\n")
        findings = run_safety(str(tmp_path))
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2024-12345"


# ---------------------------------------------------------------------------
# format_comment
# ---------------------------------------------------------------------------

class TestFormatComment:
    def test_header_contains_sha(self):
        result = ScanResult()
        comment = format_comment(result, "abc123fdeadbeef")
        assert "## Bot Review: abc123f" in comment

    def test_no_findings_shows_clean(self):
        result = ScanResult()
        comment = format_comment(result, "abc123f")
        assert "No security issues found" in comment
        assert "No CVEs" in comment

    def test_high_severity_shows_unchecked(self):
        result = ScanResult(bandit_findings=[make_finding(severity="HIGH")])
        comment = format_comment(result, "abc123f")
        assert "- [ ] B101" in comment

    def test_coverage_below_target_shows_warning(self):
        result = ScanResult(coverage_pct=61.0)
        comment = format_comment(result, "abc123f")
        assert "61.0%" in comment
        assert "target 80%" in comment

    def test_overall_line_present(self):
        result = ScanResult(
            bandit_findings=[make_finding(severity="MEDIUM")],
            coverage_pct=90.0,
        )
        comment = format_comment(result, "abc123f")
        assert "Overall:" in comment

    def test_fix_summary_shown_when_applied(self):
        result = ScanResult()
        comment = format_comment(result, "abc123f", fix_summary={"black": True, "autoflake": True})
        assert "Auto-fixes applied" in comment

    def test_flake8_capped_at_10(self):
        findings = [
            make_finding(scanner="flake8", rule_id="E501", severity="MEDIUM", title=f"issue {i}")
            for i in range(15)
        ]
        result = ScanResult(flake8_findings=findings)
        comment = format_comment(result, "abc123f")
        assert "5 more flake8 issues" in comment


# ---------------------------------------------------------------------------
# sample_app integration smoke-test (runs real bandit)
# ---------------------------------------------------------------------------

class TestSampleAppHasBugs:
    def test_bandit_finds_issues_in_sample_app(self):
        sample_path = os.path.join(os.path.dirname(__file__), "..", "sample_app")
        findings = run_bandit(os.path.abspath(sample_path))
        # sample_app deliberately contains B105, B101, B608, B602
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids, "bandit should find at least one issue in sample_app"
