import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    file_path: str = ""
    line: int = 0
    message: str = ""


@dataclass
class ScanResult:
    bandit_findings: List[Finding] = field(default_factory=list)
    flake8_findings: List[Finding] = field(default_factory=list)
    pylint_findings: List[Finding] = field(default_factory=list)
    pylint_score: Optional[float] = None
    coverage_pct: Optional[float] = None
    duplication_pct: Optional[float] = None
    cve_findings: List[Finding] = field(default_factory=list)

    @property
    def warning_count(self) -> int:
        medium_low = [
            f for f in self.bandit_findings if f.severity in ("MEDIUM", "LOW")
        ]
        return len(medium_low) + len(self.flake8_findings)

    @property
    def failure_count(self) -> int:
        high_sast = [
            f for f in self.bandit_findings if f.severity in ("HIGH", "CRITICAL")
        ]
        cov_fail = (
            1 if self.coverage_pct is not None and self.coverage_pct < 80.0 else 0
        )
        return len(high_sast) + len(self.cve_findings) + cov_fail

    @property
    def has_failures(self) -> bool:
        return self.failure_count > 0


def _run(cmd: List[str], cwd: str = ".") -> Tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def _tool_available(name: str) -> bool:
    import shutil

    return shutil.which(name) is not None


def _normalize_path(path: str) -> str:
    """Return path relative to cwd for cleaner PR comment output."""
    if not path:
        return path
    try:
        rel = os.path.relpath(path)
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return path


# ---------------------------------------------------------------------------
# SAST — bandit
# ---------------------------------------------------------------------------


def run_bandit(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    if not _tool_available("bandit"):
        return findings

    _, stdout, _ = _run(
        [
            "bandit",
            "-r",
            target_path,
            "-f",
            "json",
            "-q",
            "--exclude",
            ".venv,node_modules,tests",
        ],
    )
    if not stdout.strip():
        return findings

    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            findings.append(
                Finding(
                    scanner="bandit",
                    rule_id=r.get("test_id", ""),
                    severity=r.get("issue_severity", "LOW").upper(),
                    title=r.get("test_name", ""),
                    file_path=_normalize_path(r.get("filename", "")),
                    line=r.get("line_number", 0),
                    message=r.get("issue_text", ""),
                )
            )
    except (json.JSONDecodeError, KeyError):
        pass

    return findings


# ---------------------------------------------------------------------------
# Lint — flake8
# ---------------------------------------------------------------------------


def run_flake8(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    if not _tool_available("flake8"):
        return findings

    _, stdout, _ = _run(
        [
            "flake8",
            target_path,
            "--format=%(path)s:%(row)d:%(col)d: %(code)s %(text)s",
            "--exclude=.venv,node_modules,__pycache__",
        ]
    )

    for line in stdout.strip().splitlines():
        m = re.match(r"^(.+?):(\d+):\d+: ([A-Z]\d+) (.+)$", line)
        if m:
            file_path, lineno, code, text = m.groups()
            findings.append(
                Finding(
                    scanner="flake8",
                    rule_id=code,
                    severity="MEDIUM" if code.startswith("E") else "LOW",
                    title=text,
                    file_path=_normalize_path(file_path),
                    line=int(lineno),
                    message=f"{code} {text}",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Quality — pylint (single subprocess call)
# ---------------------------------------------------------------------------


def run_pylint(target_path: str) -> Tuple[List[Finding], Optional[float]]:
    findings: List[Finding] = []
    score: Optional[float] = None

    if not _tool_available("pylint"):
        return findings, score

    # json2 format (pylint >= 2.13) returns score + messages in one JSON object
    _, stdout, _ = _run(
        [
            "pylint",
            target_path,
            "--output-format=json2",
            "--score=yes",
            "--ignore=.venv,node_modules",
        ]
    )

    try:
        data = json.loads(stdout)
        score = data.get("statistics", {}).get("score")

        severity_map = {
            "fatal": "CRITICAL",
            "error": "HIGH",
            "warning": "MEDIUM",
            "refactor": "LOW",
            "convention": "LOW",
            "info": "INFO",
        }
        for msg in data.get("messages", []):
            findings.append(
                Finding(
                    scanner="pylint",
                    rule_id=msg.get("message-id", ""),
                    severity=severity_map.get(msg.get("type", "convention"), "LOW"),
                    title=msg.get("symbol", ""),
                    file_path=_normalize_path(msg.get("path", "")),
                    line=msg.get("line", 0),
                    message=msg.get("message", ""),
                )
            )
    except (json.JSONDecodeError, TypeError, KeyError):
        pass

    return findings, score


# ---------------------------------------------------------------------------
# Coverage — pytest-cov (single subprocess call)
# ---------------------------------------------------------------------------


def run_coverage(target_path: str) -> Optional[float]:
    if not _tool_available("pytest"):
        return None

    _run(
        [
            "pytest",
            "--cov=.",
            "--cov-report=json",
            "--cov-report=term-missing",
            "-q",
            "--tb=no",
        ],
        cwd=target_path,
    )

    cov_file = os.path.join(target_path, "coverage.json")
    if os.path.exists(cov_file):
        try:
            with open(cov_file) as f:
                data = json.load(f)
            pct = data.get("totals", {}).get("percent_covered")
            if pct is not None:
                return round(float(pct), 1)
        except (json.JSONDecodeError, KeyError, OSError):
            pass

    return None


# ---------------------------------------------------------------------------
# Duplication — jscpd (optional, requires Node.js)
# ---------------------------------------------------------------------------


def run_jscpd(target_path: str) -> Optional[float]:
    if not _tool_available("jscpd"):
        return None

    report_dir = os.path.join(target_path, ".jscpd-report")
    os.makedirs(report_dir, exist_ok=True)

    _run(
        [
            "jscpd",
            target_path,
            "--reporters",
            "json",
            "--output",
            report_dir,
            "--ignore",
            "**/.git/**,**/node_modules/**,**/__pycache__/**,**/.venv/**",
            "--min-lines",
            "5",
            "--silent",
        ]
    )

    report_file = os.path.join(report_dir, "jscpd-report.json")
    if os.path.exists(report_file):
        try:
            with open(report_file) as f:
                data = json.load(f)
            pct = data.get("statistics", {}).get("total", {}).get("percentage")
            if pct is not None:
                return round(float(pct), 1)
        except (json.JSONDecodeError, KeyError, OSError):
            pass

    return None


# ---------------------------------------------------------------------------
# CVE — pip-audit (primary) with safety fallback
# ---------------------------------------------------------------------------


def _run_pip_audit(req_file: str) -> List[Finding]:
    findings: List[Finding] = []
    _, stdout, _ = _run(
        ["pip-audit", "-r", req_file, "-f", "json", "--progress-spinner", "off"]
    )
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_id = next(
                    (a for a in aliases if a.startswith("CVE-")),
                    vuln.get("id", "UNKNOWN"),
                )
                findings.append(
                    Finding(
                        scanner="pip-audit",
                        rule_id=cve_id,
                        severity="HIGH",
                        title=f"{dep['name']} {dep['version']} has known vulnerability",
                        file_path="requirements.txt",
                        message=vuln.get("description", "")[:200],
                    )
                )
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    return findings


def _run_safety(req_file: str) -> List[Finding]:
    findings: List[Finding] = []
    _, stdout, _ = _run(["safety", "check", "-r", req_file, "--json"])
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
        # safety 2.x: list of [package, spec, version, advisory, vuln_id]
        if isinstance(data, list):
            for vuln in data:
                if isinstance(vuln, list) and len(vuln) >= 4:
                    findings.append(
                        Finding(
                            scanner="safety",
                            rule_id=vuln[4] if len(vuln) > 4 else "UNKNOWN",
                            severity="HIGH",
                            title=f"{vuln[0]} {vuln[2]} has known vulnerability",
                            file_path="requirements.txt",
                            message=str(vuln[3])[:200],
                        )
                    )
        # safety 3.x: {"vulnerabilities": [...]}
        elif isinstance(data, dict):
            for v in data.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        scanner="safety",
                        rule_id=v.get("vulnerability_id", "UNKNOWN"),
                        severity="HIGH",
                        title=f"{v.get('package_name', '')} {v.get('analyzed_version', '')} vulnerable",
                        file_path="requirements.txt",
                        message=v.get("advisory", "")[:200],
                    )
                )
    except (json.JSONDecodeError, TypeError):
        pass
    return findings


def run_safety(target_path: str) -> List[Finding]:
    """Scan requirements.txt for CVEs using pip-audit (primary) or safety (fallback)."""
    req_file = os.path.join(target_path, "requirements.txt")
    if not os.path.exists(req_file):
        return []

    if _tool_available("pip-audit"):
        return _run_pip_audit(req_file)

    if _tool_available("safety"):
        return _run_safety(req_file)

    return []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def scan(target_path: str) -> ScanResult:
    result = ScanResult()
    result.bandit_findings = run_bandit(target_path)
    result.flake8_findings = run_flake8(target_path)
    result.pylint_findings, result.pylint_score = run_pylint(target_path)
    result.coverage_pct = run_coverage(target_path)
    result.duplication_pct = run_jscpd(target_path)
    result.cve_findings = run_safety(target_path)
    return result
