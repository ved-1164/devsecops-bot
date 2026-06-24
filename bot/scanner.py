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
        medium_low = [f for f in self.bandit_findings if f.severity in ("MEDIUM", "LOW")]
        return len(medium_low) + len(self.flake8_findings)

    @property
    def failure_count(self) -> int:
        high_sast = [f for f in self.bandit_findings if f.severity in ("HIGH", "CRITICAL")]
        cov_fail = 1 if self.coverage_pct is not None and self.coverage_pct < 80.0 else 0
        return len(high_sast) + len(self.cve_findings) + cov_fail

    @property
    def has_failures(self) -> bool:
        return self.failure_count > 0


def _run(cmd: List[str], cwd: str = ".") -> Tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def run_bandit(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    _, stdout, _ = _run(["bandit", "-r", target_path, "-f", "json", "-q",
                          "--exclude", ".venv,node_modules,tests"])
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
        for r in data.get("results", []):
            findings.append(Finding(
                scanner="bandit",
                rule_id=r.get("test_id", ""),
                severity=r.get("issue_severity", "LOW").upper(),
                title=r.get("test_name", ""),
                file_path=r.get("filename", ""),
                line=r.get("line_number", 0),
                message=r.get("issue_text", ""),
            ))
    except (json.JSONDecodeError, KeyError):
        pass
    return findings


def run_flake8(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    _, stdout, _ = _run([
        "flake8", target_path,
        "--format=%(path)s:%(row)d:%(col)d: %(code)s %(text)s",
        "--exclude=.venv,node_modules,__pycache__",
    ])
    for line in stdout.strip().splitlines():
        m = re.match(r"^(.+?):(\d+):\d+: ([A-Z]\d+) (.+)$", line)
        if m:
            file_path, lineno, code, text = m.groups()
            findings.append(Finding(
                scanner="flake8",
                rule_id=code,
                severity="MEDIUM" if code.startswith("E") else "LOW",
                title=text,
                file_path=file_path,
                line=int(lineno),
                message=f"{code} {text}",
            ))
    return findings


def run_pylint(target_path: str) -> Tuple[List[Finding], Optional[float]]:
    findings: List[Finding] = []
    score: Optional[float] = None

    _, stdout, _ = _run(["pylint", target_path, "--output-format=json",
                          "--ignore=.venv,node_modules"])
    # pylint JSON output ends before the score line; extract JSON array
    json_match = re.search(r"(\[.*\])", stdout, re.DOTALL)
    if json_match:
        try:
            msgs = json.loads(json_match.group(1))
            severity_map = {
                "fatal": "CRITICAL",
                "error": "HIGH",
                "warning": "MEDIUM",
                "refactor": "LOW",
                "convention": "LOW",
                "info": "INFO",
            }
            for msg in msgs:
                findings.append(Finding(
                    scanner="pylint",
                    rule_id=msg.get("message-id", ""),
                    severity=severity_map.get(msg.get("type", "convention"), "LOW"),
                    title=msg.get("symbol", ""),
                    file_path=msg.get("path", ""),
                    line=msg.get("line", 0),
                    message=msg.get("message", ""),
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    # Run again in text mode to capture the score line
    _, stdout2, _ = _run(["pylint", target_path, "--output-format=text",
                           "--score=yes", "--ignore=.venv,node_modules"])
    m = re.search(r"rated at ([\d.]+)/10", stdout2)
    if m:
        score = float(m.group(1))

    return findings, score


def run_coverage(target_path: str) -> Optional[float]:
    _run(["pytest", "--cov=.", "--cov-report=json", "-q", "--tb=no"], cwd=target_path)

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

    # Fallback: parse pytest-cov text output from second run
    _, stdout, _ = _run(["pytest", "--cov=.", "--cov-report=term-missing",
                          "-q", "--tb=no"], cwd=target_path)
    m = re.search(r"TOTAL\s+\d+\s+\d+\s+([\d.]+)%", stdout)
    if m:
        return float(m.group(1))

    return None


def run_jscpd(target_path: str) -> Optional[float]:
    report_dir = os.path.join(target_path, ".jscpd-report")
    os.makedirs(report_dir, exist_ok=True)

    _run([
        "jscpd", target_path,
        "--reporters", "json",
        "--output", report_dir,
        "--ignore", "**/.git/**,**/node_modules/**,**/__pycache__/**,**/.venv/**",
        "--min-lines", "5",
        "--silent",
    ])

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


def run_safety(target_path: str) -> List[Finding]:
    findings: List[Finding] = []
    req_file = os.path.join(target_path, "requirements.txt")
    if not os.path.exists(req_file):
        return findings

    _, stdout, _ = _run(["safety", "check", "-r", req_file, "--json", "--output", "json"])
    if not stdout.strip():
        # Try without --output flag (older safety)
        _, stdout, _ = _run(["safety", "check", "-r", req_file, "--json"])

    if not stdout.strip():
        return findings

    try:
        data = json.loads(stdout)

        # safety 2.x: list of [package, spec, version, advisory, vuln_id]
        if isinstance(data, list):
            for vuln in data:
                if isinstance(vuln, list) and len(vuln) >= 4:
                    findings.append(Finding(
                        scanner="safety",
                        rule_id=vuln[4] if len(vuln) > 4 else "UNKNOWN",
                        severity="HIGH",
                        title=f"{vuln[0]} {vuln[2]} has known vulnerability",
                        file_path="requirements.txt",
                        message=str(vuln[3])[:200],
                    ))

        # safety 3.x: {"vulnerabilities": [...]}
        elif isinstance(data, dict):
            for v in data.get("vulnerabilities", []):
                findings.append(Finding(
                    scanner="safety",
                    rule_id=v.get("vulnerability_id", "UNKNOWN"),
                    severity="HIGH",
                    title=f"{v.get('package_name', '')} {v.get('analyzed_version', '')} vulnerable",
                    file_path="requirements.txt",
                    message=v.get("advisory", "")[:200],
                ))

    except (json.JSONDecodeError, TypeError):
        pass

    return findings


def scan(target_path: str) -> ScanResult:
    result = ScanResult()
    result.bandit_findings = run_bandit(target_path)
    result.flake8_findings = run_flake8(target_path)
    result.pylint_findings, result.pylint_score = run_pylint(target_path)
    result.coverage_pct = run_coverage(target_path)
    result.duplication_pct = run_jscpd(target_path)
    result.cve_findings = run_safety(target_path)
    return result
