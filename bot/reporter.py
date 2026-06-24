from typing import Dict, Optional

from bot.scanner import ScanResult

COVERAGE_TARGET = 80.0
DUPLICATION_THRESHOLD = 5.0


def format_comment(
    result: ScanResult,
    commit_sha: str,
    fix_summary: Optional[Dict[str, bool]] = None,
) -> str:
    short_sha = commit_sha[:7] if len(commit_sha) >= 7 else commit_sha
    lines = [f"## Bot Review: {short_sha}", ""]

    # Auto-fix summary banner
    if fix_summary:
        applied = [k for k, v in fix_summary.items() if v]
        if applied:
            lines.append(f"> Auto-fixes applied: {', '.join(applied)}")
            lines.append("")

    # --- Security (bandit) ---
    lines.append("### Security (bandit)")
    if result.bandit_findings:
        high = [f for f in result.bandit_findings if f.severity in ("HIGH", "CRITICAL")]
        others = [f for f in result.bandit_findings if f.severity not in ("HIGH", "CRITICAL")]
        for f in high:
            loc = f" -- {f.file_path}:{f.line}" if f.file_path else ""
            lines.append(f"- [ ] {f.rule_id} {f.message}{loc}")
        for f in others:
            loc = f" -- {f.file_path}:{f.line}" if f.file_path else ""
            lines.append(f"- [ ] {f.rule_id} {f.message}{loc}")
        if not high:
            lines.append("- [x] No high-severity issues")
    else:
        lines.append("- [x] No security issues found")
    lines.append("")

    # --- Code Quality (flake8 + pylint) ---
    lines.append("### Code Quality")
    if result.flake8_findings:
        cap = 10
        for f in result.flake8_findings[:cap]:
            loc = f" -- {f.file_path}:{f.line}" if f.file_path else ""
            lines.append(f"- [ ] {f.rule_id} {f.title}{loc}")
        if len(result.flake8_findings) > cap:
            lines.append(f"- [ ] ...and {len(result.flake8_findings) - cap} more flake8 issues")
    else:
        lines.append("- [x] No flake8 issues")

    if result.pylint_score is not None:
        ok = result.pylint_score >= 7.0
        marker = "x" if ok else " "
        lines.append(f"- [{marker}] Pylint: {result.pylint_score:.1f}/10")
    lines.append("")

    # --- Coverage ---
    if result.coverage_pct is not None:
        cov_ok = result.coverage_pct >= COVERAGE_TARGET
        status = "(OK)" if cov_ok else f"(target {COVERAGE_TARGET:.0f}%)"
        lines.append(f"### Coverage: {result.coverage_pct:.1f}% {status}")
    else:
        lines.append("### Coverage: N/A (no tests found or pytest failed)")

    # --- Duplication ---
    if result.duplication_pct is not None:
        dup_ok = result.duplication_pct <= DUPLICATION_THRESHOLD
        status = "(OK)" if dup_ok else f"(threshold {DUPLICATION_THRESHOLD:.0f}%)"
        lines.append(f"### Duplication: {result.duplication_pct:.1f}% {status}")
    else:
        lines.append("### Duplication: N/A (jscpd not available)")

    # --- Dependencies ---
    if result.cve_findings:
        lines.append(f"### Dependencies: {len(result.cve_findings)} CVE(s) found")
        for f in result.cve_findings:
            lines.append(f"- [ ] {f.rule_id}: {f.title}")
    else:
        lines.append("### Dependencies: No CVEs")

    lines.append("")
    lines.append(f"**Overall: Warnings {result.warning_count} | Failures {result.failure_count}**")

    return "\n".join(lines)
