#!/usr/bin/env python3
"""Entry point for the DevSecOps Bot.

Usage (called by GitHub Actions):
    python -m bot.main scan          # PR scan + auto-fix + comment
    python -m bot.main nightly-cve   # Nightly CVE scan + fix PR
"""

import os
import sys


def run_pr_scan() -> None:
    from bot.fixer import apply_fixes
    from bot.github_api import commit_auto_fixes, post_pr_comment
    from bot.reporter import format_comment
    from bot.scanner import scan

    token = os.environ["GITHUB_TOKEN"]
    repo_name = os.environ["REPO_NAME"]
    pr_number = int(os.environ["PR_NUMBER"])
    commit_sha = os.environ.get("COMMIT_SHA", "unknown")
    branch = os.environ.get("GITHUB_HEAD_REF", "")

    print("==> Applying safe auto-fixes (black + autoflake)...")
    fix_summary = apply_fixes(".")

    if any(fix_summary.values()) and branch:
        print("==> Committing auto-fixes to branch...")
        try:
            commit_auto_fixes(branch)
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: could not commit fixes: {exc}")

    print("==> Running security & quality scan...")
    result = scan(".")

    print("==> Formatting PR comment...")
    comment = format_comment(result, commit_sha, fix_summary)
    print(comment)

    print("==> Posting PR comment...")
    post_pr_comment(token, repo_name, pr_number, comment)

    print(
        f"\nScan complete — Warnings: {result.warning_count} | "
        f"Failures: {result.failure_count}"
    )

    import json as _json
    report = {
        "warnings": result.warning_count,
        "failures": result.failure_count,
        "high_severity_count": len([f for f in result.bandit_findings if f.severity in ("HIGH", "CRITICAL")]),
        "cve_count": len(result.cve_findings),
        "coverage_pct": result.coverage_pct,
        "blocked": result.has_failures,
    }
    with open("scan-report.json", "w") as _f:
        _json.dump(report, _f, indent=2)
    print("==> Scan report written to scan-report.json")


def run_nightly_cve() -> None:
    from bot.github_api import create_cve_fix_pr
    from bot.scanner import run_safety

    token = os.environ["GITHUB_TOKEN"]
    repo_name = os.environ["REPO_NAME"]

    print("==> Running nightly CVE scan...")
    cves = run_safety(".")

    if cves:
        print(f"==> Found {len(cves)} CVE(s). Opening fix PR...")
        pr_url = create_cve_fix_pr(token, repo_name, cves)
        if pr_url:
            print(f"Fix PR created: {pr_url}")
        else:
            print("Fix PR already exists or could not be created.")
    else:
        print("No CVEs found in requirements.txt.")


COMMANDS = {
    "scan": run_pr_scan,
    "nightly-cve": run_nightly_cve,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd not in COMMANDS:
        print(f"Unknown command '{cmd}'. Available: {', '.join(COMMANDS)}")
        sys.exit(1)
    COMMANDS[cmd]()
