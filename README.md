# DevSecOps Bot

A Python bot that runs on every pull request to enforce code quality, security, and dependency safety — then posts a single structured comment with all findings.

## What it does

| Check | Tool | Blocks merge? |
|---|---|---|
| SAST (security issues) | bandit | Yes — HIGH/CRITICAL |
| Lint | flake8 | No — warning only |
| Code quality score | pylint | No — warning only |
| Test coverage | pytest-cov | Yes — below 80% |
| Code duplication | jscpd | No — warning only |
| Dependency CVEs | pip-audit | Yes — any CVE |

On every PR the bot also:
- Runs **black** + **autoflake** and commits the fixes back to the branch automatically
- Nightly at 02:00 UTC, scans `requirements.txt` for CVEs and opens a fix PR if any are found

## PR Comment Example

```
## Bot Review: abc123f

> Auto-fixes applied: autoflake, black

### Security (bandit)
- [ ] B602 subprocess call with shell=True -- sample_app/app.py:25
- [ ] B608 Possible SQL injection -- sample_app/app.py:18
- [x] No high-severity issues

### Code Quality
- [ ] E501 line too long (118 > 100 characters) -- sample_app/app.py:37
- [x] Pylint: 8.9/10

### Coverage: 61.0% (target 80%)
### Duplication: 2.1% (OK)
### Dependencies: No CVEs

**Overall: Warnings 10 | Failures 2**
```

## Architecture

```
GitHub PR / Push / Schedule
        |
        v
  GitHub Actions Workflow
        |
        v
  Python Bot (bot/main.py)
    |-- scanner.py   bandit · flake8 · pylint · pytest-cov · jscpd · pip-audit
    |-- fixer.py     black · autoflake  (commits fixes back to branch)
    |-- reporter.py  aggregates all findings → single PR comment
    +-- github_api.py  PyGitHub — post comment · create CVE fix PR
```

## Setup

### 1. Fork or clone this repo into your GitHub account

```bash
git clone https://github.com/ved-1164/devsecops-bot.git
cd devsecops-bot
```

### 2. No secrets needed for basic operation

The workflows use the built-in `GITHUB_TOKEN` — no additional configuration required.

### 3. Open a pull request to trigger the PR scan

Create a branch, push a change, open a PR. The **DevSecOps Bot — PR Scan** workflow fires automatically.

### 4. Nightly CVE scan

The **DevSecOps Bot — Nightly CVE Scan** runs at 02:00 UTC every day. Trigger it manually anytime from the **Actions** tab → select the workflow → **Run workflow**.

## Local development

```bash
# Install dependencies
pip install -r requirements.txt

# Install jscpd (requires Node.js)
npm install -g jscpd

# Run the test suite
pytest tests/ -v

# Run a live scan against sample_app
python - <<'EOF'
from bot.scanner import scan
from bot.reporter import format_comment
result = scan("sample_app")
print(format_comment(result, "local-run"))
EOF
```

## Demo: CVE detection

`sample_app/requirements.txt` contains intentionally outdated packages with known CVEs:

```
requests==2.18.0   # CVE-2018-18074 and others
Pillow==9.0.0      # multiple CVEs
```

To see the CVE scanner in action locally:

```bash
pip-audit -r sample_app/requirements.txt
```

## Project structure

```
devsecops-bot/
├── .github/workflows/
│   ├── pr-scan.yml          # triggers on PR open/push
│   └── nightly-cve.yml      # runs at 02:00 UTC daily
├── bot/
│   ├── scanner.py           # all scan logic
│   ├── fixer.py             # black + autoflake auto-fix
│   ├── reporter.py          # PR comment formatter
│   ├── github_api.py        # PyGitHub interactions
│   └── main.py              # CLI entry point
├── tests/
│   └── test_scanner.py      # 23 unit tests
├── sample_app/
│   ├── app.py               # intentional bugs for demo
│   └── requirements.txt     # vulnerable packages for CVE demo
├── requirements.txt
└── setup.cfg                # flake8 / pylint / pytest config
```

## Configuration

Edit `setup.cfg` to tune thresholds:

```ini
[flake8]
max-line-length = 100          # change line length limit

[tool:pytest]
testpaths = tests              # where pytest looks for tests
```

Coverage target (80%) and duplication threshold (5%) are constants at the top of `bot/reporter.py`.

