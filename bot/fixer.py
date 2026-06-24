import subprocess
from typing import Dict, List, Tuple


def _run(cmd: List[str], cwd: str = ".") -> Tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def fix_formatting(target_path: str) -> bool:
    """Run black to reformat Python files in-place."""
    rc, _, _ = _run(
        [
            "black",
            target_path,
            "--quiet",
            "--exclude",
            r"\.venv|node_modules|__pycache__",
        ]
    )
    return rc == 0


def fix_imports(target_path: str) -> bool:
    """Remove unused imports and variables with autoflake."""
    rc, _, _ = _run(
        [
            "autoflake",
            "--in-place",
            "--recursive",
            "--remove-unused-variables",
            "--remove-all-unused-imports",
            "--exclude",
            ".venv,node_modules,__pycache__",
            target_path,
        ]
    )
    return rc == 0


def apply_fixes(target_path: str) -> Dict[str, bool]:
    """Apply all safe auto-fixes and return a per-tool success map."""
    # Order matters: clean imports first, then reformat
    autoflake_ok = fix_imports(target_path)
    black_ok = fix_formatting(target_path)
    return {"autoflake": autoflake_ok, "black": black_ok}
