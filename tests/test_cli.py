from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_cli_help_runs() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "mitiscan.py"), "--help"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 0
    assert "mitiscan" in res.stdout.lower()


def test_headless_requires_authorized() -> None:
    res = subprocess.run(
        [sys.executable, str(ROOT / "mitiscan.py"),
         "--headless", "example.com"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 2
    assert "authorized" in res.stderr.lower()
