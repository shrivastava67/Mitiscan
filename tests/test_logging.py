from __future__ import annotations

import json
from pathlib import Path

from core.logging import audit, configure, get_logger


def _read_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text("utf-8").splitlines() if line]


def test_configure_writes_jsonl(tmp_run_dir: Path) -> None:
    configure(tmp_run_dir, level="DEBUG")
    log = get_logger("test")
    log.info("hello", extra={"k": "v"})
    rec = _read_jsonl(tmp_run_dir / "mitiscan.jsonl")
    assert any(r["msg"] == "hello" and r.get("k") == "v" for r in rec)


def test_audit_redacts_secrets(tmp_run_dir: Path) -> None:
    configure(tmp_run_dir, level="INFO")
    audit("login", user="bob", password="hunter2", token="abc")
    rec = _read_jsonl(tmp_run_dir / "audit.jsonl")
    last = rec[-1]
    assert last["password"] == "***REDACTED***"
    assert last["token"] == "***REDACTED***"
    assert last["user"] == "bob"
