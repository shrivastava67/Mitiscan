"""Structured logging — JSON lines to disk, human format to console.

Why: enterprise SOCs ingest JSONL; humans want readable terminals.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["configure", "get_logger", "audit"]


_AUDIT_LOGGER = "mitiscan.audit"
_REDACT_KEYS = {"password", "token", "secret", "authorization", "cookie",
                "api_key", "apikey", "x-api-key"}


class JsonFormatter(logging.Formatter):
    """RFC 5424-ish JSON formatter. One line per record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "pid": record.process,
        }
        # Carry through structured fields users attach via `extra={...}`.
        for k, v in record.__dict__.items():
            if k in ("args", "msg", "levelname", "levelno", "pathname",
                     "filename", "module", "exc_info", "exc_text", "stack_info",
                     "lineno", "funcName", "created", "msecs", "relativeCreated",
                     "thread", "threadName", "processName", "process", "name",
                     "taskName"):
                continue
            payload[k] = _redact(k, v)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _redact(key: str, value: Any) -> Any:
    if isinstance(key, str) and key.lower() in _REDACT_KEYS:
        return "***REDACTED***"
    if isinstance(value, dict):
        return {k: _redact(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(key, v) for v in value]
    return value


def configure(out_dir: Path | None = None, level: str = "INFO") -> None:
    """Idempotent root config. Call once at startup.

    Console: human-readable. File (if out_dir): JSONL rotating.
    """
    root = logging.getLogger()
    # Tear down prior Mitiscan handlers so reconfigure (eg. tests) works.
    for h in list(root.handlers):
        if getattr(h, "_mitiscan", False):
            root.removeHandler(h)
    audit_log = logging.getLogger(_AUDIT_LOGGER)
    for h in list(audit_log.handlers):
        if getattr(h, "_mitiscan", False):
            audit_log.removeHandler(h)

    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S"))
    console._mitiscan = True   # type: ignore[attr-defined]
    root.addHandler(console)

    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        rot = logging.handlers.RotatingFileHandler(
            out_dir / "mitiscan.jsonl",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        rot.setFormatter(JsonFormatter())
        rot._mitiscan = True   # type: ignore[attr-defined]
        root.addHandler(rot)

        # Separate, append-only-style audit log for security-relevant events.
        audit_h = logging.handlers.RotatingFileHandler(
            out_dir / "audit.jsonl",
            maxBytes=10 * 1024 * 1024,
            backupCount=20,
            encoding="utf-8",
        )
        audit_h.setFormatter(JsonFormatter())
        audit_h.setLevel(logging.INFO)
        audit_h._mitiscan = True   # type: ignore[attr-defined]
        audit_log.addHandler(audit_h)
        audit_log.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"mitiscan.{name}" if not name.startswith("mitiscan") else name)


def audit(event: str, **fields: Any) -> None:
    """Write a security-relevant event.

    Examples
    --------
    >>> audit("scan.start", target="example.com", profile="BALANCED", user=os.getlogin())
    >>> audit("scan.authorized", target="example.com", source="cli")
    >>> audit("module.failed", module_id=7, reason="timeout")
    """
    fields.setdefault("user", os.environ.get("USER") or os.environ.get("USERNAME"))
    logging.getLogger(_AUDIT_LOGGER).info(event, extra={"event": event, **fields})
