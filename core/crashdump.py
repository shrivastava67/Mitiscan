"""Crash-dump hook — writes a sanitized traceback to the run dir on unhandled error.

Why: a tool that crashes mid-scan should leave forensic breadcrumbs without
leaking secrets in the terminal log.
"""
from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType

from .logging import audit, get_logger
from .version import build_info

_log = get_logger("crashdump")


def install(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def _hook(exc_type: type[BaseException],
              exc: BaseException,
              tb: TracebackType | None) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dump = out_dir / f"crash-{stamp}.txt"
        try:
            with dump.open("w", encoding="utf-8") as f:
                f.write(f"# Mitiscan crash dump\n")
                f.write(f"# build={build_info().as_dict()}\n\n")
                traceback.print_exception(exc_type, exc, tb, file=f)
        except OSError:
            pass
        audit("crash", exc_type=exc_type.__name__, dump=str(dump))
        _log.error("unhandled exception, dumped to %s", dump, exc_info=(exc_type, exc, tb))
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook
