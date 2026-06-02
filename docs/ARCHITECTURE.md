# Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Entrypoint: mitiscan.py                                             │
│   - CLI parse, deps bootstrap, mode dispatch                        │
└────────────┬────────────────────────────────────────────────────────┘
             │
   ┌─────────┴─────────┐
   ▼                   ▼
[GUI: gui.app]    [Headless: core.engine.Engine]
                       │
                       ▼
                ┌──────────────┐    ┌────────────────────┐
                │ scope.Scope  │ →  │ safety.is_in_scope │
                └──────────────┘    └────────────────────┘
                       │
                       ▼
                ┌──────────────────────────────────────────┐
                │ DAG of module coroutines (modules.py)    │
                │  - parallel per stage                    │
                │  - soft_timeout → SIGTERM → SIGKILL      │
                │  - per-module checkpoint (resume safe)   │
                └──────────────────────────────────────────┘
                       │
                       ▼
                ┌──────────────────────────────────────────┐
                │ Reporter (Jinja2 templates)              │
                │  - HTML / Markdown / JSON / PDF          │
                │  - NIST SP 800-115 + OWASP mapping       │
                │  - conditional purge of empty modules    │
                └──────────────────────────────────────────┘
                       │
                       ▼
                mitiscan_outputs/<run_id>/
                  ├── report.html|md|json|pdf
                  ├── mitiscan.jsonl   (structured log)
                  ├── audit.jsonl      (security events)
                  └── authorization.txt
```

## Core packages

| Package      | Responsibility                                                |
|--------------|---------------------------------------------------------------|
| `core.engine`     | Async orchestration. Module DAG, checkpoint, resume.    |
| `core.bootstrap`  | Self-healing OS-package + Python-package installer.     |
| `core.scope`      | Target dataclass, intake parsing.                       |
| `core.safety`     | Deny-list, RFC-1918 guard, target normalization.        |
| `core.evasion`    | Throttle profile (STEALTH / BALANCED / AGGRESSIVE).     |
| `core.reporter`   | Jinja2 conditional rendering.                           |
| `core.result`     | `ModuleResult`, `State`, normalized finding dict.       |
| `core.logging`    | JSONL log + secret-redacted audit trail.                |
| `core.errors`     | Typed exception tree.                                   |
| `core.version`    | `__version__`, build info, git SHA discovery.           |
| `core.crashdump`  | `sys.excepthook` that writes sanitized dumps.           |
| `modules.modules` | 35 scanner coroutines.                                  |
| `gui.app`         | customtkinter frontend, live state, authorization gate. |

## Concurrency model

- Engine drives an `asyncio` event loop.
- Each module is a coroutine returning `ModuleResult`.
- Stages run sequentially; modules within a stage run with `asyncio.gather`.
  STEALTH profile collapses to sequential everything.
- External tools spawn via `asyncio.create_subprocess_exec`. Soft timeout
  sends `SIGTERM`; hard timeout escalates to `SIGKILL`.
- Engine deduplicates URLs and findings globally via
  `engine.seen_urls` + normalized `(title, target)` key.

## Resume semantics

- Each module writes `<run_id>/checkpoint.json` on completion.
- `--resume <run_id>` skips modules whose checkpoint exists. Partial output
  is preserved.

## Reporting pipeline

1. Engine emits `list[ModuleResult]`.
2. Reporter purges entries with `state != COMPLETED` and zero findings.
3. Findings deduplicated, mapped to CVE/CWE/CVSS where known.
4. Jinja2 renders `templates/report.html.j2` → HTML.
5. HTML → PDF via WeasyPrint (optional, gracefully skipped if missing).
6. Markdown + JSON parallel emits.

## Extensibility

Adding a module:

```python
# modules/modules.py
async def m36_new_thing(ctx: ModuleCtx) -> ModuleResult:
    ...
```

Register it in `Engine` stage map. Add a test in `tests/modules/`.
