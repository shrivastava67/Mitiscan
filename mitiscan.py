#!/usr/bin/env python3
"""Mitiscan entrypoint.

Modes:
  mitiscan.py                      # launch GUI
  mitiscan.py --check-deps         # dry-run dependency audit (no install)
  mitiscan.py --bootstrap          # actually install missing tools
  mitiscan.py --headless <target>  # run a scan without GUI
  mitiscan.py --resume <run_id>    # resume an interrupted scan
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mitiscan", description="Automated VAPT platform")
    p.add_argument("--check-deps", action="store_true",
                   help="audit dependencies without installing (ENH #1)")
    p.add_argument("--bootstrap", action="store_true",
                   help="install missing dependencies and exit")
    p.add_argument("--headless", metavar="TARGET",
                   help="run a scan without launching the GUI")
    p.add_argument("--profile", default="BALANCED",
                   choices=["STEALTH", "BALANCED", "AGGRESSIVE"])
    p.add_argument("--resume", metavar="RUN_ID",
                   help="resume an interrupted scan by its run id (ENH #11)")
    p.add_argument("--authorized", action="store_true",
                   help="confirm authorization (required for headless runs)")
    return p


async def _do_bootstrap(check_only: bool) -> int:
    from core.bootstrap import bootstrap, format_report_table
    rep = await bootstrap(check_only=check_only)
    print(format_report_table(rep))
    print()
    print(f"Present:   {len(rep.present)}")
    print(f"Installed: {len(rep.installed)}")
    print(f"Failed:    {len(rep.failed)}")
    return 0 if not rep.failed else 1


async def _do_headless(target: str, profile_name: str, resume: str | None) -> int:
    from core.engine import Engine
    from core.evasion import EvasionProfile
    from core.reporter import Reporter

    def status_cb(mid, state, reason):
        print(f"  M{mid:02d} {state.value:<16} {reason}")

    def log_cb(msg):
        print(msg)

    engine = Engine(target, Path("./mitiscan_outputs"),
                    profile=EvasionProfile(profile_name),
                    status_cb=status_cb, log_cb=log_cb,
                    resume_run_id=resume)
    # authorization receipt for headless
    (engine.out_dir / "authorization.txt").write_text(
        f"Target: {target}\nProfile: {profile_name}\n"
        f"User passed --authorized at launch.\n")

    results = await engine.run()
    reporter = Reporter(results, engine.out_dir, target, engine.run_id,
                        ROOT / "templates")
    paths = reporter.render_all()
    for k, p in paths.items():
        print(f"[reporter] {k.upper():<5} {p}")
    return 0


def main() -> None:
    args = _cli().parse_args()

    if args.check_deps:
        sys.exit(asyncio.run(_do_bootstrap(check_only=True)))
    if args.bootstrap:
        sys.exit(asyncio.run(_do_bootstrap(check_only=False)))
    if args.headless:
        if not args.authorized:
            print("error: --headless requires --authorized "
                  "(confirms written permission to test the target)",
                  file=sys.stderr)
            sys.exit(2)
        sys.exit(asyncio.run(
            _do_headless(args.headless, args.profile, args.resume)))

    # default: GUI
    from gui.app import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
