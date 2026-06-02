"""Mitiscan async orchestration engine.

Enhancements wired:
  #5  PATH aug — every subprocess sees GOBIN + venv + ~/.local/bin
  #7  global URL dedup set (engine.seen_urls)
  #11 checkpoint — results.json flushed after every module
  #12 parallel DAG — modules grouped by stage; intra-stage runs concurrently
  #13 soft_timeout — module may register a soft cancel handler
  #15 authorization.txt receipt (written by GUI before engine starts)

Module function signature unchanged: `async def m_xx(engine) -> ModuleResult`.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Awaitable, Callable

from .evasion import EvasionConfig, EvasionProfile
from .result import ModuleResult, State
from .scope import Scope


StatusCb = Callable[[int, State, str], None]
LogCb = Callable[[str], None]


# Module DAG — modules within the same stage run concurrently when profile != STEALTH.
# Stages chosen so downstream inputs are satisfied by upstream completions.
STAGES: list[list[int]] = [
    [1],                                            # bootstrap
    [2],                                            # passive OSINT
    [3, 4, 5],                                      # active DNS + revdns + leaks
    [6],                                            # live host
    [7],                                            # port scan (gates everything below)
    [8, 9, 10, 11, 12, 13, 14, 15, 29, 30, 32],     # broad infra fan-out, web filter, cloud, container, iot
    [16, 26, 31],                                   # web fingerprint + takeover + git
    [17, 19, 27],                                   # dir fuzz, API audit, nuclei
    [18, 24, 25],                                   # param fuzz + CMS + auth
    [20, 21, 22, 23],                               # web vuln exploitation
    [28],                                           # credential brute
    [33, 34],                                       # evasion telemetry + post-ex sim
    [35],                                           # consolidation
]


class Engine:
    def __init__(
        self,
        target: str,
        output_root: Path,
        profile: EvasionProfile = EvasionProfile.BALANCED,
        status_cb: StatusCb | None = None,
        log_cb: LogCb | None = None,
        resume_run_id: str | None = None,
    ) -> None:
        self.scope = Scope(raw_target=target)
        self.scope.classify()
        self.evasion = EvasionConfig()
        self.evasion.apply_profile(profile)

        if resume_run_id:
            self.run_id = resume_run_id
            self.out_dir = output_root / f"mitiscan_outputs_{self.run_id}"
        else:
            self.run_id = uuid.uuid4().hex[:8]
            self.out_dir = output_root / f"mitiscan_outputs_{self.run_id}"
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.results: dict[int, ModuleResult] = {}
        self._status_cb: StatusCb = status_cb or (lambda *a: None)
        self._log_cb: LogCb = log_cb or (lambda *a: None)

        # ENH #7 global dedup for HTTP requests across modules
        self.seen_urls: set[str] = set()

        # late import to avoid circular
        from modules.modules import build_module_list
        self.modules: list[tuple[int, str, Callable[[Engine], Awaitable[ModuleResult]]]] = (
            build_module_list()
        )
        self._fn_by_id = {mid: fn for mid, _, fn in self.modules}
        for mid, name, _ in self.modules:
            self.results[mid] = ModuleResult(module_id=mid, name=name)

        if resume_run_id:
            self._restore_results()

    # ---------- PATH-augmented subprocess ---------- #
    def _augmented_env(self) -> dict[str, str]:
        extras = [
            str(Path.home() / "go" / "bin"),
            str(Path.home() / ".local" / "bin"),
            str(Path.cwd() / ".mitiscan_venv" / ("Scripts" if os.name == "nt" else "bin")),
        ]
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(extras + [env.get("PATH", "")])
        return env

    async def run_cmd(self, cmd: str, module_id: int, timeout: int = 600,
                      soft_timeout: int | None = None) -> tuple[int, str, str]:
        """Run shell command respecting evasion delay + augmented PATH.

        soft_timeout: if set, sends SIGTERM at soft_timeout then waits up to
        (timeout - soft_timeout) for graceful shutdown before SIGKILL.
        """
        if self.evasion.base_delay:
            await asyncio.sleep(self.evasion.base_delay)
        self.log(f"[M{module_id:02d}] $ {cmd}")
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=self._augmented_env(),
            )
        except FileNotFoundError as e:
            return 127, "", str(e)

        try:
            if soft_timeout:
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(), timeout=soft_timeout)
                except asyncio.TimeoutError:
                    proc.terminate()
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(), timeout=max(timeout - soft_timeout, 5))
            else:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, "", "timeout"

        elapsed_ms = (time.time() - start) * 1000
        self.evasion.adjust_from_signal(None, elapsed_ms)
        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")
        if stdout:
            self.log(stdout[-2000:])
        if stderr and proc.returncode != 0:
            self.log(f"[M{module_id:02d} stderr] {stderr[-500:]}")
        return proc.returncode or 0, stdout, stderr

    # ---------- URL dedup ---------- #
    def see(self, url: str) -> bool:
        """Returns True if URL was already seen → caller may skip request."""
        if url in self.seen_urls:
            return True
        self.seen_urls.add(url)
        return False

    # ---------- logging / state ---------- #
    def log(self, msg: str) -> None:
        try:
            self._log_cb(msg)
        except Exception:
            pass

    def set_state(self, mid: int, state: State, reason: str = "") -> None:
        self.results[mid].state = state
        if reason:
            self.results[mid].skip_reason = reason
        try:
            self._status_cb(mid, state, reason)
        except Exception:
            pass

    # ---------- checkpoint ---------- #
    def _checkpoint(self) -> None:
        try:
            (self.out_dir / "results.json").write_text(
                json.dumps(
                    {str(k): asdict(v) for k, v in self.results.items()},
                    default=str, indent=2,
                ),
                encoding="utf-8",
            )
        except Exception as e:
            self.log(f"[checkpoint failed] {e!r}")

    def _restore_results(self) -> None:
        ck = self.out_dir / "results.json"
        if not ck.exists():
            return
        try:
            raw = json.loads(ck.read_text())
            for mid_str, data in raw.items():
                mid = int(mid_str)
                if mid not in self.results:
                    continue
                r = self.results[mid]
                r.state = State(data.get("state", "PENDING"))
                r.findings = data.get("findings", [])
                r.raw_artifacts = data.get("raw_artifacts", [])
                r.skip_reason = data.get("skip_reason")
                r.started_at = data.get("started_at")
                r.finished_at = data.get("finished_at")
                r.cves = data.get("cves", [])
                r.cwes = data.get("cwes", [])
        except Exception as e:
            self.log(f"[resume failed — starting fresh] {e!r}")

    # ---------- module driver ---------- #
    async def _drive(self, mid: int) -> None:
        r = self.results[mid]
        if r.state == State.COMPLETED:
            self.log(f"[M{mid:02d}] resume — already COMPLETED, skipping")
            self._status_cb(mid, r.state, r.skip_reason or "")
            return
        r.started_at = time.time()
        self.set_state(mid, State.RUNNING)
        fn = self._fn_by_id[mid]
        try:
            produced = await fn(self)
            if produced is not None:
                self.results[mid] = produced
        except Exception as exc:
            self.results[mid].state = State.FAILED
            self.results[mid].skip_reason = f"exception: {exc!r}"
            self.log(f"[M{mid:02d} FAILED] {exc!r}")
        r = self.results[mid]
        r.finished_at = time.time()
        self._status_cb(mid, r.state, r.skip_reason or "")
        self._checkpoint()

    # ---------- main loop (parallel DAG) ---------- #
    async def run(self) -> dict[int, ModuleResult]:
        self.log(f"[engine] run_id={self.run_id} target={self.scope.raw_target} "
                 f"profile={self.evasion.profile.value} out={self.out_dir}")
        if shutil.which("nmap") is None:
            self.log("[engine] WARNING — nmap not on PATH. M01 bootstrap will attempt install.")

        sequential = self.evasion.profile == EvasionProfile.STEALTH
        for stage in STAGES:
            if sequential or len(stage) == 1:
                for mid in stage:
                    await self._drive(mid)
            else:
                # bounded concurrency w/in stage
                sem = asyncio.Semaphore(min(len(stage), self.evasion.max_threads))

                async def _bounded(mid_: int) -> None:
                    async with sem:
                        await self._drive(mid_)

                await asyncio.gather(*(_bounded(m) for m in stage))

        self._checkpoint()
        return self.results

    # ---------- helpers used by modules ---------- #
    def skip(self, mid: int, reason: str, na: bool = False) -> ModuleResult:
        r = self.results[mid]
        r.state = State.NOT_APPLICABLE if na else State.SKIPPED
        r.skip_reason = reason
        return r

    def done(
        self,
        mid: int,
        findings: list[dict],
        artifacts: list[str] | None = None,
        cves: list[str] | None = None,
        cwes: list[str] | None = None,
    ) -> ModuleResult:
        r = self.results[mid]
        r.state = State.COMPLETED
        r.findings = findings
        r.raw_artifacts = artifacts or []
        r.cves = cves or []
        r.cwes = cwes or []
        return r

    def artifact_path(self, mid: int, name: str) -> Path:
        d = self.out_dir / f"M{mid:02d}"
        d.mkdir(exist_ok=True)
        return d / name
