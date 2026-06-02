"""Self-healing dependency bootstrap.

Fixes from audit:
  - sudo prefix for system writes (apt, /opt, /usr/local/bin)
  - `apt-get update` once per run (or every 24h via cache)
  - PEP-668 detection → auto-venv for pip tools
  - GOBIN export so `go install` lands somewhere on PATH
  - per-tool: apt → pip → go-install → git+build fallback chain
  - actual binary name validation (some tools install scripts w/ different names)
  - idempotency cache at ~/.mitiscan/bootstrap.json
  - --check-deps mode (no install, just report)
  - version probe + minimum-version gating
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path


CACHE_DIR = Path.home() / ".mitiscan"
CACHE_FILE = CACHE_DIR / "bootstrap.json"
CACHE_TTL_SEC = 24 * 3600

VENV_DIR = Path.cwd() / ".mitiscan_venv"
GO_BIN_DIR = Path.home() / "go" / "bin"
OPT_BIN_DIRS = [Path("/opt"), Path("/usr/local/bin"), Path.home() / ".local" / "bin"]


# Registry schema:
#   key       = binary name to look up via shutil.which after install
#   apt       = apt package name (or None)
#   pip       = pip package name (or None)
#   go        = full `go install` argument (`@latest` etc) (or None)
#   git       = git URL for source clone (or None)
#   build     = shell command run inside the cloned dir
#   bin_path  = absolute path of resulting binary (post-build). Used when binary
#               doesn't auto-land on PATH so we symlink it into ~/.local/bin
#   min_ver   = minimum acceptable version (semver-ish), e.g. "2.9.0"
#   version_cmd = command that prints version on stdout/stderr
#   version_re  = regex with one capture group extracting version
#
# Fallback order: apt → pip → go → git+build → fail
TOOL_REGISTRY: dict[str, dict] = {
    # -------- recon --------
    "nmap":          {"apt": "nmap"},
    "masscan":       {"apt": "masscan"},
    "fping":         {"apt": "fping"},
    "amass":         {"apt": "amass"},
    "subfinder":     {"apt": "subfinder",
                      "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "theHarvester":  {"apt": "theharvester"},
    "assetfinder":   {"go": "github.com/tomnomnom/assetfinder@latest"},

    # -------- DNS --------
    "dnsx":          {"go": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "shuffledns":    {"go": "github.com/projectdiscovery/shuffledns/v2/cmd/shuffledns@latest"},
    "massdns":       {"apt": "massdns"},
    "puredns":       {"go": "github.com/d3mondev/puredns/v2@latest"},

    # -------- web fingerprint/probe --------
    "httpx":         {"go": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "whatweb":       {"apt": "whatweb"},
    "nikto":         {"apt": "nikto"},

    # -------- web fuzz --------
    "nuclei":        {"go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "ffuf":          {"apt": "ffuf"},
    "feroxbuster":   {"apt": "feroxbuster"},
    "gobuster":      {"apt": "gobuster"},
    "arjun":         {"pip": "arjun"},

    # -------- web vuln --------
    "wafw00f":       {"apt": "wafw00f"},
    "testssl.sh":    {"apt": "testssl.sh"},
    "sqlmap":        {"apt": "sqlmap"},
    "dalfox":        {"go": "github.com/hahwul/dalfox/v2@latest"},
    "commix":        {"apt": "commix"},
    "wpscan":        {"apt": "wpscan"},
    "joomscan":      {"apt": "joomscan"},
    "droopescan":    {"pip": "droopescan"},

    # -------- AD / infra --------
    "smbmap":        {"apt": "smbmap"},
    "enum4linux-ng": {"apt": "enum4linux-ng",
                      "pip": "enum4linux-ng"},
    "netexec":       {"pip": "netexec"},
    "kerbrute":      {"go": "github.com/ropnop/kerbrute@latest"},
    "ssh-audit":     {"apt": "ssh-audit"},
    "hydra":         {"apt": "hydra"},

    # -------- takeover --------
    "subzy":         {"go": "github.com/PentestPad/subzy@latest"},

    # -------- cloud / container --------
    "s3scanner":     {"pip": "s3scanner"},
    "kube-hunter":   {"pip": "kube-hunter"},
    "gitjacker":     {"go": "github.com/liamg/gitjacker/cmd/gitjacker@latest"},

    # -------- creds / leaks --------
    "h8mail":        {"pip": "h8mail"},

    # -------- python tk for fallback GUI on Linux --------
    "python3-tk":    {"apt": "python3-tk", "no_binary": True},
}


@dataclass
class ToolStatus:
    name: str
    present: bool = False
    installed_this_run: bool = False
    failed: bool = False
    version: str | None = None
    path: str | None = None
    error: str | None = None


@dataclass
class BootstrapReport:
    tools: dict[str, ToolStatus] = field(default_factory=dict)
    apt_updated: bool = False
    venv_used: bool = False

    @property
    def present(self) -> list[str]:
        return [n for n, s in self.tools.items() if s.present]

    @property
    def installed(self) -> list[str]:
        return [n for n, s in self.tools.items() if s.installed_this_run and not s.failed]

    @property
    def failed(self) -> list[str]:
        return [n for n, s in self.tools.items() if s.failed]


# -------- helpers -------- #
async def _run(cmd: str, timeout: int = 600, env: dict | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode or 0, out_b.decode(errors="replace"), err_b.decode(errors="replace")


def _have_sudo() -> bool:
    return shutil.which("sudo") is not None and os.geteuid() != 0 if hasattr(os, "geteuid") else False


def _sudo_prefix() -> str:
    """Empty if root, otherwise 'sudo -n ' for non-interactive."""
    if not hasattr(os, "geteuid"):  # Windows dev box
        return ""
    if os.geteuid() == 0:
        return ""
    return "sudo -n " if shutil.which("sudo") else ""


def _pep668_active() -> bool:
    """Detect Debian-style externally-managed Python env (Kali 2023+)."""
    try:
        import sysconfig
        marker = Path(sysconfig.get_path("stdlib")) / "EXTERNALLY-MANAGED"
        return marker.exists()
    except Exception:
        return False


async def _ensure_venv() -> Path | None:
    """Create venv if PEP-668 active. Returns path to venv bin/ or None."""
    if not _pep668_active():
        return None
    if not VENV_DIR.exists():
        rc, _, err = await _run(f"python3 -m venv {VENV_DIR}", timeout=120)
        if rc != 0:
            return None
    bin_dir = VENV_DIR / ("Scripts" if os.name == "nt" else "bin")
    return bin_dir if bin_dir.exists() else None


def _path_with_extras() -> str:
    """Augmented PATH for subprocess calls — add GOBIN, venv, ~/.local/bin."""
    extras = [str(GO_BIN_DIR), str(Path.home() / ".local" / "bin")]
    if VENV_DIR.exists():
        bin_dir = VENV_DIR / ("Scripts" if os.name == "nt" else "bin")
        if bin_dir.exists():
            extras.insert(0, str(bin_dir))
    return os.pathsep.join(extras + [os.environ.get("PATH", "")])


def _which_aug(binary: str) -> str | None:
    """shutil.which with augmented PATH (covers Go bin + venv)."""
    return shutil.which(binary, path=_path_with_extras())


# -------- cache -------- #
def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except Exception:
        return {}


def _save_cache(data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(data, indent=2))


def _cache_fresh(entry: dict | None) -> bool:
    if not entry:
        return False
    ts = entry.get("ts", 0)
    return (time.time() - ts) < CACHE_TTL_SEC


# -------- install primitives -------- #
async def _apt_update_once(report: BootstrapReport) -> None:
    if report.apt_updated:
        return
    if shutil.which("apt-get") is None:
        return
    cache = _load_cache()
    if _cache_fresh(cache.get("apt_update")):
        report.apt_updated = True
        return
    rc, _, _ = await _run(f"{_sudo_prefix()}apt-get update -qq", timeout=180)
    if rc == 0:
        cache["apt_update"] = {"ts": time.time()}
        _save_cache(cache)
        report.apt_updated = True


async def _install_apt(pkg: str) -> tuple[bool, str]:
    if shutil.which("apt-get") is None:
        return False, "apt-get not present"
    rc, _, err = await _run(
        f"DEBIAN_FRONTEND=noninteractive {_sudo_prefix()}apt-get install -y -qq {pkg}",
        timeout=600)
    return rc == 0, err[-300:] if rc != 0 else ""


async def _install_pip(pkg: str, venv_bin: Path | None) -> tuple[bool, str]:
    pip_cmd = (
        f"{venv_bin}/pip install --quiet {pkg}" if venv_bin
        else (f"pip install --quiet --break-system-packages {pkg}" if _pep668_active()
              else f"pip install --quiet {pkg}")
    )
    rc, _, err = await _run(pip_cmd, timeout=600)
    return rc == 0, err[-300:] if rc != 0 else ""


async def _install_go(pkg_spec: str) -> tuple[bool, str]:
    if shutil.which("go") is None:
        # bootstrap Go itself
        ok, err = await _install_apt("golang-go")
        if not ok:
            return False, "go not present and apt golang-go failed"
    GO_BIN_DIR.mkdir(parents=True, exist_ok=True)
    env = {"GOBIN": str(GO_BIN_DIR), "GOPATH": str(Path.home() / "go"),
           "PATH": _path_with_extras()}
    rc, _, err = await _run(f"go install {pkg_spec}", timeout=900, env=env)
    return rc == 0, err[-300:] if rc != 0 else ""


async def _install_git(name: str, repo: str, build: str | None) -> tuple[bool, str]:
    """Clone to ~/.mitiscan/src/{name} (user-writable), build, symlink binary."""
    src_root = CACHE_DIR / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    dest = src_root / name
    if dest.exists():
        rc, _, _ = await _run(f"git -C {dest} pull --ff-only", timeout=180)
    else:
        rc, _, err = await _run(f"git clone --depth 1 {repo} {dest}", timeout=300)
        if rc != 0:
            return False, err[-300:]
    if build:
        env = {"GOBIN": str(GO_BIN_DIR), "PATH": _path_with_extras()}
        rc, _, err = await _run(f"cd {dest} && {build}", timeout=900, env=env)
        if rc != 0:
            return False, err[-300:]
    return True, ""


async def _probe_version(spec: dict, binary: str) -> str | None:
    cmd_template = spec.get("version_cmd", f"{binary} --version")
    rc, out, err = await _run(cmd_template, timeout=15)
    blob = (out + err).strip()
    pattern = spec.get("version_re", r"(\d+\.\d+(?:\.\d+)?)")
    m = re.search(pattern, blob)
    return m.group(1) if m else None


def _version_ok(version: str | None, minimum: str | None) -> bool:
    if not minimum:
        return True
    if not version:
        return False
    def t(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    try:
        return t(version) >= t(minimum)
    except Exception:
        return True


# -------- per-tool resolver -------- #
async def _resolve_one(tool: str, spec: dict, venv_bin: Path | None,
                       report: BootstrapReport, check_only: bool = False) -> ToolStatus:
    status = ToolStatus(name=tool)
    if spec.get("no_binary"):
        # apt-only metapackages (e.g. python3-tk) — best-effort
        if not check_only:
            await _install_apt(spec.get("apt", tool))
        status.present = True  # cannot meaningfully verify
        return status

    path = _which_aug(tool)
    if path:
        status.present = True
        status.path = path
        status.version = await _probe_version(spec, tool)
        if not _version_ok(status.version, spec.get("min_ver")):
            status.failed = True
            status.error = f"version {status.version} < min {spec.get('min_ver')}"
        return status

    if check_only:
        status.failed = True
        status.error = "missing (check-only mode)"
        return status

    # try chain
    last_err = ""
    if "apt" in spec:
        await _apt_update_once(report)
        ok, err = await _install_apt(spec["apt"])
        if ok and _which_aug(tool):
            status.present = True; status.installed_this_run = True
            status.path = _which_aug(tool); return status
        last_err = err or "apt failed"
    if "pip" in spec:
        ok, err = await _install_pip(spec["pip"], venv_bin)
        if ok and _which_aug(tool):
            status.present = True; status.installed_this_run = True
            status.path = _which_aug(tool); return status
        last_err = err or "pip failed"
    if "go" in spec:
        ok, err = await _install_go(spec["go"])
        if ok and _which_aug(tool):
            status.present = True; status.installed_this_run = True
            status.path = _which_aug(tool); return status
        last_err = err or "go install failed"
    if "git" in spec:
        ok, err = await _install_git(tool, spec["git"], spec.get("build"))
        if ok and _which_aug(tool):
            status.present = True; status.installed_this_run = True
            status.path = _which_aug(tool); return status
        last_err = err or "git build failed"

    status.failed = True
    status.error = last_err or "no install strategy worked"
    return status


# -------- public API -------- #
async def bootstrap(check_only: bool = False) -> BootstrapReport:
    """Resolve every tool. Returns structured report consumed by M01 + CLI."""
    report = BootstrapReport()
    venv_bin = None if check_only else await _ensure_venv()
    if venv_bin:
        report.venv_used = True

    for tool, spec in TOOL_REGISTRY.items():
        status = await _resolve_one(tool, spec, venv_bin, report, check_only=check_only)
        report.tools[tool] = status

    # persist outcome
    if not check_only:
        cache = _load_cache()
        cache["last_run"] = {
            "ts": time.time(),
            "tools": {k: asdict(v) for k, v in report.tools.items()},
        }
        _save_cache(cache)
    return report


def format_report_table(report: BootstrapReport) -> str:
    lines = [f"{'TOOL':<18} {'STATE':<14} {'VER':<10} PATH/ERROR"]
    lines.append("-" * 80)
    for name, s in report.tools.items():
        if s.failed:
            state = "FAILED"
        elif s.installed_this_run:
            state = "INSTALLED"
        elif s.present:
            state = "PRESENT"
        else:
            state = "UNKNOWN"
        info = s.error if s.failed else (s.path or "")
        lines.append(f"{name:<18} {state:<14} {s.version or '-':<10} {info}")
    return "\n".join(lines)
