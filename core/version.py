"""Single source of truth for project version + build metadata."""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__", "BuildInfo", "build_info"]

try:
    __version__: str = version("mitiscan")
except PackageNotFoundError:  # editable / source checkout w/o install
    __version__ = "0.1.0.dev0"


@dataclass(frozen=True)
class BuildInfo:
    version: str
    python: str
    platform: str
    git_sha: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "version": self.version,
            "python": self.python,
            "platform": self.platform,
            "git_sha": self.git_sha,
        }


def _git_sha() -> str | None:
    sha = os.environ.get("MITISCAN_GIT_SHA") or os.environ.get("GIT_SHA")
    if sha:
        return sha[:12]
    # Best-effort read from .git/HEAD (no subprocess — safer in containers)
    from pathlib import Path
    here = Path(__file__).resolve().parent.parent
    head = here / ".git" / "HEAD"
    try:
        ref = head.read_text(encoding="utf-8").strip()
        if ref.startswith("ref:"):
            ref_path = here / ".git" / ref.split(" ", 1)[1]
            return ref_path.read_text(encoding="utf-8").strip()[:12]
        return ref[:12]
    except OSError:
        return None


def build_info() -> BuildInfo:
    return BuildInfo(
        version=__version__,
        python=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        platform=f"{platform.system()}-{platform.release()}-{platform.machine()}",
        git_sha=_git_sha(),
    )
