"""Module result + state enums."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class State(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"


@dataclass
class ModuleResult:
    module_id: int
    name: str
    state: State = State.PENDING
    findings: list[dict] = field(default_factory=list)
    raw_artifacts: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)

    @property
    def has_renderable(self) -> bool:
        """Reporter gates section rendering on this."""
        return self.state == State.COMPLETED and len(self.findings) > 0

    @property
    def duration_sec(self) -> float:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 2)
        return 0.0
