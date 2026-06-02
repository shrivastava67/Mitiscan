"""Adaptive evasion config — WAF-aware throttle every module respects."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EvasionProfile(str, Enum):
    STEALTH = "STEALTH"
    BALANCED = "BALANCED"
    AGGRESSIVE = "AGGRESSIVE"


@dataclass
class EvasionConfig:
    profile: EvasionProfile = EvasionProfile.BALANCED
    base_delay: float = 0.0           # sec between subprocess invocations
    max_threads: int = 20
    rate_limit_qps: int = 5000
    waf_detected: bool = False
    consecutive_429: int = 0
    consecutive_403: int = 0
    latency_baseline_ms: float = 0.0

    def apply_profile(self, profile: EvasionProfile) -> None:
        self.profile = profile
        if profile == EvasionProfile.STEALTH:
            self.base_delay = 1.5
            self.max_threads = 4
            self.rate_limit_qps = 50
        elif profile == EvasionProfile.BALANCED:
            self.base_delay = 0.3
            self.max_threads = 20
            self.rate_limit_qps = 1000
        else:
            self.base_delay = 0.0
            self.max_threads = 100
            self.rate_limit_qps = 10000

    def adjust_from_signal(self, status_code: int | None, latency_ms: float | None) -> None:
        """Module 33 hooks here — adaptive backoff."""
        if status_code == 429:
            self.consecutive_429 += 1
            self.base_delay = min(self.base_delay + 0.5, 10.0)
            self.rate_limit_qps = max(self.rate_limit_qps // 2, 50)
        elif status_code == 403:
            self.consecutive_403 += 1
            if self.consecutive_403 >= 3:
                self.waf_detected = True
        else:
            self.consecutive_429 = max(self.consecutive_429 - 1, 0)
        if latency_ms and self.latency_baseline_ms:
            if latency_ms > 2 * self.latency_baseline_ms:
                self.base_delay = min(self.base_delay + 0.2, 10.0)
            elif latency_ms < 0.5 * self.latency_baseline_ms and self.base_delay > 0:
                self.base_delay = max(self.base_delay - 0.1, 0.0)
