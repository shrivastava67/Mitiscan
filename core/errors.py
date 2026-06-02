"""Typed exceptions for Mitiscan.

Why: callers can branch on type instead of substring-matching messages.
"""
from __future__ import annotations

__all__ = [
    "MitiscanError",
    "ConfigError",
    "AuthorizationError",
    "DependencyError",
    "ScopeError",
    "ModuleError",
    "TimeoutError",
    "ReportError",
]


class MitiscanError(Exception):
    """Root for all Mitiscan-raised errors."""


class ConfigError(MitiscanError):
    """Invalid configuration, profile, or runtime parameter."""


class AuthorizationError(MitiscanError):
    """Caller did not assert written authorization to test the target."""


class DependencyError(MitiscanError):
    """A required external tool or Python package is missing or broken."""


class ScopeError(MitiscanError):
    """Target is malformed, out of policy, or in a deny-listed range."""


class ModuleError(MitiscanError):
    """A scanner module failed in a recoverable, reportable way."""


class TimeoutError(MitiscanError):  # noqa: A001 - intentionally shadow builtin
    """Module exceeded its soft/hard timeout budget."""


class ReportError(MitiscanError):
    """Report rendering or artifact write failed."""
