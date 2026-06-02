from __future__ import annotations

import core.errors as e


def test_hierarchy() -> None:
    for cls in (e.ConfigError, e.AuthorizationError, e.DependencyError,
                e.ScopeError, e.ModuleError, e.TimeoutError, e.ReportError):
        assert issubclass(cls, e.MitiscanError)
        assert issubclass(cls, Exception)
