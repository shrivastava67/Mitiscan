from __future__ import annotations

import pytest

from core.errors import ScopeError
from core.safety import is_in_scope, normalize_target


@pytest.mark.parametrize("raw, expected", [
    ("https://Example.COM/path", "example.com"),
    ("  http://foo.bar  ", "foo.bar"),
    ("8.8.8.8", "8.8.8.8"),
    ("8.8.8.0/24", "8.8.8.0/24"),
    ("foo.bar:8080", "foo.bar"),
])
def test_normalize_target_ok(raw: str, expected: str) -> None:
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", "not a host!", "..", "-foo.bar"])
def test_normalize_target_rejects(bad: str) -> None:
    with pytest.raises(ScopeError):
        normalize_target(bad)


def test_scope_denies_loopback() -> None:
    d = is_in_scope("127.0.0.1")
    assert not d.allowed
    assert "deny" in d.reason


def test_scope_denies_private_by_default() -> None:
    d = is_in_scope("10.0.0.5")
    assert not d.allowed
    assert "private" in d.reason.lower()


def test_scope_allows_private_with_override() -> None:
    d = is_in_scope("10.0.0.5", allow_private=True)
    assert d.allowed


def test_scope_allows_public_ip() -> None:
    d = is_in_scope("8.8.8.8")
    assert d.allowed


def test_scope_allows_hostname() -> None:
    d = is_in_scope("example.com")
    assert d.allowed
