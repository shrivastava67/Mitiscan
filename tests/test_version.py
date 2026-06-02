from __future__ import annotations

from core.version import __version__, build_info


def test_version_is_string() -> None:
    assert isinstance(__version__, str)
    assert __version__


def test_build_info_shape() -> None:
    info = build_info().as_dict()
    assert set(info) == {"version", "python", "platform", "git_sha"}
    assert info["version"] == __version__
    assert info["python"].count(".") == 2
