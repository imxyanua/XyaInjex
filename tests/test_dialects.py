import pytest

from xyainjex import Dialect, analyze, parse_dialect
from xyainjex.dialects import get_spec


def test_parse_dialect_aliases():
    assert parse_dialect("bash") == Dialect.POSIX
    assert parse_dialect("sh") == Dialect.POSIX
    assert parse_dialect("CMD") == Dialect.CMD
    assert parse_dialect("bat") == Dialect.CMD
    assert parse_dialect("pwsh") == Dialect.POWERSHELL
    assert parse_dialect("powershell") == Dialect.POWERSHELL


def test_parse_dialect_unknown_raises():
    with pytest.raises(ValueError):
        parse_dialect("fortran")


def test_default_dialect_is_posix():
    result = analyze('curl "{INPUT}"', '"; id ; #')
    assert result.dialect == Dialect.POSIX


def test_result_dict_includes_dialect():
    data = analyze("ping {INPUT}", "& whoami", Dialect.CMD).to_dict()
    assert data["dialect"] == "cmd"


def test_spec_comment_support():
    assert get_spec(Dialect.POSIX).supports_comment
    assert not get_spec(Dialect.CMD).supports_comment
    assert get_spec(Dialect.POWERSHELL).supports_comment
