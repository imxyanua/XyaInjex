import json

import pytest

from xyainjex import encode
from xyainjex.cli import main

SQL_T = "SELECT * FROM u WHERE n = '{INPUT}'"
SQL_P = "' OR 1=1 -- "


# --- core encode behaviour ---


def test_encode_includes_original_first():
    r = encode(SQL_P, lang="sql")
    assert r.variants[0].strategy == "original"
    assert r.variants[0].payload == SQL_P


def test_encode_unvalidated_without_template():
    r = encode(SQL_P, lang="sql")
    assert r.total == r.surviving  # nothing validated, so all "survive"
    assert all(v.validated is None for v in r.variants)


def test_encode_validates_against_template():
    r = encode(SQL_P, lang="sql", template=SQL_T)
    # Case folding and inline comments survive the SQL lexer.
    survivors = {v.strategy for v in r.variants if v.validated}
    assert "original" in survivors
    assert "case-lower" in survivors
    assert "sql-inline-comment" in survivors
    # Percent-encoding a SQL string literal does not.
    encoded = next(v for v in r.variants if v.strategy == "url-encode")
    assert encoded.validated is False


def test_encode_surviving_count_matches():
    r = encode(SQL_P, lang="sql", template=SQL_T)
    assert r.surviving == sum(1 for v in r.variants if v.validated)
    assert 0 < r.surviving < r.total


def test_encode_case_variants_carry_risk():
    r = encode(SQL_P, lang="sql", template=SQL_T)
    lower = next(v for v in r.variants if v.strategy == "case-lower")
    assert lower.validated is True
    assert lower.risk == "CRITICAL"


def test_encode_rejects_unsupported_lang():
    with pytest.raises(ValueError):
        encode("x", lang="prompt")


# --- result shape and CLI ---


def test_encode_to_dict():
    data = encode(SQL_P, lang="sql", template=SQL_T).to_dict()
    assert data["payload"] == SQL_P
    assert data["total"] >= 1
    assert "variants" in data
    assert data["variants"][0]["strategy"] == "original"


def test_cli_encode_json(capsys):
    code = main(["--lang", "sql", "--encode", "--json", SQL_T, SQL_P])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["surviving"] >= 1
    assert any(v["strategy"] == "sql-inline-comment" for v in data["variants"])


def test_cli_encode_text(capsys):
    code = main(["-l", "sql", "--encode", SQL_T, SQL_P])
    out = capsys.readouterr().out
    assert code == 0
    assert "payload encoder" in out.lower()
    assert "[ok]" in out


def test_cli_encode_requires_payload():
    with pytest.raises(SystemExit):
        main(["-l", "sql", "--encode", SQL_T])
