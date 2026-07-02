import json

from xyainjex import Context, SqlDialect, analyze_sql, mutate_sql, parse_sql_dialect
from xyainjex.cli import main
from xyainjex.sql.balance import sql_balance
from xyainjex.sql.context import analyze_sql_context

STRING_TMPL = "SELECT * FROM users WHERE name = '{INPUT}'"
NUMERIC_TMPL = "SELECT * FROM users WHERE id = {INPUT}"


# --- context ---


def test_string_context():
    assert analyze_sql_context(STRING_TMPL) == Context.SQL_STRING


def test_numeric_context():
    assert analyze_sql_context(NUMERIC_TMPL) == Context.SQL_NUMERIC


def test_mysql_double_quote_is_string():
    assert (
        analyze_sql_context('... a = "{INPUT}"', SqlDialect.MYSQL) == Context.SQL_STRING
    )


def test_postgres_double_quote_is_identifier():
    assert (
        analyze_sql_context('... a = "{INPUT}"', SqlDialect.POSTGRES)
        == Context.SQL_IDENTIFIER
    )


def test_backtick_identifier_context():
    assert analyze_sql_context("SELECT `{INPUT}` FROM t") == Context.SQL_IDENTIFIER


# --- balance ---


def test_balanced_string():
    assert sql_balance("SELECT * FROM t WHERE a = 'x'").syntax_valid


def test_unbalanced_string():
    b = sql_balance("SELECT * FROM t WHERE a = 'x")
    assert not b.syntax_valid
    assert b.single_quote_open


def test_doubled_quote_stays_balanced():
    # '' is an escaped quote, not two string boundaries.
    assert sql_balance("SELECT 'O''Brien'").syntax_valid


def test_open_block_comment_unbalanced():
    b = sql_balance("SELECT 1 /* comment")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("/* */") == 1


def test_unbalanced_parens():
    b = sql_balance("SELECT * FROM (t")
    assert b.unbalanced_pairs.get("()") == 1


# --- breakout ---


def test_boolean_breakout_with_comment():
    r = analyze_sql(STRING_TMPL, "' OR 1=1 -- ")
    assert r.context == Context.SQL_STRING
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.breakout.comment_terminated
    assert "OR" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_boolean_breakout_balanced_without_comment():
    r = analyze_sql(STRING_TMPL, "' OR '1'='1")
    assert r.breakout.command_injected
    assert r.balance.syntax_valid
    assert r.risk.value == "CRITICAL"


def test_numeric_breakout():
    r = analyze_sql(NUMERIC_TMPL, "1 OR 1=1")
    assert r.context == Context.SQL_NUMERIC
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_stacked_query_breakout():
    r = analyze_sql(STRING_TMPL, "'; DROP TABLE users -- ")
    assert ";" in r.breakout.separators
    assert "DROP" in r.breakout.separators
    assert r.breakout.command_injected


def test_union_breakout():
    r = analyze_sql(STRING_TMPL, "' UNION SELECT NULL,NULL -- ")
    assert "UNION" in r.breakout.separators
    assert r.breakout.command_injected


def test_plain_value_no_breakout():
    r = analyze_sql(STRING_TMPL, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_numeric_plain_no_breakout():
    r = analyze_sql(NUMERIC_TMPL, "5")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_quote_closed_without_code_is_medium():
    # Escapes the string but injects no SQL keyword, no comment; the trailing
    # template quote leaves the statement unbalanced.
    r = analyze_sql(STRING_TMPL, "x' ")
    assert r.breakout.quote_closed
    assert not r.breakout.command_injected


def test_high_risk_when_unbalanced():
    r = analyze_sql(STRING_TMPL, "' OR 1=1")
    assert r.breakout.command_injected
    assert not r.balance.syntax_valid
    assert r.risk.value == "HIGH"


# --- mutation ---


def test_mutate_string_context():
    result = mutate_sql(STRING_TMPL)
    assert result.context == Context.SQL_STRING
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_numeric_context():
    result = mutate_sql(NUMERIC_TMPL)
    assert result.context == Context.SQL_NUMERIC
    assert result.valid > 0


def test_mutate_dict_shape():
    data = mutate_sql(STRING_TMPL).to_dict()
    assert data["dialect"] == "mysql"
    assert isinstance(data["high_probability"], list)


# --- dialect parsing ---


def test_parse_sql_dialect_aliases():
    assert parse_sql_dialect("mariadb") == SqlDialect.MYSQL
    assert parse_sql_dialect("postgresql") == SqlDialect.POSTGRES
    assert parse_sql_dialect("sqlserver") == SqlDialect.MSSQL


def test_result_dict_includes_sql_dialect():
    data = analyze_sql(STRING_TMPL, "' OR 1=1 -- ").to_dict()
    assert data["dialect"] == "mysql"
    assert data["context"] == "sql_string"


# --- CLI ---


def test_cli_sql_json(capsys):
    code = main(["--lang", "sql", "--json", STRING_TMPL, "' OR 1=1 -- "])
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "mysql"
    assert data["risk"] == "CRITICAL"
    assert code == 2


def test_cli_sql_dialect_postgres(capsys):
    code = main(
        ["-l", "sql", "-d", "postgres", "--json", '... a = "{INPUT}"', '" OR 1=1 -- ']
    )
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "postgres"
    assert data["context"] == "sql_identifier"
    assert code == 2


def test_cli_sql_mutate(capsys):
    code = main(["--lang", "sql", "--mutate", STRING_TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out


def test_cli_bad_lang():
    import pytest

    with pytest.raises(SystemExit):
        main(["--lang", "cobol", STRING_TMPL, "x"])
