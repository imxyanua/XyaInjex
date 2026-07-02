from xyainjex import Context, SqlDialect, analyze_sql, parse_sql_dialect
from xyainjex.sql.balance import sql_balance
from xyainjex.sql.context import analyze_sql_context

# --- MSSQL bracket identifiers ---


def test_mssql_bracket_identifier_context():
    ctx = analyze_sql_context("SELECT [{INPUT}] FROM t", SqlDialect.MSSQL)
    assert ctx == Context.SQL_IDENTIFIER


def test_mssql_bracket_breakout():
    r = analyze_sql("SELECT [{INPUT}] FROM t", "col] WHERE 1=1 OR [x", SqlDialect.MSSQL)
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_mssql_bracket_balance():
    assert sql_balance("SELECT [col] FROM t", SqlDialect.MSSQL).syntax_valid
    assert not sql_balance("SELECT [col FROM t", SqlDialect.MSSQL).syntax_valid


def test_bracket_only_for_mssql():
    # In other dialects [ is an ordinary character, not an identifier quote.
    assert (
        analyze_sql_context("SELECT [{INPUT}]", SqlDialect.MYSQL) == Context.SQL_NUMERIC
    )


# --- PostgreSQL dollar-quoting ---


def test_postgres_dollar_quote_context():
    ctx = analyze_sql_context("DO $$ {INPUT} $$", SqlDialect.POSTGRES)
    assert ctx == Context.SQL_STRING


def test_postgres_tagged_dollar_quote_context():
    ctx = analyze_sql_context("DO $body$ {INPUT} $body$", SqlDialect.POSTGRES)
    assert ctx == Context.SQL_STRING


def test_postgres_dollar_breakout():
    r = analyze_sql(
        "DO $tag$ {INPUT} $tag$", "$tag$; DROP TABLE t; --", SqlDialect.POSTGRES
    )
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_postgres_positional_param_not_quote():
    # $1 is a bind parameter, not a dollar-quote opener.
    ctx = analyze_sql_context("WHERE id = $1 AND x = {INPUT}", SqlDialect.POSTGRES)
    assert ctx == Context.SQL_NUMERIC


def test_postgres_open_dollar_quote_unbalanced():
    assert not sql_balance("DO $$ body", SqlDialect.POSTGRES).syntax_valid


# --- Oracle q-quoting and comments ---


def test_oracle_qquote_context():
    ctx = analyze_sql_context("SELECT q'[{INPUT}]' FROM dual", SqlDialect.ORACLE)
    assert ctx == Context.SQL_STRING


def test_oracle_qquote_breakout():
    r = analyze_sql(
        "SELECT q'[{INPUT}]' FROM dual", "x]' OR 1=1 -- ", SqlDialect.ORACLE
    )
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_oracle_hash_is_literal():
    # Oracle has no # comment, so # inside a string stays data.
    r = analyze_sql("SELECT '{INPUT}'", "a#b", SqlDialect.ORACLE)
    assert r.context == Context.SQL_STRING
    assert r.risk.value == "LOW"


def test_mysql_hash_still_comment():
    r = analyze_sql(
        "SELECT * FROM t WHERE a = '{INPUT}'", "' OR 1=1#", SqlDialect.MYSQL
    )
    assert r.breakout.command_injected


# --- dialect parsing ---


def test_parse_oracle_aliases():
    assert parse_sql_dialect("oracle") == SqlDialect.ORACLE
    assert parse_sql_dialect("plsql") == SqlDialect.ORACLE
