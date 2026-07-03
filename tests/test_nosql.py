import json

from xyainjex import Context, analyze_nosql, mutate_nosql
from xyainjex.cli import main
from xyainjex.nosql.balance import nosql_balance
from xyainjex.nosql.context import analyze_nosql_context

STRING_TMPL = '{"user": "{INPUT}", "pass": "x"}'
VALUE_TMPL = '{"age": {INPUT}}'


# --- context ---


def test_string_context():
    assert analyze_nosql_context(STRING_TMPL) == Context.NOSQL_STRING


def test_value_context():
    assert analyze_nosql_context(VALUE_TMPL) == Context.NOSQL_VALUE


# --- balance ---


def test_balanced_document():
    assert nosql_balance('{"user": "x"}').syntax_valid


def test_unterminated_string():
    b = nosql_balance('{"user": "x}')
    assert not b.syntax_valid
    assert b.double_quote_open


def test_unbalanced_object():
    b = nosql_balance('{"user": {"$ne": null}')
    assert b.unbalanced_pairs.get("{}") == 1


# --- breakout ---


def test_benign_string_value():
    r = analyze_nosql(STRING_TMPL, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_operator_via_string_breakout():
    r = analyze_nosql(STRING_TMPL, '", "$ne": "')
    assert r.context == Context.NOSQL_STRING
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert "$ne" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_or_tautology_breakout():
    r = analyze_nosql(STRING_TMPL, '", "$or": [{}], "x": "')
    assert r.breakout.command_injected


def test_where_js_breakout():
    r = analyze_nosql(STRING_TMPL, '", "$where": "1==1", "x": "')
    assert "$where" in r.breakout.separators
    assert r.breakout.command_injected


def test_value_position_operator():
    r = analyze_nosql(VALUE_TMPL, '{"$gt": 0}')
    assert r.context == Context.NOSQL_VALUE
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_value_position_plain_number():
    r = analyze_nosql(VALUE_TMPL, "42")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_string_with_no_operator_no_breakout():
    r = analyze_nosql(STRING_TMPL, "no operators here")
    assert not r.breakout.command_injected


# --- mutation ---


def test_mutate_string_context():
    result = mutate_nosql(STRING_TMPL)
    assert result.context == Context.NOSQL_STRING
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_value_context():
    result = mutate_nosql(VALUE_TMPL)
    assert result.context == Context.NOSQL_VALUE
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_nosql(STRING_TMPL, '", "$ne": "').to_dict()
    assert data["dialect"] is None
    assert data["context"] == "nosql_string"


def test_cli_nosql_json(capsys):
    code = main(["--lang", "nosql", "--json", STRING_TMPL, '", "$ne": "'])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_nosql_mutate(capsys):
    code = main(["-l", "nosql", "--mutate", VALUE_TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
