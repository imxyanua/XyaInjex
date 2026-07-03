import json

from xyainjex import Context, analyze_xpath, mutate_xpath
from xyainjex.cli import main
from xyainjex.xpath.balance import xpath_balance
from xyainjex.xpath.context import analyze_xpath_context

STRING_TMPL = "//user[name = '{INPUT}']"
EXPR_TMPL = "//user[position() = {INPUT}]"


# --- context ---


def test_string_context():
    assert analyze_xpath_context(STRING_TMPL) == Context.XPATH_STRING


def test_expression_context():
    assert analyze_xpath_context(EXPR_TMPL) == Context.XPATH_EXPRESSION


def test_double_quote_string_context():
    assert analyze_xpath_context('//user[name = "{INPUT}"]') == Context.XPATH_STRING


# --- balance ---


def test_balanced_expression():
    assert xpath_balance("//user[name = 'x']").syntax_valid


def test_unbalanced_string():
    b = xpath_balance("//user[name = 'x")
    assert not b.syntax_valid
    assert b.single_quote_open


def test_unbalanced_predicate():
    b = xpath_balance("//user[name = 'x'")
    assert b.unbalanced_pairs.get("[]") == 1


# --- breakout ---


def test_boolean_tautology_breakout():
    r = analyze_xpath(STRING_TMPL, "' or '1'='1")
    assert r.context == Context.XPATH_STRING
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert "or" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_and_breakout():
    r = analyze_xpath(STRING_TMPL, "' and '1'='2")
    assert r.breakout.command_injected
    assert "and" in r.breakout.separators


def test_node_union_breakout():
    r = analyze_xpath(STRING_TMPL, "']|//password|//x['")
    assert r.breakout.command_injected
    assert "|" in r.breakout.separators


def test_expression_position_breakout():
    r = analyze_xpath(EXPR_TMPL, "1 or 1=1")
    assert r.context == Context.XPATH_EXPRESSION
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_plain_value_no_breakout():
    r = analyze_xpath(STRING_TMPL, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_quote_closed_without_logic_is_medium():
    r = analyze_xpath(STRING_TMPL, "x' ")
    assert r.breakout.quote_closed
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_suffix_bracket_not_counted_as_injection():
    # The template's own trailing ] must not be attributed to a benign payload.
    r = analyze_xpath(STRING_TMPL, "bob")
    assert not r.breakout.command_injected


# --- mutation ---


def test_mutate_string_context():
    result = mutate_xpath(STRING_TMPL)
    assert result.context == Context.XPATH_STRING
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_expression_context():
    result = mutate_xpath(EXPR_TMPL)
    assert result.context == Context.XPATH_EXPRESSION
    assert result.valid > 0


# --- result shape ---


def test_result_dialect_is_null():
    data = analyze_xpath(STRING_TMPL, "' or '1'='1").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "xpath_string"


# --- CLI ---


def test_cli_xpath_json(capsys):
    code = main(["--lang", "xpath", "--json", STRING_TMPL, "' or '1'='1"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_xpath_mutate(capsys):
    code = main(["-l", "xpath", "--mutate", STRING_TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
