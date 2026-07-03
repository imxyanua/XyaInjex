import json

from xyainjex import Context, analyze_ldap, mutate_ldap
from xyainjex.cli import main
from xyainjex.ldap.balance import ldap_balance
from xyainjex.ldap.context import analyze_ldap_context

TMPL = "(&(uid={INPUT})(objectClass=person))"


# --- context ---


def test_ldap_context():
    assert analyze_ldap_context(TMPL) == Context.LDAP_FILTER


# --- balance ---


def test_balanced_filter():
    assert ldap_balance("(&(uid=x)(objectClass=person))").syntax_valid


def test_unbalanced_filter():
    b = ldap_balance("(&(uid=x)")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("()") == 1


# --- breakout ---


def test_benign_value_no_breakout():
    r = analyze_ldap(TMPL, "john")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_wildcard_is_medium():
    r = analyze_ldap(TMPL, "*")
    assert not r.breakout.command_injected
    assert "*" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_close_open_breakout():
    r = analyze_ldap(TMPL, "*)(uid=*")
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_tautology_breakout():
    r = analyze_ldap(TMPL, "*)(uid=*))(|(uid=*")
    assert r.breakout.command_injected
    assert "|" in r.breakout.separators


def test_escaped_metachar_is_literal():
    # A backslash-escaped '*' (\2a) is data, not a wildcard.
    r = analyze_ldap(TMPL, "\\2a")
    assert not r.breakout.command_injected
    assert "*" not in r.breakout.separators
    assert r.risk.value == "LOW"


def test_operator_injection():
    r = analyze_ldap(TMPL, "x)(&(password=*")
    assert r.breakout.command_injected


# --- mutation ---


def test_mutate_finds_candidates():
    result = mutate_ldap(TMPL)
    assert result.context == Context.LDAP_FILTER
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_ldap(TMPL, "*)(uid=*").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "ldap_filter"


def test_cli_ldap_json(capsys):
    code = main(["--lang", "ldap", "--json", TMPL, "*)(uid=*"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_ldap_mutate(capsys):
    code = main(["-l", "ldap", "--mutate", TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
