import json

from xyainjex import Context, analyze_graphql, mutate_graphql
from xyainjex.cli import main
from xyainjex.graphql.balance import graphql_balance
from xyainjex.graphql.context import analyze_graphql_context

STRING = '{ user(name: "{INPUT}") { id } }'
ARG = "{ user(id: {INPUT}) { id } }"


# --- context ---


def test_string_context():
    assert analyze_graphql_context(STRING) == Context.GQL_STRING


def test_arg_context():
    assert analyze_graphql_context(ARG) == Context.GQL_ARG


# --- balance ---


def test_balanced_query():
    assert graphql_balance("{ user { id } }").syntax_valid


def test_unbalanced_braces():
    b = graphql_balance("{ user { id }")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("{}") == 1


def test_unterminated_string():
    assert not graphql_balance('{ user(name: "x) { id } }').syntax_valid


# --- breakout ---


def test_benign_string():
    r = analyze_graphql(STRING, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_string_field_injection():
    r = analyze_graphql(STRING, '") { id password }')
    assert r.context == Context.GQL_STRING
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_arg_field_injection():
    r = analyze_graphql(ARG, "1) { id password }")
    assert r.context == Context.GQL_ARG
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_introspection():
    r = analyze_graphql(ARG, "1) { __schema { types { name } } }")
    assert "introspection" in r.breakout.separators
    assert r.breakout.command_injected


def test_directive_injection():
    r = analyze_graphql(ARG, "1) @include(if: true) { id }")
    assert "@" in r.breakout.separators
    assert r.breakout.command_injected


def test_benign_arg():
    r = analyze_graphql(ARG, "42")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_string():
    result = mutate_graphql(STRING)
    assert result.context == Context.GQL_STRING
    assert result.valid > 0


def test_mutate_arg():
    result = mutate_graphql(ARG)
    assert result.context == Context.GQL_ARG
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_graphql(ARG, "1) { id }").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "gql_arg"


def test_cli_graphql_json(capsys):
    code = main(["--lang", "graphql", "--json", ARG, "1) { id password }"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_graphql_mutate(capsys):
    code = main(["-l", "graphql", "--mutate", ARG])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
