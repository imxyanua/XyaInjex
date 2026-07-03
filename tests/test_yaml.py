import json

from xyainjex import Context, analyze_yaml, mutate_yaml
from xyainjex.cli import main
from xyainjex.yaml.balance import yaml_balance
from xyainjex.yaml.context import analyze_yaml_context

PLAIN = "name: {INPUT}"
DOUBLE = 'name: "{INPUT}"'
SINGLE = "name: '{INPUT}'"


# --- context ---


def test_plain_context():
    assert analyze_yaml_context(PLAIN) == Context.YAML_PLAIN


def test_double_context():
    assert analyze_yaml_context(DOUBLE) == Context.YAML_DOUBLE


def test_single_context():
    assert analyze_yaml_context(SINGLE) == Context.YAML_SINGLE


# --- balance ---


def test_balanced_scalar():
    assert yaml_balance('name: "value"').syntax_valid


def test_unterminated_double_scalar():
    b = yaml_balance('name: "value')
    assert not b.syntax_valid
    assert b.double_quote_open


def test_doubled_single_quote_balances():
    assert yaml_balance("name: 'O''Brien'").syntax_valid


# --- breakout ---


def test_benign_plain():
    r = analyze_yaml(PLAIN, "alice")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_deserialization_tag_is_critical():
    r = analyze_yaml(PLAIN, "!!python/object/apply:os.system ['id']")
    assert r.breakout.command_injected
    assert "tag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_new_key_injection_is_high():
    r = analyze_yaml(PLAIN, "\nadmin: true")
    assert r.breakout.command_injected
    assert "key" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_double_quote_escape_and_key():
    r = analyze_yaml(DOUBLE, '"\nadmin: true')
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_double_quote_escape_and_tag_is_critical():
    r = analyze_yaml(DOUBLE, '"\n!!python/object/apply:os.system ["id"]')
    assert "tag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_single_quote_escape():
    r = analyze_yaml(SINGLE, "'\nadmin: true")
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_benign_quoted():
    r = analyze_yaml(DOUBLE, "plain text")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_plain():
    result = mutate_yaml(PLAIN)
    assert result.context == Context.YAML_PLAIN
    assert result.valid > 0


def test_mutate_double():
    result = mutate_yaml(DOUBLE)
    assert result.context == Context.YAML_DOUBLE
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_yaml(PLAIN, "!!python/object/apply:os.system ['id']").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "yaml_plain"


def test_cli_yaml_json(capsys):
    code = main(
        ["--lang", "yaml", "--json", PLAIN, "!!python/object/apply:os.system ['id']"]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_yaml_mutate(capsys):
    code = main(["-l", "yaml", "--mutate", PLAIN])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
