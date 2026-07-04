import json

from xyainjex import Context, analyze_prototype, mutate_prototype
from xyainjex.cli import main
from xyainjex.prototype.context import analyze_prototype_context

JSON = "{INPUT}"
JVAL = '{"user": {INPUT}}'
PATH = "settings[{INPUT}]=1"


# --- context ---


def test_context_json():
    assert analyze_prototype_context(JSON) == Context.PP_JSON
    assert analyze_prototype_context(JVAL) == Context.PP_JSON


def test_context_path():
    assert analyze_prototype_context(PATH) == Context.PP_PATH


# --- json vector ---


def test_benign_json_is_low():
    r = analyze_prototype(JSON, '{"name": "bob"}')
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_proto_pollution_is_high():
    r = analyze_prototype(JSON, '{"__proto__": {"polluted": true}}')
    assert r.breakout.command_injected
    assert "pollution" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_proto_key_without_nested_is_medium():
    r = analyze_prototype(JSON, '{"__proto__": 1}')
    assert not r.breakout.command_injected
    assert "proto-key" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_constructor_chain_is_high():
    r = analyze_prototype(JSON, '{"constructor": {"prototype": {"x": 1}}}')
    assert r.breakout.command_injected
    assert "constructor-key" in r.breakout.separators
    assert "prototype-key" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_gadget_is_critical():
    r = analyze_prototype(JSON, '{"__proto__": {"NODE_OPTIONS": "--inspect"}}')
    assert "gadget" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- path vector ---


def test_path_bracket_pollution_is_high():
    r = analyze_prototype(JSON, "__proto__[polluted]=1")
    assert r.breakout.command_injected
    assert "path-vector" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_path_dot_pollution_is_high():
    r = analyze_prototype(JSON, "__proto__.polluted=1")
    assert r.breakout.command_injected
    assert r.risk.value == "HIGH"


def test_path_gadget_is_critical():
    r = analyze_prototype(JSON, "__proto__[NODE_OPTIONS]=--inspect")
    assert "gadget" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_setting_proto_to_scalar_is_not_pollution():
    r = analyze_prototype(JSON, "[__proto__]=1")
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_benign_path_is_low():
    r = analyze_prototype(JSON, "user[name]=bob")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_json():
    result = mutate_prototype(JSON)
    assert result.context == Context.PP_JSON
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_path():
    result = mutate_prototype(PATH)
    assert result.context == Context.PP_PATH
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_prototype(JSON, '{"__proto__": {"x": 1}}').to_dict()
    assert data["dialect"] is None
    assert data["context"] == "pp_json"


def test_cli_prototype_json(capsys):
    code = main(
        ["--lang", "prototype", "--json", JSON, '{"__proto__": {"NODE_OPTIONS": "x"}}']
    )
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_prototype_mutate(capsys):
    code = main(["-l", "prototype", "--mutate", JSON])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
