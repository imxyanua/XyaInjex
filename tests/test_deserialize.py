import json

from xyainjex import Context, analyze_deserialize, mutate_deserialize
from xyainjex.cli import main
from xyainjex.deserialize.context import analyze_deserialize_context

DOC = "{INPUT}"

PICKLE = "cos\nsystem\n(S'id'\ntR."
PHP_OBJECT = 'O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}'
PHP_DATA = 'a:2:{i:0;s:2:"hi";i:1;i:5;}'
JAVA_B64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
JAVA_HEX = "aced0005737200116a6176612e7574696c2e486173684d6170"
DOTNET_B64 = "AAEAAAD/////AAAAAAAAAAAEAQAAAA=="


# --- context ---


def test_context_default():
    assert analyze_deserialize_context(DOC) == Context.DESERIALIZE_RAW


# --- detection ---


def test_benign_is_low():
    r = analyze_deserialize(DOC, "hello world")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_random_base64_text_is_low():
    r = analyze_deserialize(DOC, "just base64 dGV4dA==")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_pickle_with_gadget_is_critical():
    r = analyze_deserialize(DOC, PICKLE)
    assert r.breakout.command_injected
    assert "python-pickle" in r.breakout.separators
    assert "gadget" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_php_object_is_high():
    r = analyze_deserialize(DOC, PHP_OBJECT)
    assert r.breakout.command_injected
    assert "php-object" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_php_data_only_is_medium():
    r = analyze_deserialize(DOC, PHP_DATA)
    assert not r.breakout.command_injected
    assert "php-data" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_java_base64_is_high_and_encoded():
    r = analyze_deserialize(DOC, JAVA_B64)
    assert "java" in r.breakout.separators
    assert "encoded" in r.breakout.separators
    assert r.context == Context.DESERIALIZE_ENCODED
    assert r.risk.value == "HIGH"


def test_java_hex_is_high():
    r = analyze_deserialize(DOC, JAVA_HEX)
    assert "java" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_dotnet_base64_is_high():
    r = analyze_deserialize(DOC, DOTNET_B64)
    assert "dotnet" in r.breakout.separators
    assert r.risk.value == "HIGH"


# --- mutation ---


def test_mutate():
    result = mutate_deserialize(DOC)
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"
    assert all(c.command_injected for c in result.candidates)


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_deserialize(DOC, JAVA_B64).to_dict()
    assert data["dialect"] is None
    assert data["context"] == "deserialize_encoded"


def test_cli_deserialize_json(capsys):
    code = main(["--lang", "deserialize", "--json", DOC, PHP_OBJECT])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "HIGH"
    assert data["dialect"] is None
    assert code == 2


def test_cli_deserialize_mutate(capsys):
    code = main(["-l", "deserialize", "--mutate", DOC])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
