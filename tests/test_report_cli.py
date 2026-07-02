import json

from xyainjex import analyze
from xyainjex.cli import main
from xyainjex.report import to_json, visualize


def test_to_json_roundtrip():
    result = analyze('curl "{INPUT}"', '"; id ; #')
    data = json.loads(to_json(result))
    assert data["context"] == "double_quote"
    assert data["risk"] == "CRITICAL"
    assert data["breakout"]["command_injected"] is True
    assert data["syntax_valid"] is True


def test_visualize_contains_breakout_marker():
    result = analyze('curl "{INPUT}"', '"; id ; #')
    text = visualize(result)
    assert "breakout point" in text
    assert "Command injection" in text
    assert "Execution" in text


def test_cli_json_mode(capsys):
    code = main(["--json", 'curl "{INPUT}"', '"; id ; #'])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["risk"] == "CRITICAL"
    # Exit code non-zero signals a detected breakout.
    assert code == 2


def test_cli_mutate_mode(capsys):
    code = main(["--mutate", 'curl "{INPUT}"'])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out


def test_cli_missing_marker(capsys):
    code = main(["curl example.com", "; id"])
    assert code == 1
    err = capsys.readouterr().err
    assert "marker" in err
