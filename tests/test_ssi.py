import json

from xyainjex import Context, analyze_ssi, mutate_ssi
from xyainjex.cli import main
from xyainjex.ssi.context import analyze_ssi_context

TMPL = "<html><body>Hello {INPUT}</body></html>"


# --- context ---


def test_ssi_context():
    assert analyze_ssi_context(TMPL) == Context.SSI_TEXT


# --- breakout ---


def test_benign_value():
    r = analyze_ssi(TMPL, "World")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_exec_cmd_is_critical():
    r = analyze_ssi(TMPL, '<!--#exec cmd="id" -->')
    assert r.breakout.command_injected
    assert "rce" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_include_is_high():
    r = analyze_ssi(TMPL, '<!--#include virtual="/etc/passwd" -->')
    assert r.breakout.command_injected
    assert "file-read" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_echo_is_medium():
    r = analyze_ssi(TMPL, '<!--#echo var="DATE_LOCAL" -->')
    assert r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_printenv_is_medium():
    r = analyze_ssi(TMPL, "<!--#printenv -->")
    assert r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_partial_exec_is_medium():
    r = analyze_ssi(TMPL, '<!--#exec cmd="id"')
    assert not r.breakout.command_injected
    assert "partial-exec" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_normal_html_comment_is_not_directive():
    r = analyze_ssi(TMPL, "just <!-- a normal comment -->")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate():
    result = mutate_ssi(TMPL)
    assert result.context == Context.SSI_TEXT
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_ssi(TMPL, '<!--#exec cmd="id" -->').to_dict()
    assert data["dialect"] is None
    assert data["context"] == "ssi_text"


def test_cli_ssi_json(capsys):
    code = main(["--lang", "ssi", "--json", TMPL, '<!--#exec cmd="id" -->'])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_ssi_mutate(capsys):
    code = main(["-l", "ssi", "--mutate", TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
