import json

from xyainjex import Context, analyze_host, mutate_host
from xyainjex.cli import main
from xyainjex.host.context import analyze_host_context

HOST = "Host: {INPUT}"
XF = "X-Forwarded-Host: {INPUT}"


# --- context ---


def test_context_header():
    assert analyze_host_context(HOST) == Context.HOST_HEADER


def test_context_forwarded():
    assert analyze_host_context(XF) == Context.HOST_FORWARDED
    assert analyze_host_context("X-Host: {INPUT}") == Context.HOST_FORWARDED


# --- Host context ---


def test_empty_is_low():
    r = analyze_host(HOST, "")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_plain_host_is_medium():
    r = analyze_host(HOST, "evil.example.com")
    assert r.breakout.command_injected
    assert "attacker-host" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_userinfo_override_is_high():
    r = analyze_host(HOST, "expected.example.com@evil.example.com")
    assert "userinfo-override" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_second_host_is_high():
    r = analyze_host(HOST, "expected.example.com, evil.example.com")
    assert "second-host" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_absolute_url_is_high():
    r = analyze_host(HOST, "http://evil.example.com/")
    assert "absolute-url" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_internal_is_high():
    r = analyze_host(HOST, "localhost")
    assert "internal" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_crlf_is_critical():
    r = analyze_host(HOST, "evil.example.com\r\nX-Forwarded-Host: evil.example.com")
    assert "crlf" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_port_is_medium():
    r = analyze_host(HOST, "example.com:8080")
    assert "port" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


# --- X-Forwarded-Host context ---


def test_forwarded_plain_host_is_high():
    r = analyze_host(XF, "evil.example.com")
    assert r.breakout.command_injected
    assert r.context == Context.HOST_FORWARDED
    assert r.risk.value == "HIGH"


# --- mutation ---


def test_mutate_header():
    result = mutate_host(HOST)
    assert result.context == Context.HOST_HEADER
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_forwarded():
    result = mutate_host(XF)
    assert result.context == Context.HOST_FORWARDED
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_host(HOST, "evil.example.com").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "host_header"


def test_cli_host_json(capsys):
    code = main(["--lang", "host", "--json", HOST, "a@evil.example.com"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "HIGH"
    assert data["dialect"] is None
    assert code == 2


def test_cli_host_mutate(capsys):
    code = main(["-l", "host", "--mutate", HOST])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
