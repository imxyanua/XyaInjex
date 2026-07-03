import json

from xyainjex import Context, CrlfKind, analyze_crlf, mutate_crlf, parse_crlf_kind
from xyainjex.cli import main

HEADER_TMPL = "Location: {INPUT}"
LOG_TMPL = "[INFO] user={INPUT} logged in"


# --- context / parsing ---


def test_header_context():
    from xyainjex.crlf.context import analyze_crlf_context

    assert analyze_crlf_context(HEADER_TMPL, CrlfKind.HEADER) == Context.HTTP_HEADER


def test_log_context():
    from xyainjex.crlf.context import analyze_crlf_context

    assert analyze_crlf_context(LOG_TMPL, CrlfKind.LOG) == Context.LOG_LINE


def test_parse_kind_aliases():
    assert parse_crlf_kind("http") == CrlfKind.HEADER
    assert parse_crlf_kind("logging") == CrlfKind.LOG


# --- breakout ---


def test_benign_header_value():
    r = analyze_crlf(HEADER_TMPL, "https://ok.example", CrlfKind.HEADER)
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_header_crlf_injection():
    r = analyze_crlf(HEADER_TMPL, "x\r\nSet-Cookie: injected=1", CrlfKind.HEADER)
    assert r.breakout.command_injected
    assert "CRLF" in r.breakout.separators
    assert "new-header" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_response_splitting():
    r = analyze_crlf(HEADER_TMPL, "x\r\n\r\n<html>body</html>", CrlfKind.HEADER)
    assert "double-CRLF" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_bare_lf_header_is_high():
    r = analyze_crlf(HEADER_TMPL, "x\nSet-Cookie: y=1", CrlfKind.HEADER)
    assert r.breakout.command_injected
    assert "LF" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_encoded_crlf_is_medium():
    r = analyze_crlf(HEADER_TMPL, "x%0d%0aSet-Cookie: y=1", CrlfKind.HEADER)
    assert not r.breakout.command_injected
    assert "encoded" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_log_forging_is_high():
    r = analyze_crlf(LOG_TMPL, "bob\n[ERROR] forged", CrlfKind.LOG)
    assert r.breakout.command_injected
    assert r.risk.value == "HIGH"


def test_log_benign():
    r = analyze_crlf(LOG_TMPL, "normal message", CrlfKind.LOG)
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_line_break_count():
    r = analyze_crlf(HEADER_TMPL, "a\r\nb\r\nc", CrlfKind.HEADER)
    assert r.breakout.commands_created == 2


# --- mutation ---


def test_mutate_header():
    result = mutate_crlf(HEADER_TMPL, CrlfKind.HEADER)
    assert result.context == Context.HTTP_HEADER
    assert result.valid > 0


def test_mutate_log():
    result = mutate_crlf(LOG_TMPL, CrlfKind.LOG)
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_kind():
    data = analyze_crlf(HEADER_TMPL, "x\r\ny: z", CrlfKind.HEADER).to_dict()
    assert data["dialect"] == "header"
    assert data["context"] == "http_header"


def test_cli_crlf_json(capsys):
    code = main(
        [
            "--lang",
            "crlf",
            "-d",
            "header",
            "--json",
            HEADER_TMPL,
            "x\r\nSet-Cookie: a=1",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "header"
    assert data["risk"] == "CRITICAL"
    assert code == 2


def test_cli_crlf_mutate(capsys):
    code = main(["-l", "crlf", "-d", "log", "--mutate", LOG_TMPL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
