import json

from xyainjex import Context, analyze_xss, mutate_xss
from xyainjex.cli import main
from xyainjex.xss.context import analyze_xss_context

TEXT = "<div>{INPUT}</div>"
ATTR = '<img src="{INPUT}">'
ATTR_S = "<img src='{INPUT}'>"
SCRIPT = "<script>var x = '{INPUT}';</script>"
COMMENT = "<!-- {INPUT} -->"


# --- context ---


def test_context_text():
    assert analyze_xss_context(TEXT) == Context.HTML_TEXT


def test_context_attr():
    assert analyze_xss_context(ATTR) == Context.HTML_ATTR
    assert analyze_xss_context(ATTR_S) == Context.HTML_ATTR


def test_context_script():
    assert analyze_xss_context(SCRIPT) == Context.HTML_SCRIPT


def test_context_comment():
    assert analyze_xss_context(COMMENT) == Context.HTML_COMMENT


# --- text context ---


def test_benign_text():
    r = analyze_xss(TEXT, "hello world")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_script_element_is_critical():
    r = analyze_xss(TEXT, "<script>alert(1)</script>")
    assert r.breakout.command_injected
    assert "script" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_event_handler_is_critical():
    r = analyze_xss(TEXT, "<img src=x onerror=alert(1)>")
    assert r.breakout.command_injected
    assert "event-handler" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_plain_markup_is_high():
    r = analyze_xss(TEXT, "<b>bold</b>")
    assert r.breakout.command_injected
    assert "script" not in r.breakout.separators
    assert r.risk.value == "HIGH"


# --- attribute context ---


def test_attr_breakout_is_critical():
    r = analyze_xss(ATTR, '"><script>alert(1)</script>')
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_attr_event_is_critical():
    r = analyze_xss(ATTR, '" onmouseover="alert(1)')
    assert r.breakout.quote_closed
    assert "event-handler" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_single_quote_attr_breakout():
    r = analyze_xss(ATTR_S, "'><svg onload=alert(1)>")
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_js_url_without_breakout_is_high():
    r = analyze_xss(ATTR, "javascript:alert(1)")
    assert not r.breakout.command_injected
    assert "js-url" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_benign_attr():
    r = analyze_xss(ATTR, "safevalue")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- script context ---


def test_script_breakout_is_critical():
    r = analyze_xss(SCRIPT, "</script><script>alert(1)</script>")
    assert r.breakout.command_injected
    assert "script-close" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_script_string_only_is_not_breakout():
    r = analyze_xss(SCRIPT, "value")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- comment context ---


def test_comment_escape_is_critical():
    r = analyze_xss(COMMENT, "--><script>alert(1)</script>")
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_comment_stays_inside():
    r = analyze_xss(COMMENT, "a normal comment")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_text():
    result = mutate_xss(TEXT)
    assert result.context == Context.HTML_TEXT
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_attr():
    result = mutate_xss(ATTR)
    assert result.context == Context.HTML_ATTR
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_xss(TEXT, "<script>alert(1)</script>").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "html_text"


def test_cli_xss_json(capsys):
    code = main(["--lang", "xss", "--json", ATTR, '"><script>alert(1)</script>'])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_xss_mutate(capsys):
    code = main(["-l", "xss", "--mutate", TEXT])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
