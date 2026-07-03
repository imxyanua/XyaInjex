"""Detect how a payload breaks out into an XSS-executable HTML context."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_xss_context
from .scanner import XssScanner

_JS_URL = re.compile(r"javascript\s*:", re.IGNORECASE)
_SCRIPT = re.compile(r"<script\b", re.IGNORECASE)
_EVENT = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script", re.IGNORECASE)

# Markers that imply script execution (rather than plain HTML injection).
_EXEC_MARKERS = {"script", "event-handler", "js-url", "script-close"}


def detect_xss_breakout(template: str, payload: str) -> Breakout:
    """Analyze the XSS breakout produced by injecting ``payload``.

    ``command_injected`` means the payload reached an HTML markup or script
    position where it can inject an element, an event handler, or script.
    """
    parts = split_template(template)
    context = analyze_xss_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = XssScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = XssScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]
    if _JS_URL.search(payload):
        tokens.append("js-url")

    has_element = "element" in tokens
    has_close = ">" in tokens
    has_event = "event-handler" in tokens or bool(_EVENT.search(payload))
    has_script = "script" in tokens or bool(_SCRIPT.search(payload))
    has_script_close = "script-close" in tokens or bool(_SCRIPT_CLOSE.search(payload))

    if context == Context.HTML_TEXT:
        quote_closed = False
        command_injected = has_element
    elif context == Context.HTML_ATTR:
        quote_closed = escaped
        command_injected = quote_closed and (has_element or has_event or has_close)
    elif context == Context.HTML_SCRIPT:
        quote_closed = escaped
        command_injected = has_script_close
    else:  # HTML_COMMENT
        quote_closed = escaped
        command_injected = quote_closed and has_element

    if has_event:
        tokens.append("event-handler")
    if has_script:
        tokens.append("script")
    tokens = list(dict.fromkeys(tokens))

    first_index = None
    for ev in st.separators:
        if payload_start <= ev.index < payload_end:
            first_index = ev.index
            break

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=tokens.count("element"),
        breakout_index=first_index,
    )


def score_xss_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an XSS breakout and syntax validity to a risk rating."""
    exec_marker = any(m in breakout.separators for m in _EXEC_MARKERS)
    if breakout.command_injected:
        # Script execution vs plain HTML injection.
        return Risk.CRITICAL if exec_marker else Risk.HIGH
    if "js-url" in breakout.separators:
        # A javascript: URL in an attribute value executes on activation.
        return Risk.HIGH
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
