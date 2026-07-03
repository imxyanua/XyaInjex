"""Detect how a payload breaks out of an XML context."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_xml_context
from .scanner import XmlScanner

_XXE = re.compile(r"<!ENTITY|<!DOCTYPE", re.IGNORECASE)


def detect_xml_breakout(template: str, payload: str) -> Breakout:
    """Analyze the XML breakout produced by injecting ``payload``.

    ``command_injected`` means the payload introduced new markup: a new element
    from text, or closing a quoted attribute or the tag to inject an element.
    """
    parts = split_template(template)
    context = analyze_xml_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = XmlScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = XmlScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]
    has_element = "element" in tokens
    has_close = ">" in tokens
    xxe = bool(_XXE.search(payload))

    if context == Context.XML_TEXT:
        quote_closed = False
        command_injected = has_element
    else:
        quote_closed = escaped
        command_injected = quote_closed and (has_element or has_close)

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
        separators=tokens + (["xxe"] if xxe else []),
        commands_created=tokens.count("element"),
        breakout_index=first_index,
    )


def score_xml_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an XML breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if "xxe" in breakout.separators:
        return Risk.HIGH
    if "entity" in breakout.separators or breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
