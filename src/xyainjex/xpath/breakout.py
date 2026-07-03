"""Detect how a payload breaks out of an XPath context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_xpath_context
from .scanner import XPathScanner


def detect_xpath_breakout(template: str, payload: str) -> Breakout:
    """Analyze the XPath breakout produced by injecting ``payload``.

    ``command_injected`` means the payload introduced XPath logic (an ``or`` or
    ``and`` operator, a predicate close, a union, or a comparison) where the
    query expected a data value.
    """
    parts = split_template(template)
    context = analyze_xpath_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    # Two phase scan to measure whether the payload escapes a string literal.
    escape = XPathScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = XPathScanner().feed(rendered, record=True)
    injected = [
        ev
        for ev in st.separators
        if ev.stack_depth == 0 and payload_start <= ev.index < payload_end
    ]
    tokens = [ev.token for ev in injected]

    quote_closed = escaped if context == Context.XPATH_STRING else False

    if context == Context.XPATH_STRING:
        command_injected = quote_closed and bool(injected)
    else:  # expression position, e.g. [position() = {INPUT}]
        command_injected = bool(injected)

    breakout_index = injected[0].index if injected else None

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=len(injected),
        breakout_index=breakout_index,
    )


def score_xpath_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an XPath breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
