"""Detect how a payload breaks out of a NoSQL query context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_nosql_context
from .scanner import NoSqlScanner


def detect_nosql_breakout(template: str, payload: str) -> Breakout:
    """Analyze the NoSQL breakout produced by injecting ``payload``.

    ``command_injected`` means the payload introduced a MongoDB operator or a new
    query field where the document expected a plain value: closing a string and
    adding ``"$ne": null`` in a string context, or supplying an operator object
    such as ``{"$gt": ""}`` in a value context.
    """
    parts = split_template(template)
    context = analyze_nosql_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = NoSqlScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = NoSqlScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]

    has_operator = any(t.startswith("$") for t in tokens)
    has_field = ":" in tokens
    has_object = "{" in tokens

    quote_closed = escaped if context == Context.NOSQL_STRING else False

    if context == Context.NOSQL_STRING:
        command_injected = quote_closed and (has_operator or has_field)
    else:  # value position
        command_injected = has_operator or has_object

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
        commands_created=sum(1 for t in tokens if t.startswith("$")),
        breakout_index=first_index,
    )


def score_nosql_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a NoSQL breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
