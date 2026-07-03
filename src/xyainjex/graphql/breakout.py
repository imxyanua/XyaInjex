"""Detect how a payload breaks out of a GraphQL context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_graphql_context
from .scanner import GraphqlScanner

_STRUCTURE = {"{", "(", "@"}


def detect_graphql_breakout(template: str, payload: str) -> Breakout:
    """Analyze the GraphQL breakout produced by injecting ``payload``.

    ``command_injected`` means the payload introduced query structure, a field
    selection, an argument list, or a directive, after escaping any string
    argument.
    """
    parts = split_template(template)
    context = analyze_graphql_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = GraphqlScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = GraphqlScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]
    has_structure = any(t in _STRUCTURE for t in tokens)

    if context == Context.GQL_STRING:
        quote_closed = escaped
        command_injected = quote_closed and has_structure
    else:  # argument / value position
        quote_closed = False
        command_injected = has_structure

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
        commands_created=tokens.count("{"),
        breakout_index=first_index,
    )


def score_graphql_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a GraphQL breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if "introspection" in breakout.separators:
        return Risk.MEDIUM
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
