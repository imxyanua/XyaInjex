"""Detect how a payload breaks out of an LDAP filter."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .scanner import LdapScanner

_OPERATORS = {"&", "|", "!"}


def detect_ldap_breakout(template: str, payload: str) -> Breakout:
    """Analyze the LDAP filter breakout produced by injecting ``payload``.

    ``command_injected`` means the payload closed the enclosing assertion and
    opened a new one, changing the filter's structure (the classic
    ``*)(uid=*`` style tautology).
    """
    parts = split_template(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    # Two phase scan to see whether the payload closes an enclosing assertion.
    escape = LdapScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = LdapScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]

    opened_new = "(" in tokens
    has_operator = any(op in tokens for op in _OPERATORS)

    command_injected = escaped and (opened_new or has_operator)

    first_index = None
    for ev in st.separators:
        if payload_start <= ev.index < payload_end:
            first_index = ev.index
            break

    return Breakout(
        context=Context.LDAP_FILTER,
        quote_closed=escaped,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=sum(1 for t in tokens if t == "("),
        breakout_index=first_index,
    )


def score_ldap_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an LDAP breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if "*" in breakout.separators:
        # A wildcard alone can turn an assertion into an always-true match.
        return Risk.MEDIUM
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
