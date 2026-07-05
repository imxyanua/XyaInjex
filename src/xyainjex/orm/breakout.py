"""Detect ORM lookup injection (Django-style field__lookup) in a filter key."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_orm_context

# Django field lookups (the suffix after the final "__").
_LOOKUPS = {
    "exact",
    "iexact",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "range",
    "regex",
    "iregex",
    "isnull",
    "search",
    "year",
    "month",
    "day",
    "week_day",
    "hour",
    "date",
    "overlap",
}
# Lookups that enable blind, character-by-character data exfiltration.
_EXFIL = {
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "gt",
    "gte",
    "lt",
    "lte",
    "range",
    "regex",
    "iregex",
    "search",
}
_REGEX = {"regex", "iregex"}

# Field names that should never be reachable through a user-controlled lookup.
_SENSITIVE = {
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "is_staff",
    "is_superuser",
    "is_admin",
    "ssn",
    "hash",
    "salt",
    "session",
}


def detect_orm_breakout(template: str, payload: str) -> Breakout:
    """Analyze the ORM lookup breakout produced by injecting ``payload``.

    ``command_injected`` means the payload lands in a filter key and adds a
    lookup suffix or a relation traversal that changes the query semantics.
    """
    context = analyze_orm_context(template)
    prefix = split_template(template).prefix

    key = payload.split("=", 1)[0].strip()
    segments = re.split(r"__", key) if key else []

    tokens: set[str] = set()
    has_lookup = len(segments) >= 2 and segments[-1].lower() in _LOOKUPS
    lookup = segments[-1].lower() if has_lookup else None
    field_segments = segments[:-1] if has_lookup else segments
    traversal = len(field_segments) >= 2
    sensitive = any(s.lower() in _SENSITIVE for s in segments)

    if context == Context.ORM_LOOKUP_KEY:
        if has_lookup:
            tokens.add("lookup")
            tokens.add(lookup)
            if lookup in _EXFIL:
                tokens.add("exfil-lookup")
            if lookup in _REGEX:
                tokens.add("regex-lookup")
            if lookup == "isnull":
                tokens.add("isnull-lookup")
        if traversal:
            tokens.add("relation-traversal")
        if sensitive:
            tokens.add("sensitive-field")
        command_injected = has_lookup or traversal
    else:
        # The input is a value; a "__" here is plain data.
        command_injected = False

    index = len(prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=1 if command_injected else 0,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "sensitive-field",
    "relation-traversal",
    "regex-lookup",
    "exfil-lookup",
    "isnull-lookup",
    "lookup",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_orm_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map an ORM lookup breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        return Risk.LOW
    if seps & {"sensitive-field", "relation-traversal", "regex-lookup"}:
        # Reaches a sensitive or related field, or a ReDoS-capable regex lookup.
        return Risk.HIGH
    if seps & {"exfil-lookup", "isnull-lookup"}:
        # A comparison / boolean lookup enables blind exfiltration.
        return Risk.MEDIUM
    return Risk.MEDIUM
