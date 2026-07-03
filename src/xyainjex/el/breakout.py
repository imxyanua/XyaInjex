"""Detect how a payload breaks out into expression-language evaluation."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_el_context
from .scanner import ElScanner

# The Log4Shell JNDI lookup and common OGNL/SpEL RCE gadgets.
_JNDI = re.compile(r"\bjndi:", re.IGNORECASE)
_GADGET = re.compile(
    r"Runtime|ProcessBuilder|getRuntime|\.exec\b|T\s*\(\s*java|@\s*java|scriptContext",
    re.IGNORECASE,
)


def detect_el_breakout(template: str, payload: str) -> Breakout:
    """Analyze the expression-language breakout produced by ``payload``.

    ``command_injected`` means the payload reaches an evaluated expression: it
    opened one from text, is already inside one, or escaped a string literal in
    one.
    """
    parts = split_template(template)
    context = analyze_el_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = ElScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    scanner = ElScanner()
    scanner.feed(rendered, record=True)
    opened = [r for r in scanner.regions if payload_start <= r.start < payload_end]
    closed = [r for r in opened if r.end is not None]

    jndi = bool(_JNDI.search(payload))
    gadget = bool(_GADGET.search(payload))

    tokens: list[str] = []
    tokens += sorted({r.opener for r in opened})
    if jndi:
        tokens.append("jndi")
    if gadget:
        tokens.append("gadget")

    if context == Context.EL_TEXT:
        quote_closed = False
        command_injected = bool(closed)
    elif context == Context.EL_EXPRESSION:
        quote_closed = False
        command_injected = True
    else:  # EL_STRING
        quote_closed = escaped
        command_injected = quote_closed

    if opened:
        index = opened[0].start
    elif command_injected:
        index = payload_start
    else:
        index = None

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=len(closed),
        breakout_index=index,
    )


def score_el_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an expression-language breakout and syntax validity to a rating."""
    if "jndi" in breakout.separators:
        # A JNDI lookup (Log4Shell) reaches remote code loading.
        return Risk.CRITICAL
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if "gadget" in breakout.separators or breakout.separators:
        # An opened-but-unclosed expression, or an RCE gadget without evaluation.
        return Risk.MEDIUM
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
