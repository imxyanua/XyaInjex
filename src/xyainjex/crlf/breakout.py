"""Detect CRLF injection breakout in an HTTP header value or log line."""

from __future__ import annotations

import re

from ..models import Breakout, CrlfKind, Risk
from ..shell.context import split_template
from .context import analyze_crlf_context

_ENCODED = re.compile(r"%0d|%0a|%250d|%250a|\\u000d|\\u000a|\\r|\\n", re.IGNORECASE)
# A header line after a line break: "Name: value".
_HEADER_AFTER = re.compile(r"[\r\n]\s*[A-Za-z][A-Za-z0-9-]*\s*:")


def detect_crlf_breakout(
    template: str, payload: str, kind: CrlfKind = CrlfKind.HEADER
) -> Breakout:
    """Analyze the CRLF breakout produced by injecting ``payload``.

    ``command_injected`` means the payload contains a raw carriage return or line
    feed that breaks out of the value onto a new line.
    """
    parts = split_template(template)
    context = analyze_crlf_context(template, kind)

    has_crlf = "\r\n" in payload
    has_lf = "\n" in payload
    has_cr = "\r" in payload
    has_double = "\r\n\r\n" in payload or "\n\n" in payload
    encoded = bool(_ENCODED.search(payload))
    header_after = bool(_HEADER_AFTER.search(payload))

    tokens: list[str] = []
    if has_crlf:
        tokens.append("CRLF")
    elif has_lf:
        tokens.append("LF")
    elif has_cr:
        tokens.append("CR")
    if has_double:
        tokens.append("double-CRLF")
    if header_after:
        tokens.append("new-header")
    if encoded:
        tokens.append("encoded")

    command_injected = has_lf or has_cr
    line_breaks = payload.replace("\r\n", "\n").replace("\r", "\n").count("\n")

    index = None
    match = re.search(r"[\r\n]", payload)
    if match:
        index = len(parts.prefix) + match.start()
    elif encoded:
        index = len(parts.prefix) + _ENCODED.search(payload).start()

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=line_breaks,
        breakout_index=index,
    )


def score_crlf_risk(
    breakout: Breakout, kind: CrlfKind, syntax_valid: bool = True
) -> Risk:
    """Map a CRLF breakout and sink kind to a risk rating."""
    tokens = breakout.separators
    proper_crlf = "CRLF" in tokens
    raw = breakout.command_injected
    encoded = "encoded" in tokens

    if kind == CrlfKind.HEADER:
        # A proper CRLF can add headers or, with a blank line, split the body.
        if proper_crlf:
            return Risk.CRITICAL
        if raw:  # a bare LF or CR that many servers still honour
            return Risk.HIGH
        if encoded:
            return Risk.MEDIUM
        return Risk.LOW

    # Log line: forging entries is high impact, but response splitting does not
    # apply, so bare line feeds are rated high rather than critical.
    if raw:
        return Risk.HIGH
    if encoded:
        return Risk.MEDIUM
    return Risk.LOW
