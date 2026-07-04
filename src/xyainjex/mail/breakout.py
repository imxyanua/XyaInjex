"""Detect email header / SMTP command injection breakout."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_mail_context

_ENCODED = re.compile(r"%0d|%0a|%250d|%250a|\\u000d|\\u000a|\\r|\\n", re.IGNORECASE)
_LINE_SPLIT = re.compile(r"\r\n|\r|\n")
_SMTP_VERB = re.compile(
    r"^(MAIL\s+FROM|RCPT\s+TO|DATA|HELO|EHLO|VRFY|EXPN|RSET|QUIT|AUTH|STARTTLS)\b",
    re.IGNORECASE,
)
_HEADER = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:")
_RECIPIENT_HEADERS = {"bcc", "cc", "to"}


def detect_mail_breakout(template: str, payload: str) -> Breakout:
    """Analyze the mail-injection breakout produced by injecting ``payload``.

    ``command_injected`` means the payload contains a raw line break that escapes
    the current header / command onto a new line where it can inject a header,
    body, or SMTP command.
    """
    context = analyze_mail_context(template)
    prefix = split_template(template).prefix

    has_lf = "\n" in payload
    has_cr = "\r" in payload
    raw_break = has_lf or has_cr
    encoded = bool(_ENCODED.search(payload))

    tokens: set[str] = set()

    # Everything after the first line break lands on a new line.
    segments = _LINE_SPLIT.split(payload)
    injected = segments[1:]
    for seg in injected:
        s = seg.strip()
        if _SMTP_VERB.match(s):
            tokens.add("smtp-smuggle")
        elif s == ".":
            tokens.add("data-terminator")
        elif context != Context.MAIL_BODY and _HEADER.match(s):
            tokens.add("new-header")
            if _HEADER.match(s).group(1).lower() in _RECIPIENT_HEADERS:
                tokens.add("recipient")
        elif s == "" and context == Context.MAIL_HEADER:
            tokens.add("body-injection")

    structural = tokens & {
        "smtp-smuggle",
        "data-terminator",
        "new-header",
        "recipient",
        "body-injection",
    }
    if raw_break and not structural and context != Context.MAIL_BODY:
        # A bare break still folds a new line into the header / command.
        tokens.add("line-break")

    if raw_break and "\r\n" in payload:
        tokens.add("CRLF")
    if encoded:
        tokens.add("encoded")

    command_injected = bool(raw_break and (structural or "line-break" in tokens))

    line_breaks = payload.replace("\r\n", "\n").replace("\r", "\n").count("\n")

    index = None
    match = _LINE_SPLIT.search(payload)
    if match:
        index = len(prefix) + match.start()
    elif encoded:
        index = len(prefix) + _ENCODED.search(payload).start()

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated="data-terminator" in tokens,
        separators=_order_tokens(tokens),
        commands_created=line_breaks,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "smtp-smuggle",
    "data-terminator",
    "recipient",
    "new-header",
    "body-injection",
    "line-break",
    "CRLF",
    "encoded",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_mail_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map a mail-injection breakout to a risk rating."""
    seps = set(breakout.separators)
    if seps & {"smtp-smuggle", "data-terminator"}:
        # Smuggling a full SMTP command or ending DATA hijacks the transaction.
        return Risk.CRITICAL
    if seps & {"recipient", "new-header"}:
        # Injecting a header (silent Bcc, spoofed From, ...).
        return Risk.HIGH
    if breakout.command_injected:
        # A body override or a bare line fold.
        return Risk.MEDIUM
    if "encoded" in seps:
        # Encoded CR/LF that a web-to-mail layer may decode.
        return Risk.MEDIUM
    return Risk.LOW
