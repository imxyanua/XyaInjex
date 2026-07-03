"""Detect Server-Side Includes (SSI) injection breakout."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template

# A complete SSI directive: <!--#name ... -->
_DIRECTIVE = re.compile(r"<!--\s*#\s*(\w+)\b.*?-->", re.IGNORECASE | re.DOTALL)
# An opened but unclosed exec directive.
_OPEN_EXEC = re.compile(r"<!--\s*#\s*exec\b", re.IGNORECASE)

_RCE = {"exec"}
_FILE = {"include"}


def detect_ssi_breakout(template: str, payload: str) -> Breakout:
    """Analyze the SSI breakout produced by injecting ``payload``.

    ``command_injected`` means the payload contains a complete SSI directive that
    the server evaluates.
    """
    parts = split_template(template)

    directives = [m.group(1).lower() for m in _DIRECTIVE.finditer(payload)]
    command_injected = bool(directives)

    tokens: list[str] = list(dict.fromkeys(directives))
    if any(d in _RCE for d in directives):
        tokens.append("rce")
    if any(d in _FILE for d in directives):
        tokens.append("file-read")
    if not command_injected and _OPEN_EXEC.search(payload):
        tokens.append("partial-exec")

    match = _DIRECTIVE.search(payload)
    index = len(parts.prefix) + match.start() if match else None

    return Breakout(
        context=Context.SSI_TEXT,
        quote_closed=False,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=len(directives),
        breakout_index=index,
    )


def score_ssi_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an SSI breakout to a risk rating."""
    if "rce" in breakout.separators:
        # #exec cmd / #exec cgi reaches command execution.
        return Risk.CRITICAL
    if "file-read" in breakout.separators:
        # #include virtual can read files or reach internal URLs.
        return Risk.HIGH
    if breakout.command_injected:
        # #echo, #printenv, #config: information disclosure.
        return Risk.MEDIUM
    if "partial-exec" in breakout.separators:
        return Risk.MEDIUM
    return Risk.LOW
