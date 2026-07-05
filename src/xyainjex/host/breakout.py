"""Detect HTTP host header injection / poisoning in a host value."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_host_context

_SCHEME = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*)://(.*)$", re.DOTALL)
_CRLF = re.compile(r"\r|\n|%0d|%0a", re.IGNORECASE)
_PORT = re.compile(r":\d+$")
_HOSTISH = re.compile(r"^[A-Za-z0-9.\-\[\]:_]+$")

_INTERNAL = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "169.254.169.254",
    "metadata.google.internal",
}


def detect_host_breakout(template: str, payload: str) -> Breakout:
    """Analyze the host-header breakout produced by injecting ``payload``.

    ``command_injected`` means the payload supplies an attacker-controlled host
    (or breaks the header with CRLF); the risk reflects how it defeats a naive
    ``Host`` check and what it poisons.
    """
    context = analyze_host_context(template)
    prefix = split_template(template).prefix

    tokens: set[str] = set()

    crlf = bool(_CRLF.search(payload))
    if crlf:
        tokens.add("crlf")

    # A CRLF splits the value; the host is what precedes it.
    first_line = re.split(r"\r|\n|%0d|%0a", payload, maxsplit=1, flags=re.IGNORECASE)[0]

    m = _SCHEME.match(first_line)
    absolute = bool(m)
    if absolute:
        tokens.add("absolute-url")
    rest = m.group(2) if m else first_line

    authority = re.split(r"[/?#]", rest, maxsplit=1)[0].strip()
    # A comma or whitespace introduces a second host (last-wins parsers).
    host_list = [h for h in re.split(r"[,\s]+", authority) if h]
    primary = host_list[0] if host_list else ""
    if len(host_list) > 1:
        tokens.add("second-host")
    if "@" in primary:
        tokens.add("userinfo-override")

    host_port = primary.split("@")[-1].strip()
    if _PORT.search(host_port):
        tokens.add("port")
    host = _PORT.sub("", host_port).strip().lower()

    has_host = bool(host) and bool(_HOSTISH.match(host))
    if has_host:
        tokens.add("attacker-host")
    if host in _INTERNAL or host.startswith("127.") or host.endswith(".internal"):
        tokens.add("internal")

    command_injected = has_host or crlf

    ordered = _order_tokens(tokens)
    index = len(prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed=crlf or "userinfo-override" in tokens,
        command_injected=command_injected,
        comment_terminated=crlf,
        separators=ordered,
        commands_created=1 if command_injected else 0,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "crlf",
    "userinfo-override",
    "absolute-url",
    "second-host",
    "internal",
    "attacker-host",
    "port",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_host_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map a host-header breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        return Risk.LOW
    if "crlf" in seps:
        # CRLF in the host value splits the response / injects headers.
        return Risk.CRITICAL
    if seps & {"userinfo-override", "absolute-url", "second-host", "internal"}:
        # Defeats a naive Host check, or targets an internal host.
        return Risk.HIGH
    # A plain attacker host. X-Forwarded-Host is trusted-but-unvalidated, so it
    # poisons app-generated URLs (password reset) more directly than Host.
    if breakout.context == Context.HOST_FORWARDED:
        return Risk.HIGH
    return Risk.MEDIUM
