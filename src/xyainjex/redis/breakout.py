"""Detect Redis / RESP command injection in a payload."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_redis_context

# Commands that reach code execution on the server.
_RCE = {"EVAL", "EVALSHA", "SCRIPT", "MODULE", "SLAVEOF", "REPLICAOF"}
# Commands that write / destroy / reconfigure.
_WRITE = {
    "SET",
    "SETEX",
    "SETNX",
    "APPEND",
    "GETSET",
    "FLUSHALL",
    "FLUSHDB",
    "RENAME",
    "DEL",
    "UNLINK",
    "SHUTDOWN",
    "MIGRATE",
    "BGSAVE",
    "SAVE",
    "BGREWRITEAOF",
    "DEBUG",
    "RESTORE",
    "ACL",
    "CONFIG",
}
# Commands that read data / disclose information.
_READ = {
    "GET",
    "MGET",
    "KEYS",
    "INFO",
    "CLIENT",
    "HGETALL",
    "SCAN",
    "TYPE",
    "TTL",
    "LRANGE",
    "SMEMBERS",
    "DUMP",
    "RANDOMKEY",
    "DBSIZE",
}
_ALL = _RCE | _WRITE | _READ

_RESP_FRAMING = re.compile(r"\*\d+\r?\n\$\d+", re.IGNORECASE)


def _decode_crlf(payload: str) -> str:
    return (
        payload.replace("%0d%0a", "\r\n")
        .replace("%0D%0A", "\r\n")
        .replace("%0a", "\n")
        .replace("%0A", "\n")
        .replace("%0d", "\r")
        .replace("%0D", "\r")
    )


def detect_redis_breakout(template: str, payload: str) -> Breakout:
    """Analyze the Redis / RESP breakout produced by injecting ``payload``.

    ``command_injected`` means the payload starts a new Redis command: a CRLF
    break in an argument, or a command word in the inline position.
    """
    context = analyze_redis_context(template)
    prefix = split_template(template).prefix

    decoded = _decode_crlf(payload)
    crlf = bool(re.search(r"[\r\n]", decoded))
    lines = re.split(r"[\r\n]+", decoded)

    tokens: set[str] = set()
    if crlf:
        tokens.add("crlf")
    if _RESP_FRAMING.search(decoded):
        tokens.add("resp-framing")

    # Lines that Redis parses as freshly injected commands.
    injected = lines if context == Context.REDIS_INLINE else lines[1:]
    injected_text = "\n".join(injected)

    present: set[str] = set()
    for cmd in _ALL:
        if re.search(rf"(?:^|\s|\$\d+\r?\n){cmd}\b", injected_text, re.IGNORECASE):
            present.add(cmd)

    for cmd in present:
        tokens.add(cmd.lower())
    if present & _RCE:
        tokens.add("rce-command")
    if present & _WRITE:
        tokens.add("write-command")
    if present & _READ:
        tokens.add("read-command")

    # CONFIG SET dir / dbfilename writes an arbitrary file (webshell, keys).
    if "CONFIG" in present and re.search(
        r"CONFIG\s+SET\s+(?:dir|dbfilename)", injected_text, re.IGNORECASE
    ):
        tokens.add("config-rce")

    if context == Context.REDIS_INLINE:
        command_injected = bool(present) or crlf
    else:
        command_injected = crlf or "resp-framing" in tokens

    index = len(prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed=crlf,
        command_injected=command_injected,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=len(present),
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "config-rce",
    "rce-command",
    "write-command",
    "read-command",
    "crlf",
    "resp-framing",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_redis_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map a Redis breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        return Risk.LOW
    if seps & {"config-rce", "rce-command"}:
        # EVAL / MODULE / SLAVEOF / CONFIG SET dir -> code execution.
        return Risk.CRITICAL
    if "write-command" in seps:
        # SET / FLUSHALL / CONFIG / RENAME -> data write or destruction.
        return Risk.HIGH
    if "read-command" in seps:
        return Risk.MEDIUM
    # A CRLF break with no recognized command still injects a new command line.
    return Risk.MEDIUM
