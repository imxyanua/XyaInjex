"""Top level Redis / RESP injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import redis_balance
from .breakout import detect_redis_breakout, score_redis_risk


def analyze_redis(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a Redis command ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``GET {INPUT}``
    or ``SET session {INPUT}`` (the input is an argument) or ``{INPUT}`` (the
    input is the command line, e.g. smuggled through gopher:// SSRF).
    """
    rendered = render(template, payload)
    breakout = detect_redis_breakout(template, payload)
    bal = redis_balance(rendered)
    risk = score_redis_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout)

    return AnalysisResult(
        template=template,
        payload=payload,
        rendered=rendered,
        dialect=None,
        context=breakout.context,
        breakout=breakout,
        balance=bal,
        risk=risk,
        notes=notes,
    )


def _build_notes(breakout) -> list[str]:
    notes: list[str] = []
    seps = breakout.separators

    if breakout.command_injected:
        if breakout.context == Context.REDIS_INLINE:
            notes.append("Payload injects a Redis command in the inline position.")
        else:
            notes.append(
                "Payload breaks the argument line and injects a Redis command."
            )
    else:
        notes.append("Payload stays within the current command argument.")

    if "config-rce" in seps:
        notes.append("CONFIG SET dir / dbfilename writes an arbitrary file (RCE).")
    if "rce-command" in seps:
        notes.append("Injects an RCE command (EVAL / MODULE / SLAVEOF).")
    if "write-command" in seps:
        notes.append("Injects a write / destructive command (SET / FLUSHALL / ...).")
    if "resp-framing" in seps:
        notes.append("Payload crafts raw RESP protocol framing.")

    return notes
