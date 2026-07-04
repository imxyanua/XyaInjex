"""Top level XXE (XML external entity) analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import xxe_balance
from .breakout import detect_xxe_breakout, score_xxe_risk


def analyze_xxe(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an XML document ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``{INPUT}``
    (the input is the whole parsed document) or ``<?xml version="1.0"?>{INPUT}``.
    """
    rendered = render(template, payload)
    breakout = detect_xxe_breakout(template, payload)
    bal = xxe_balance(rendered)
    risk = score_xxe_risk(breakout, bal.syntax_valid)

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
        notes.append(
            "Payload defines a DOCTYPE with an external entity the parser processes."
        )
    elif breakout.context == Context.XXE_CONTENT and "doctype" in seps:
        notes.append(
            "A DOCTYPE injected inside an element does not parse; XXE here needs "
            "the input at the document start or an existing DTD."
        )
    elif seps:
        notes.append(
            "Payload contains DTD constructs but no processed external entity."
        )
    else:
        notes.append("Payload contains no DTD or entity constructs.")

    if "oob" in seps:
        notes.append(
            "Parameter entity + external DTD enables out-of-band data exfiltration."
        )
    if "wrapper" in seps:
        notes.append("Entity uses a dangerous wrapper (php:// / expect://).")
    if "ssrf" in seps:
        notes.append("External entity points at a remote URL (SSRF).")
    if "file-read" in seps:
        notes.append("External entity reads a local file (file:// or a path).")
    if "expansion" in seps:
        notes.append(
            "Nested internal entities expand exponentially (billion laughs, DoS)."
        )

    return notes
