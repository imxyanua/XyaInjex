"""Top level ORM lookup injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import orm_balance
from .breakout import detect_orm_breakout, score_orm_risk


def analyze_orm(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an ORM filter ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``User.objects.filter({INPUT})`` or ``?{INPUT}=value`` (the input is a filter
    key that becomes a field lookup) or ``name={INPUT}`` (a filter value).
    """
    rendered = render(template, payload)
    breakout = detect_orm_breakout(template, payload)
    bal = orm_balance(rendered)
    risk = score_orm_risk(breakout, bal.syntax_valid)

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
        notes.append("Payload adds a field lookup that changes the query.")
    elif breakout.context == Context.ORM_LOOKUP_VALUE:
        notes.append("The input is a filter value; a '__' here is plain data.")
    else:
        notes.append("Payload is a plain field name with no lookup or traversal.")

    if "relation-traversal" in seps:
        notes.append("Traverses a relation to reach a field on another model.")
    if "sensitive-field" in seps:
        notes.append("Reaches a sensitive field (password / token / privilege flag).")
    if "regex-lookup" in seps:
        notes.append("A __regex lookup enables information leak and ReDoS.")
    if "exfil-lookup" in seps:
        notes.append("A comparison lookup enables blind, char-by-char exfiltration.")

    return notes
