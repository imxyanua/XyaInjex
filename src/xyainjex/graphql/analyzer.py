"""Top level GraphQL injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import graphql_balance
from .breakout import detect_graphql_breakout, score_graphql_risk


def analyze_graphql(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a GraphQL ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``{ user(name: "{INPUT}") { id } }`` or ``{ user(id: {INPUT}) { id } }``.
    """
    rendered = render(template, payload)
    breakout = detect_graphql_breakout(template, payload)
    bal = graphql_balance(rendered)
    risk = score_graphql_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal)

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


def _build_notes(breakout, bal) -> list[str]:
    notes: list[str] = []
    ctx = breakout.context

    if ctx == Context.GQL_STRING:
        if breakout.quote_closed:
            notes.append("Payload closed the string argument.")
        else:
            notes.append("Payload stayed inside the string argument.")
    else:
        notes.append("Input sits in an argument or value position.")

    if breakout.command_injected:
        notes.append(
            "Payload injected query structure (a field, argument, or directive)."
        )
    if "introspection" in breakout.separators:
        notes.append("Payload references an introspection field (schema disclosure).")

    if not bal.syntax_valid:
        notes.append(
            "Rendered query is unbalanced: "
            + ", ".join(bal.unbalanced_pairs.keys() or ["string"])
            + "."
        )
    else:
        notes.append("Rendered query is balanced.")

    return notes
