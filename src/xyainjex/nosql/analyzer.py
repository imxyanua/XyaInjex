"""Top level NoSQL (MongoDB) injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import nosql_balance
from .breakout import detect_nosql_breakout, score_nosql_risk


def analyze_nosql(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a NoSQL query ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``{"user": "{INPUT}", "pass": "secret"}``.
    """
    rendered = render(template, payload)
    breakout = detect_nosql_breakout(template, payload)
    bal = nosql_balance(rendered)
    risk = score_nosql_risk(breakout, bal.syntax_valid)

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

    if ctx == Context.NOSQL_STRING:
        if breakout.quote_closed:
            notes.append("Payload closed the JSON string value.")
        else:
            notes.append("Payload stayed inside the JSON string value.")
    else:
        notes.append("Input sits in a JSON value position.")

    operators = [t for t in breakout.separators if t.startswith("$")]
    if operators:
        notes.append(
            "Injected MongoDB operator(s): " + ", ".join(dict.fromkeys(operators))
        )

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unterminated string")
        if bal.unbalanced_pairs:
            problems.append("unbalanced " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered document has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered document is balanced.")

    return notes
