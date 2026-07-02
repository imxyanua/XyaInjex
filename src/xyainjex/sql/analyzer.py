"""Top level SQL injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context, SqlDialect
from ..shell.breakout import render
from .balance import sql_balance
from .breakout import detect_sql_breakout, score_sql_risk


def analyze_sql(
    template: str, payload: str, dialect: SqlDialect = SqlDialect.MYSQL
) -> AnalysisResult:
    """Analyze injecting ``payload`` into a SQL ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``SELECT * FROM users WHERE name = '{INPUT}'``.
    """
    rendered = render(template, payload)
    breakout = detect_sql_breakout(template, payload, dialect)
    bal = sql_balance(rendered, dialect)
    risk = score_sql_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal)

    return AnalysisResult(
        template=template,
        payload=payload,
        rendered=rendered,
        dialect=dialect,
        context=breakout.context,
        breakout=breakout,
        balance=bal,
        risk=risk,
        notes=notes,
    )


def _build_notes(breakout, bal) -> list[str]:
    notes: list[str] = []
    ctx = breakout.context

    if ctx == Context.SQL_NUMERIC:
        notes.append(
            "Input sits in a numeric or expression position; no quote closure "
            "is needed to inject SQL."
        )
    elif breakout.quote_closed:
        notes.append(f"Payload closed the {ctx.value} context.")
    else:
        notes.append(f"Payload stayed inside the {ctx.value} context.")

    if breakout.separators:
        tokens = ", ".join(dict.fromkeys(breakout.separators))
        notes.append(f"Injected SQL tokens at the top level: {tokens}.")

    if breakout.comment_terminated:
        notes.append("Trailing statement is commented out.")

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unbalanced quotes")
        if bal.unbalanced_pairs:
            problems.append("unbalanced " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered statement has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered statement is syntactically balanced.")

    return notes
