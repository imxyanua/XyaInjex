"""Top level expression-language injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import el_balance
from .breakout import detect_el_breakout, score_el_risk


def analyze_el(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an expression-language ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``Hello ${{INPUT}}`` (text), ``#{ {INPUT} }`` (SpEL), or a log message
    ``[INFO] user={INPUT}`` for Log4j-style JNDI lookups.
    """
    rendered = render(template, payload)
    breakout = detect_el_breakout(template, payload)
    bal = el_balance(rendered)
    risk = score_el_risk(breakout, bal.syntax_valid)

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

    if ctx == Context.EL_TEXT:
        if breakout.command_injected:
            notes.append("Payload opened an evaluated expression from literal text.")
        else:
            notes.append("Payload stayed in literal text.")
    elif ctx == Context.EL_EXPRESSION:
        notes.append("Injection point is already inside an evaluated expression.")
    else:
        if breakout.quote_closed:
            notes.append("Payload closed the string literal inside the expression.")
        else:
            notes.append("Payload stayed inside the expression string literal.")

    if "jndi" in breakout.separators:
        notes.append("Payload uses a JNDI lookup (Log4Shell; remote code loading).")
    if "gadget" in breakout.separators:
        notes.append(
            "Payload references an RCE gadget (Runtime/ProcessBuilder/T(...))."
        )

    if not bal.syntax_valid:
        notes.append(
            "Rendered expression is unbalanced: "
            + ", ".join(bal.unbalanced_pairs.keys() or ["string"])
            + "."
        )
    else:
        notes.append("Rendered expression is balanced.")

    return notes
