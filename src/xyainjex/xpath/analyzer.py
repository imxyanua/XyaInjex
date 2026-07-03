"""Top level XPath injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import xpath_balance
from .breakout import detect_xpath_breakout, score_xpath_risk


def analyze_xpath(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an XPath ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``//user[name = '{INPUT}']``.
    """
    rendered = render(template, payload)
    breakout = detect_xpath_breakout(template, payload)
    bal = xpath_balance(rendered)
    risk = score_xpath_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal)

    # XPath has no dialects, so the result's dialect field is left unset.
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

    if ctx == Context.XPATH_STRING:
        if breakout.quote_closed:
            notes.append("Payload closed the XPath string literal.")
        else:
            notes.append("Payload stayed inside the XPath string literal.")
    else:
        notes.append(
            "Input sits in an XPath expression position; no quote closure is "
            "needed to inject logic."
        )

    if breakout.separators:
        tokens = ", ".join(dict.fromkeys(breakout.separators))
        notes.append(f"Injected XPath logic tokens: {tokens}.")

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unbalanced string literal")
        if bal.unbalanced_pairs:
            problems.append("unbalanced " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered expression has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered expression is syntactically balanced.")

    return notes
