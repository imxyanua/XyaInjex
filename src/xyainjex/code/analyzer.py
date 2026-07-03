"""Top level code (eval sink) injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, CodeLang, Context
from ..shell.breakout import render
from .balance import code_balance
from .breakout import detect_code_breakout, score_code_risk


def analyze_code(
    template: str, payload: str, lang: CodeLang = CodeLang.PYTHON
) -> AnalysisResult:
    """Analyze injecting ``payload`` into a code ``template`` for ``lang``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``eval("result = " + "{INPUT}")`` or ``eval({INPUT})``.
    """
    rendered = render(template, payload)
    breakout = detect_code_breakout(template, payload, lang)
    bal = code_balance(rendered, lang)
    risk = score_code_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal)

    return AnalysisResult(
        template=template,
        payload=payload,
        rendered=rendered,
        dialect=lang,
        context=breakout.context,
        breakout=breakout,
        balance=bal,
        risk=risk,
        notes=notes,
    )


def _build_notes(breakout, bal) -> list[str]:
    notes: list[str] = []
    ctx = breakout.context

    if ctx == Context.CODE_STRING:
        if breakout.quote_closed:
            notes.append("Payload closed the string literal, reaching code position.")
        else:
            notes.append("Payload stayed inside the string literal.")
    elif ctx == Context.CODE_TEMPLATE:
        if breakout.substitution_injected:
            notes.append("Payload opened a ${...} template substitution.")
        elif breakout.quote_closed:
            notes.append("Payload closed the template literal.")
        else:
            notes.append("Payload stayed inside the template literal.")
    else:
        notes.append("Input sits in a code (expression) position.")

    sinks = [t for t in breakout.separators if t != ";"]
    if sinks:
        notes.append("Reached sink identifier(s): " + ", ".join(dict.fromkeys(sinks)))
    if ";" in breakout.separators:
        notes.append("Injected a statement separator ';'.")

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unterminated string or template")
        if bal.unbalanced_pairs:
            problems.append("unbalanced " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered code has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered code is balanced.")

    return notes
