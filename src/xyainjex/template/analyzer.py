"""Top level template injection (SSTI) analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context, TemplateEngine
from ..shell.breakout import render
from .balance import template_balance
from .breakout import detect_template_breakout, score_template_risk


def analyze_template(
    template: str, payload: str, engine: TemplateEngine = TemplateEngine.JINJA2
) -> AnalysisResult:
    """Analyze injecting ``payload`` into a template rendered by ``engine``.

    ``template`` must contain the ``{INPUT}`` marker denoting where untrusted
    input is concatenated into the template source, for example
    ``Hello {INPUT}`` or ``{{ user.{INPUT} }}``.
    """
    rendered = render(template, payload)
    breakout = detect_template_breakout(template, payload, engine)
    bal = template_balance(rendered, engine)
    risk = score_template_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal)

    return AnalysisResult(
        template=template,
        payload=payload,
        rendered=rendered,
        dialect=engine,
        context=breakout.context,
        breakout=breakout,
        balance=bal,
        risk=risk,
        notes=notes,
    )


def _build_notes(breakout, bal) -> list[str]:
    notes: list[str] = []
    ctx = breakout.context

    if ctx == Context.TEMPLATE_TEXT:
        if breakout.command_injected:
            notes.append(
                "Payload opened a template expression from literal text "
                "(server-side template injection)."
            )
        else:
            notes.append("Payload stayed in literal text; no expression opened.")
    elif ctx in (Context.TEMPLATE_EXPRESSION, Context.TEMPLATE_STATEMENT):
        notes.append(
            f"Injection point is already inside a {ctx.value} region and is "
            "evaluated server-side."
        )
    elif ctx == Context.TEMPLATE_STRING:
        if breakout.quote_closed:
            notes.append(
                "Payload closed the string literal inside the expression, "
                "reaching evaluated code."
            )
        else:
            notes.append("Payload stayed inside the expression string literal.")
    elif ctx == Context.TEMPLATE_COMMENT:
        if breakout.command_injected:
            notes.append("Payload escaped the comment and opened an expression.")
        else:
            notes.append("Payload stayed inside the template comment.")

    if breakout.separators:
        tokens = ", ".join(breakout.separators)
        notes.append(f"Opened template regions with: {tokens}.")

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unbalanced string literal")
        if bal.unbalanced_pairs:
            problems.append("unclosed " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered template has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered template is syntactically balanced.")

    return notes
