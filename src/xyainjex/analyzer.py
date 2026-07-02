"""Top level analysis entry point tying the engine together."""

from __future__ import annotations

from .models import AnalysisResult, Context, Dialect, Risk
from .shell.balance import balance
from .shell.breakout import detect_breakout, render, score_risk


def analyze(
    template: str, payload: str, dialect: Dialect = Dialect.POSIX
) -> AnalysisResult:
    """Analyze injecting ``payload`` into ``template``.

    ``template`` must contain the ``{INPUT}`` marker denoting the injection
    point, for example ``curl "{INPUT}"``. ``dialect`` selects the command
    language rules (POSIX shell, cmd.exe, or PowerShell).
    """
    rendered = render(template, payload)
    breakout = detect_breakout(template, payload, dialect)
    bal = balance(rendered, dialect)
    risk = score_risk(breakout, bal.syntax_valid)

    notes = _build_notes(breakout, bal, risk)

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


def _build_notes(breakout, bal, risk: Risk) -> list[str]:
    notes: list[str] = []
    ctx = breakout.context

    if ctx == Context.UNQUOTED:
        notes.append("Input is unquoted; no quote closure is required to break out.")
    elif breakout.quote_closed:
        q = ctx.quote_char or "the surrounding delimiter"
        notes.append(f"Payload closed the {ctx.value} context ({q}).")
    else:
        notes.append(
            f"Payload stayed inside the {ctx.value} context; no breakout detected."
        )

    if breakout.command_injected:
        seps = ", ".join(sorted(set(breakout.separators)))
        notes.append(
            f"{breakout.commands_created} command separator(s) injected at the "
            f"top level: {seps}."
        )

    if breakout.comment_terminated:
        notes.append("Trailing template content is commented out with '#'.")

    if not bal.syntax_valid:
        problems = []
        if not bal.quotes_balanced:
            problems.append("unbalanced quotes")
        if bal.unbalanced_pairs:
            problems.append("unbalanced " + ", ".join(bal.unbalanced_pairs.keys()))
        notes.append("Rendered command has " + "; ".join(problems) + ".")
    else:
        notes.append("Rendered command is syntactically balanced.")

    return notes
