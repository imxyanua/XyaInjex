"""Top level argument / option injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import argument_balance
from .breakout import detect_argument_breakout, score_argument_risk


def analyze_argument(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` as an argument of ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``curl {INPUT}``
    (the input is its own argument) or ``--name={INPUT}`` (a glued value). The
    command is assumed to run without a shell (an argv list), so this is option
    injection, not shell-metacharacter injection.
    """
    rendered = render(template, payload)
    breakout = detect_argument_breakout(template, payload)
    bal = argument_balance(rendered)
    risk = score_argument_risk(breakout, bal.syntax_valid)

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
    seps = set(breakout.separators)

    if breakout.command_injected:
        notes.append("Payload starts a new argument with a '-', parsed as an option.")
    elif breakout.context == Context.ARG_VALUE and seps & {
        "option-injection",
        "new-option",
    }:
        notes.append(
            "The input is glued to a preceding token; option injection here needs "
            "the runner to word-split the value."
        )
    elif seps & {"option-injection", "new-option"}:
        notes.append("Payload contains an option pattern.")
    else:
        notes.append("Payload does not introduce a command-line option.")

    if "rce-flag" in seps:
        notes.append("Injects a flag that reaches command execution.")
    if "file-flag" in seps:
        notes.append("Injects a flag that reads or writes an arbitrary file.")
    if "end-of-options" in seps:
        notes.append("Payload contains the '--' end-of-options separator.")

    return notes
