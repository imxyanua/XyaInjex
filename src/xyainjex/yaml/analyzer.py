"""Top level YAML injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import yaml_balance
from .breakout import detect_yaml_breakout, score_yaml_risk


def analyze_yaml(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a YAML ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``name: {INPUT}`` or ``name: "{INPUT}"``.
    """
    rendered = render(template, payload)
    breakout = detect_yaml_breakout(template, payload)
    bal = yaml_balance(rendered)
    risk = score_yaml_risk(breakout, bal.syntax_valid)

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

    if ctx == Context.YAML_PLAIN:
        notes.append("Input sits in a plain (unquoted) scalar.")
    elif breakout.quote_closed:
        notes.append("Payload closed the quoted scalar.")
    else:
        notes.append("Payload stayed inside the quoted scalar.")

    if "tag" in breakout.separators:
        notes.append(
            "Payload injects a YAML tag (deserialization; RCE under an unsafe loader)."
        )
    if "key" in breakout.separators:
        notes.append("Payload injects a new mapping key.")
    if "newline" in breakout.separators:
        notes.append("Payload injects a line break.")

    if not bal.syntax_valid:
        notes.append("Rendered YAML has an unterminated quoted scalar.")
    else:
        notes.append("Rendered YAML is balanced.")

    return notes
