"""Top level CSV / spreadsheet formula injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import csv_balance
from .breakout import detect_csv_breakout, score_csv_risk


def analyze_csv(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a CSV ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``name,{INPUT},email`` or just ``{INPUT}``.
    """
    rendered = render(template, payload)
    breakout = detect_csv_breakout(template, payload)
    bal = csv_balance(rendered)
    risk = score_csv_risk(breakout, bal.syntax_valid)

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

    if breakout.context == Context.CSV_CELL:
        notes.append("Input begins a cell.")
    else:
        notes.append("Input sits mid-cell; only a new cell can start a formula.")

    if breakout.command_injected:
        notes.append("A cell begins with a formula trigger and is evaluated.")
    else:
        notes.append("No cell begins with a formula trigger.")

    if "dangerous" in breakout.separators:
        notes.append(
            "Payload uses a command or exfiltration function (cmd|, DDE, "
            "HYPERLINK, WEBSERVICE, IMPORT...)."
        )

    return notes
