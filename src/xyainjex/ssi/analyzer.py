"""Top level Server-Side Includes (SSI) injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult
from ..shell.breakout import render
from .balance import ssi_balance
from .breakout import detect_ssi_breakout, score_ssi_risk


def analyze_ssi(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an SSI-parsed page ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``<html><body>Hello {INPUT}</body></html>``.
    """
    rendered = render(template, payload)
    breakout = detect_ssi_breakout(template, payload)
    bal = ssi_balance(rendered)
    risk = score_ssi_risk(breakout, bal.syntax_valid)

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

    if breakout.command_injected:
        directives = [t for t in breakout.separators if t not in ("rce", "file-read")]
        notes.append("Injected SSI directive(s): " + ", ".join(directives) + ".")
        if "rce" in breakout.separators:
            notes.append("#exec reaches command execution.")
        elif "file-read" in breakout.separators:
            notes.append("#include can read files or reach internal URLs.")
        else:
            notes.append("Directive discloses information (echo/printenv/config).")
    elif "partial-exec" in breakout.separators:
        notes.append("Payload opens an #exec directive but does not close it.")
    else:
        notes.append("Payload contains no complete SSI directive.")

    return notes
