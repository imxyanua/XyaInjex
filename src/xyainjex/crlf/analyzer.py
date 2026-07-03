"""Top level CRLF injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, CrlfKind
from ..shell.breakout import render
from .balance import crlf_balance
from .breakout import detect_crlf_breakout, score_crlf_risk


def analyze_crlf(
    template: str, payload: str, kind: CrlfKind = CrlfKind.HEADER
) -> AnalysisResult:
    """Analyze injecting ``payload`` into a header value or log line.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``Location: {INPUT}`` or ``[INFO] user={INPUT}``.
    """
    rendered = render(template, payload)
    breakout = detect_crlf_breakout(template, payload, kind)
    bal = crlf_balance(rendered)
    risk = score_crlf_risk(breakout, kind, bal.syntax_valid)

    notes = _build_notes(breakout, kind)

    return AnalysisResult(
        template=template,
        payload=payload,
        rendered=rendered,
        dialect=kind,
        context=breakout.context,
        breakout=breakout,
        balance=bal,
        risk=risk,
        notes=notes,
    )


def _build_notes(breakout, kind: CrlfKind) -> list[str]:
    notes: list[str] = []
    tokens = breakout.separators

    if breakout.command_injected:
        notes.append(
            f"Payload injects {breakout.commands_created} raw line break(s) "
            f"({', '.join(t for t in tokens if t in ('CRLF', 'LF', 'CR'))})."
        )
    elif "encoded" in tokens:
        notes.append(
            "Payload contains encoded CR/LF sequences that may inject if the sink "
            "decodes them."
        )
    else:
        notes.append("Payload contains no line breaks.")

    if kind == CrlfKind.HEADER:
        if "double-CRLF" in tokens:
            notes.append(
                "A blank line ends the headers; the rest becomes the response body "
                "(response splitting)."
            )
        if "new-header" in tokens:
            notes.append("Payload injects a new header line.")
    elif breakout.command_injected:
        notes.append("Injected line breaks can forge log entries.")

    return notes
