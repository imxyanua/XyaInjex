"""Top level prototype-pollution analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import prototype_balance
from .breakout import detect_prototype_breakout, score_prototype_risk


def analyze_prototype(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a merged object ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``{INPUT}``
    (the input is the merged JSON body), ``{"user": {INPUT}}`` (a JSON value), or
    ``settings[{INPUT}]=1`` (a property path).
    """
    rendered = render(template, payload)
    breakout = detect_prototype_breakout(template, payload)
    bal = prototype_balance(rendered)
    risk = score_prototype_risk(breakout, bal.syntax_valid)

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
    vector = (
        "a property path" if breakout.context == Context.PP_PATH else "a JSON object"
    )

    if breakout.command_injected:
        notes.append(f"Payload pollutes Object.prototype through {vector}.")
    elif seps & {"proto-key", "constructor-key", "prototype-key"}:
        notes.append(
            "Payload names a prototype key but does not set a property under it."
        )
    else:
        notes.append("Payload contains no prototype-pollution key.")

    if "constructor-key" in seps and "prototype-key" in seps:
        notes.append(
            "Uses the constructor.prototype chain (bypasses a __proto__ filter)."
        )
    if "gadget" in seps:
        notes.append("Sets a known RCE gadget property (e.g. NODE_OPTIONS / execArgv).")

    return notes
