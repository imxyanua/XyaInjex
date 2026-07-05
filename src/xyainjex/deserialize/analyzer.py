"""Top level insecure-deserialization analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult
from ..shell.breakout import render
from .balance import deserialize_balance
from .breakout import detect_deserialize_breakout, score_deserialize_risk

_FORMAT_LABEL = {
    "java": "a Java serialized stream",
    "php-object": "a PHP serialized object",
    "php-data": "PHP serialized data",
    "python-pickle": "a Python pickle",
    "dotnet": "a .NET BinaryFormatter blob",
    "ruby": "a Ruby Marshal blob",
}


def analyze_deserialize(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a deserialization sink ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``{INPUT}``
    (the input is deserialized directly) or ``session={INPUT}`` (a cookie value).
    """
    rendered = render(template, payload)
    breakout = detect_deserialize_breakout(template, payload)
    bal = deserialize_balance(rendered)
    risk = score_deserialize_risk(breakout, bal.syntax_valid)

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
    seps = breakout.separators

    formats = [_FORMAT_LABEL[t] for t in seps if t in _FORMAT_LABEL]
    if breakout.command_injected:
        notes.append(f"Payload is {formats[0]} that the runtime would deserialize.")
    elif "php-data" in seps:
        notes.append("Payload is serialized data (no object instantiation).")
    else:
        notes.append("Payload is not recognized serialized data.")

    if "encoded" in seps:
        notes.append("Serialized data is base64 / hex encoded.")
    if "gadget" in seps:
        notes.append("Carries a known deserialization RCE gadget marker.")

    return notes
