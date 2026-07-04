"""Top level path traversal / LFI analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import path_balance
from .breakout import detect_path_breakout, score_path_risk


def analyze_path(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a filesystem path ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``/var/www/uploads/{INPUT}`` (base directory), ``include('pages/{INPUT}.php')``
    (fixed extension), or ``{INPUT}`` (the whole path).
    """
    rendered = render(template, payload)
    breakout = detect_path_breakout(template, payload)
    bal = path_balance(rendered)
    risk = score_path_risk(breakout, bal.syntax_valid)

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
    ctx = breakout.context
    label = {
        Context.PATH_FULL: "the whole path",
        Context.PATH_BASE: "a base directory",
        Context.PATH_EXT: "a path with a fixed suffix",
    }.get(ctx, "the path")
    seps = breakout.separators

    if breakout.command_injected:
        notes.append(f"Payload in {label} escapes the intended file.")
    else:
        notes.append(f"Payload in {label} stays within the intended file.")

    if "traversal" in seps:
        notes.append("Payload climbs out with a ../ traversal sequence.")
    if "encoded" in seps:
        notes.append("Traversal is percent-encoded to evade a naive filter.")
    if "absolute" in seps:
        notes.append("Payload supplies an absolute path (resets the base).")
    if "remote-scheme" in seps:
        notes.append("Remote scheme: remote file inclusion / content fetch.")
    if "rce-wrapper" in seps:
        notes.append("Dangerous wrapper (php://input / expect:// / data://) -> RCE.")
    if "read-wrapper" in seps:
        notes.append("Read wrapper (php://filter / file://) discloses file source.")
    if "extension-bypass" in seps:
        notes.append("Null byte truncates the appended extension.")
    if "sensitive-file" in seps:
        notes.append("Target names a well-known sensitive file.")

    return notes
