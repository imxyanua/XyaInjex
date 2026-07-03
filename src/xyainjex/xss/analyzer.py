"""Top level HTML / XSS injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import xss_balance
from .breakout import detect_xss_breakout, score_xss_risk


def analyze_xss(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an HTML ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``<div>{INPUT}</div>`` (text), ``<img src="{INPUT}">`` (attribute), or
    ``<script>var x = '{INPUT}';</script>`` (script).
    """
    rendered = render(template, payload)
    breakout = detect_xss_breakout(template, payload)
    bal = xss_balance(rendered)
    risk = score_xss_risk(breakout, bal.syntax_valid)

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
    label = {
        Context.HTML_TEXT: "element text",
        Context.HTML_ATTR: "an attribute",
        Context.HTML_SCRIPT: "a script block",
        Context.HTML_COMMENT: "a comment",
    }.get(ctx, "the document")

    if breakout.command_injected:
        notes.append(f"Payload broke out of {label} into HTML markup.")
    else:
        notes.append(f"Payload stayed within {label}.")

    if "script" in breakout.separators:
        notes.append("Payload injects a <script> element.")
    if "event-handler" in breakout.separators:
        notes.append("Payload injects an on* event handler.")
    if "js-url" in breakout.separators:
        notes.append("Payload uses a javascript: URL.")
    if "script-close" in breakout.separators:
        notes.append("Payload closes the script block with </script>.")

    if not bal.syntax_valid:
        notes.append(
            "Rendered HTML is unbalanced: "
            + ", ".join(bal.unbalanced_pairs.keys())
            + "."
        )
    else:
        notes.append("Rendered HTML is balanced.")

    return notes
