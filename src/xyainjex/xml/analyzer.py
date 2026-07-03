"""Top level XML injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import xml_balance
from .breakout import detect_xml_breakout, score_xml_risk


def analyze_xml(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an XML ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``<user><name>{INPUT}</name></user>`` or ``<user name="{INPUT}"/>``.
    """
    rendered = render(template, payload)
    breakout = detect_xml_breakout(template, payload)
    bal = xml_balance(rendered)
    risk = score_xml_risk(breakout, bal.syntax_valid)

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

    if ctx == Context.XML_TEXT:
        if breakout.command_injected:
            notes.append("Payload injected a new element into the document text.")
        else:
            notes.append("Payload stayed in element text.")
    else:
        label = {
            Context.XML_ATTR: "attribute",
            Context.XML_CDATA: "CDATA section",
            Context.XML_COMMENT: "comment",
        }.get(ctx, "region")
        if breakout.quote_closed:
            notes.append(f"Payload escaped the {label} and reached markup.")
        else:
            notes.append(f"Payload stayed inside the {label}.")

    if "xxe" in breakout.separators:
        notes.append("Payload declares an entity or DOCTYPE (possible XXE).")
    elif "entity" in breakout.separators:
        notes.append("Payload injects an entity reference.")

    if not bal.syntax_valid:
        notes.append(
            "Rendered XML is unbalanced: "
            + ", ".join(bal.unbalanced_pairs.keys())
            + "."
        )
    else:
        notes.append("Rendered XML is balanced.")

    return notes
