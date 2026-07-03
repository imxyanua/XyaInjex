"""Top level LDAP injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult
from ..shell.breakout import render
from .balance import ldap_balance
from .breakout import detect_ldap_breakout, score_ldap_risk


def analyze_ldap(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an LDAP filter ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``(&(uid={INPUT})(objectClass=person))``.
    """
    rendered = render(template, payload)
    breakout = detect_ldap_breakout(template, payload)
    bal = ldap_balance(rendered)
    risk = score_ldap_risk(breakout, bal.syntax_valid)

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

    if breakout.quote_closed:
        notes.append("Payload closed the enclosing filter assertion with ')'.")
    else:
        notes.append("Payload stayed inside the filter assertion value.")

    if breakout.command_injected:
        notes.append("Payload opened a new filter assertion, altering the query.")
    elif "*" in breakout.separators:
        notes.append("Payload injected a '*' wildcard.")

    if not bal.syntax_valid:
        notes.append(
            "Rendered filter has unbalanced parentheses "
            f"({bal.unbalanced_pairs.get('()', 0)} unclosed)."
        )
    else:
        notes.append("Rendered filter is balanced.")

    return notes
