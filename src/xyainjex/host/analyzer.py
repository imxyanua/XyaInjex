"""Top level HTTP host header injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import host_balance
from .breakout import detect_host_breakout, score_host_risk


def analyze_host(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an HTTP host header ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example ``Host: {INPUT}``
    or ``X-Forwarded-Host: {INPUT}``.
    """
    rendered = render(template, payload)
    breakout = detect_host_breakout(template, payload)
    bal = host_balance(rendered)
    risk = score_host_risk(breakout, bal.syntax_valid)

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
    header = (
        "X-Forwarded-Host" if breakout.context == Context.HOST_FORWARDED else "Host"
    )

    if breakout.command_injected:
        notes.append(f"Payload sets an attacker-controlled {header} value.")
    else:
        notes.append("Payload does not supply a usable host.")

    if "crlf" in seps:
        notes.append("CRLF in the value splits the response / injects headers.")
    if "userinfo-override" in seps:
        notes.append("An '@' makes the real host differ from what a prefix check sees.")
    if "absolute-url" in seps:
        notes.append("An absolute URL in the host value can bypass a naive check.")
    if "second-host" in seps:
        notes.append("A second host (comma / space) targets last-wins parsers.")
    if "internal" in seps:
        notes.append("Targets an internal host (routing / cache / SSRF).")
    if "attacker-host" in seps and "crlf" not in seps:
        notes.append(
            "A trusted host value poisons app-generated URLs (password reset) and "
            "the web cache."
        )

    return notes
