"""Top level SSRF (server-side request forgery) analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import ssrf_balance
from .breakout import detect_ssrf_breakout, score_ssrf_risk


def analyze_ssrf(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into a fetched URL ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``http://api.example.com/fetch?url={INPUT}`` (query), ``http://{INPUT}/``
    (host), or ``{INPUT}`` (the whole URL).
    """
    rendered = render(template, payload)
    breakout = detect_ssrf_breakout(template, payload)
    bal = ssrf_balance(rendered)
    risk = score_ssrf_risk(breakout, bal.syntax_valid)

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
        Context.SSRF_URL: "the full request URL",
        Context.SSRF_HOST: "the URL host",
        Context.SSRF_PATH: "the URL path",
        Context.SSRF_QUERY: "a query-string value",
    }.get(ctx, "the URL")
    seps = breakout.separators

    if breakout.command_injected:
        notes.append(f"Payload in {label} redirects the server's request.")
    else:
        notes.append(f"Payload in {label} stays on the intended target.")

    if "metadata" in seps:
        notes.append("Target is a cloud metadata endpoint (credential theft).")
    if "loopback" in seps:
        notes.append("Target resolves to the loopback interface.")
    if "private-ip" in seps:
        notes.append("Target resolves to a private / link-local address.")
    if "obfuscated-ip" in seps:
        notes.append("Address is obfuscated (decimal / hex / octal) to evade filters.")
    if "userinfo-override" in seps:
        notes.append("An '@' authority override points the real host past a filter.")
    if "scheme-change" in seps:
        schemes = [s for s in seps if s in ("file", "gopher", "dict", "netdoc")]
        if schemes:
            notes.append(f"Payload switches to the {schemes[0]}: scheme.")
        else:
            notes.append("Payload switches to a non-HTTP scheme.")
    if "protocol-relative" in seps:
        notes.append("Protocol-relative URL (//host) overrides the host.")

    return notes
