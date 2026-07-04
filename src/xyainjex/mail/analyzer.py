"""Top level email header / SMTP injection analysis entry point."""

from __future__ import annotations

from ..models import AnalysisResult, Context
from ..shell.breakout import render
from .balance import mail_balance
from .breakout import detect_mail_breakout, score_mail_risk


def analyze_mail(template: str, payload: str) -> AnalysisResult:
    """Analyze injecting ``payload`` into an email / SMTP ``template``.

    ``template`` must contain the ``{INPUT}`` marker, for example
    ``To: {INPUT}`` (header), ``Subject: {INPUT}`` (header), or
    ``RCPT TO:<{INPUT}>`` (SMTP command).
    """
    rendered = render(template, payload)
    breakout = detect_mail_breakout(template, payload)
    bal = mail_balance(rendered)
    risk = score_mail_risk(breakout, bal.syntax_valid)

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
        Context.MAIL_HEADER: "an email header value",
        Context.MAIL_BODY: "the message body",
        Context.SMTP_COMMAND: "an SMTP command line",
    }.get(ctx, "the message")
    seps = breakout.separators

    if breakout.command_injected:
        notes.append(f"Payload breaks out of {label} onto a new line.")
    else:
        notes.append(f"Payload stays within {label}.")

    if "smtp-smuggle" in seps:
        notes.append("Payload smuggles a raw SMTP command (RCPT TO / MAIL FROM / ...).")
    if "data-terminator" in seps:
        notes.append("Payload sends a lone '.' line that ends the DATA phase.")
    if "recipient" in seps:
        notes.append("Payload injects a recipient header (Bcc / Cc / To).")
    elif "new-header" in seps:
        notes.append("Payload injects a new email header.")
    if "body-injection" in seps:
        notes.append("A blank line starts an attacker-controlled message body.")
    if "encoded" in seps:
        notes.append("Line break is encoded; a web-to-mail layer may decode it.")

    return notes
