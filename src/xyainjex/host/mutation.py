"""HTTP host header injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_host_context

_HEADER_BODIES = [
    ("evil.example.com\r\nX-Forwarded-Host: evil.example.com", "crlf-inject"),
    ("expected.example.com@evil.example.com", "userinfo-override"),
    ("expected.example.com, evil.example.com", "second-host"),
    ("localhost", "internal"),
    ("evil.example.com", "host-poison"),
]

_FORWARDED_BODIES = [
    ("evil.example.com", "forwarded-host"),
    ("evil.example.com:8080", "forwarded-port"),
    ("localhost", "internal"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class HostCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class HostMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[HostCandidate] = field(default_factory=list)

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
    if context == Context.HOST_FORWARDED:
        return _FORWARDED_BODIES
    return _HEADER_BODIES


def mutate_host(template: str) -> HostMutationResult:
    """Generate and rank host-header injection payloads for ``template``."""
    from .analyzer import analyze_host

    context = analyze_host_context(template)
    generated = _bodies(context)

    candidates: list[HostCandidate] = []
    for payload, strategy in generated:
        result = analyze_host(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                HostCandidate(
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

    return HostMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
