"""Server-side template injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk, TemplateEngine
from .context import analyze_template_context
from .engines import COMMENT, EXPR, get_template_spec

# Probe expressions that demonstrate evaluation in most engines.
_BODIES = ["7*7", "7*'7'", "config", "self", "''.__class__"]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class TemplateCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class TemplateMutationResult:
    template: str
    engine: TemplateEngine
    context: Context
    generated: int
    valid: int
    candidates: list[TemplateCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "engine": self.engine.value,
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


def _region_defs(engine: TemplateEngine):
    spec = get_template_spec(engine)
    expr = next((r for r in spec.regions if r.kind == EXPR), None)
    comment = next((r for r in spec.regions if r.kind == COMMENT), None)
    return expr, comment


def _generate(context: Context, engine: TemplateEngine) -> list[tuple[str, str]]:
    expr, comment = _region_defs(engine)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload and payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context in (Context.TEMPLATE_EXPRESSION, Context.TEMPLATE_STATEMENT):
        for body in _BODIES:
            add(body, "direct-expression")
        return out

    if context == Context.TEMPLATE_STRING:
        for quote in ("'", '"'):
            add(quote, "close-string")
            for body in _BODIES:
                add(f"{quote}+{body}+{quote}", "close-string")
        return out

    if expr is None:
        return out

    if context == Context.TEMPLATE_COMMENT:
        for _, close in [(comment.open, comment.close)] if comment else []:
            for body in _BODIES:
                add(f"{close}{expr.open}{body}{expr.close}", "escape-comment")
        return out

    # TEMPLATE_TEXT
    for body in _BODIES:
        add(f"{expr.open}{body}{expr.close}", "open-expression")
        add(f"{expr.open} {body} {expr.close}", "open-expression")
    return out


def mutate_template(
    template: str, engine: TemplateEngine = TemplateEngine.JINJA2
) -> TemplateMutationResult:
    """Generate and rank SSTI payloads for ``template``."""
    from .analyzer import analyze_template

    context = analyze_template_context(template, engine)
    generated = _generate(context, engine)

    candidates: list[TemplateCandidate] = []
    for payload, strategy in generated:
        result = analyze_template(template, payload, engine)
        if result.breakout.command_injected:
            candidates.append(
                TemplateCandidate(
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

    return TemplateMutationResult(
        template=template,
        engine=engine,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
