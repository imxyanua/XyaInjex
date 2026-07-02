"""Context aware payload mutation engine.

Given a command template, generate candidate breakout payloads, analyze each
one, and rank the variants that actually create an injected command.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Context, Risk
from .shell.context import analyze_context

# Command separators ordered from most to least commonly effective.
_SEPARATORS = [";", "&&", "||", "|", "\n", "&"]

# Command substitution wrappers, applied around the demo command.
_SUBSTITUTIONS = ["$({cmd})", "`{cmd}`"]

# Comment / terminator tokens used to swallow trailing template content.
_TERMINATORS = ["#", " #", ";#", "%23", ""]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class Candidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class MutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[Candidate] = field(default_factory=list)

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


def _closers(context: Context) -> list[str]:
    """Prefixes needed to escape the surrounding context."""
    quote = context.quote_char
    if quote is None:
        return [""]
    # Try closing the quote, and also a no-op prefix in case the parser is lax.
    return [quote, ""]


def _generate(context: Context, command: str) -> list[tuple[str, str]]:
    """Return (payload, strategy) pairs to try for a context."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    for closer in _closers(context):
        for sep in _SEPARATORS:
            for term in _TERMINATORS:
                add(f"{closer}{sep}{command}{term}", "separator")
                add(f"{closer}{sep} {command} {term}".rstrip(), "separator-spaced")
        for sub in _SUBSTITUTIONS:
            wrapped = sub.format(cmd=command)
            for term in _TERMINATORS:
                add(f"{closer}{wrapped}{term}", "substitution")

    return out


def mutate(template: str, command: str = "id") -> MutationResult:
    """Generate and rank breakout payloads for ``template``.

    ``command`` is the demonstration command embedded in generated payloads.
    """
    # Local import avoids a circular import at module load time.
    from .analyzer import analyze

    context = analyze_context(template)
    generated = _generate(context, command)

    candidates: list[Candidate] = []
    for payload, strategy in generated:
        result = analyze(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                Candidate(
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

    return MutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
