"""Exploit-path discovery and cross-dialect differential analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analyzer import analyze
from ..dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from ..models import AnalysisResult, Risk
from ..mutation import mutate
from ..sql import analyze_sql, mutate_sql
from ..template import analyze_template, mutate_template
from .mutators import expand

_FUZZ_LANGS = ("shell", "sql", "template")

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


def _analyze(
    template: str, payload: str, lang: str, dialect: str | None
) -> AnalysisResult:
    if lang == "sql":
        return analyze_sql(template, payload, parse_sql_dialect(dialect or "mysql"))
    if lang == "template":
        return analyze_template(
            template, payload, parse_template_engine(dialect or "jinja2")
        )
    return analyze(template, payload, parse_dialect(dialect or "posix"))


def _seed_payloads(
    template: str, lang: str, dialect: str | None, command: str
) -> list[str]:
    if lang == "sql":
        result = mutate_sql(template, parse_sql_dialect(dialect or "mysql"))
    elif lang == "template":
        result = mutate_template(template, parse_template_engine(dialect or "jinja2"))
    else:
        result = mutate(
            template, command=command, dialect=parse_dialect(dialect or "posix")
        )
    return [c.payload for c in result.candidates]


def _stages(result: AnalysisResult) -> list[str]:
    b = result.breakout
    stages = ["context"]
    if b.quote_closed:
        stages.append("quote-closure")
    if b.command_injected:
        stages.append("injection")
    if b.comment_terminated:
        stages.append("comment-truncation")
    stages.append("execution" if b.command_injected else "contained")
    return stages


@dataclass
class ExploitPath:
    payload: str
    risk: Risk
    context: str
    syntax_valid: bool
    strategy: str
    stages: list[str]

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "risk": self.risk.value,
            "context": self.context,
            "syntax_valid": self.syntax_valid,
            "strategy": self.strategy,
            "stages": self.stages,
        }


@dataclass
class FuzzResult:
    template: str
    lang: str
    dialect: str | None
    generated: int
    valid: int
    paths: list[ExploitPath] = field(default_factory=list)

    @property
    def contexts_reached(self) -> list[str]:
        return sorted({p.context for p in self.paths})

    @property
    def strategies(self) -> list[str]:
        return sorted({p.strategy for p in self.paths})

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "lang": self.lang,
            "dialect": self.dialect,
            "generated": self.generated,
            "valid": self.valid,
            "contexts_reached": self.contexts_reached,
            "strategies": self.strategies,
            "paths": [p.to_dict() for p in self.paths],
        }


def fuzz(
    template: str,
    lang: str = "shell",
    dialect: str | None = None,
    command: str = "id",
    extra_seeds: list[str] | None = None,
) -> FuzzResult:
    """Discover breakout payloads for ``template`` by expanding and testing.

    Seed payloads come from the language's mutation engine (context aware) plus
    any ``extra_seeds``. Each seed is expanded with obfuscation mutators, every
    variant is analyzed, and the ones that inject a command are returned as
    exploit paths, deduplicated and ranked by risk.
    """
    if lang not in _FUZZ_LANGS:
        raise ValueError(f"fuzzing supports {_FUZZ_LANGS}, not {lang!r}")

    seeds = _seed_payloads(template, lang, dialect, command)
    seeds += extra_seeds or []

    corpus: dict[str, str] = {}  # payload -> strategy (first seen wins)
    for seed in seeds:
        for payload, strategy in expand(seed, lang):
            corpus.setdefault(payload, strategy)

    paths: list[ExploitPath] = []
    for payload, strategy in corpus.items():
        result = _analyze(template, payload, lang, dialect)
        if result.breakout.command_injected:
            paths.append(
                ExploitPath(
                    payload=payload,
                    risk=result.risk,
                    context=result.context.value,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                    stages=_stages(result),
                )
            )

    paths.sort(
        key=lambda p: (_RISK_ORDER[p.risk], p.syntax_valid, -len(p.payload)),
        reverse=True,
    )

    return FuzzResult(
        template=template,
        lang=lang,
        dialect=dialect,
        generated=len(corpus),
        valid=len(paths),
        paths=paths,
    )


@dataclass
class DifferentialResult:
    template: str
    payload: str
    lang: str
    per_dialect: dict[str, dict] = field(default_factory=dict)

    @property
    def divergent(self) -> bool:
        injected = {v["command_injected"] for v in self.per_dialect.values()}
        return len(injected) > 1

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "lang": self.lang,
            "divergent": self.divergent,
            "per_dialect": self.per_dialect,
        }


def differential(
    template: str, payload: str, lang: str, dialects: list[str]
) -> DifferentialResult:
    """Analyze one payload across several dialects to reveal parser divergence.

    A payload that injects under one dialect but not another is a parser
    differential: the same input is data to one engine and code to another.
    """
    if lang not in _FUZZ_LANGS:
        raise ValueError(f"differential supports {_FUZZ_LANGS}, not {lang!r}")

    per: dict[str, dict] = {}
    for dialect in dialects:
        result = _analyze(template, payload, lang, dialect)
        per[dialect] = {
            "risk": result.risk.value,
            "command_injected": result.breakout.command_injected,
            "context": result.context.value,
        }
    return DifferentialResult(
        template=template, payload=payload, lang=lang, per_dialect=per
    )
