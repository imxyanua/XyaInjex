"""Exploit-path discovery and cross-dialect differential analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..corpus.seeds import corpus_seeds
from ..dispatch import BREAKOUT_LANGS, DIALECT_LANGS, analyze_lang, seed_payloads
from ..models import AnalysisResult, Risk
from .mutators import expand

# Re-exported so callers (CLI, API) share one source of truth.
_FUZZ_LANGS = BREAKOUT_LANGS
_DIALECT_LANGS = DIALECT_LANGS

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


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

    Seed payloads come from the language's mutation engine, matching divergent
    benchmark corpus cases for the same template, plus any ``extra_seeds``. Each
    seed is expanded with obfuscation mutators, every variant is analyzed, and
    the ones that inject a command are returned as exploit paths, deduplicated
    and ranked by risk.
    """
    if lang not in _FUZZ_LANGS:
        raise ValueError(
            "fuzzing supports " + ", ".join(_FUZZ_LANGS) + f", not {lang!r}"
        )

    corpus: dict[str, str] = {}  # payload -> strategy (first seen wins)
    for payload, strategy in corpus_seeds(template, lang, dialect):
        corpus.setdefault(payload, strategy)

    seeds = seed_payloads(template, lang, dialect, command)
    for seed in seeds:
        for payload, strategy in expand(seed, lang):
            corpus.setdefault(payload, strategy)

    for seed in extra_seeds or []:
        for payload, _strategy in expand(seed, lang):
            corpus.setdefault(payload, "extra")

    paths: list[ExploitPath] = []
    for payload, strategy in corpus.items():
        result = analyze_lang(template, payload, lang, dialect)
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


def parser_divergent(per_dialect: dict[str, dict], metric: str) -> bool:
    """Return True when dialects disagree on the chosen divergence metric."""
    if metric == "risk":
        values = {info["risk"] for info in per_dialect.values()}
    else:
        values = {info["command_injected"] for info in per_dialect.values()}
    return len(values) > 1


@dataclass
class DifferentialResult:
    template: str
    payload: str
    lang: str
    per_dialect: dict[str, dict] = field(default_factory=dict)
    metric: str = "command_injected"

    @property
    def divergent(self) -> bool:
        return parser_divergent(self.per_dialect, self.metric)

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "lang": self.lang,
            "divergent": self.divergent,
            "metric": self.metric,
            "per_dialect": self.per_dialect,
        }


def differential(
    template: str,
    payload: str,
    lang: str,
    dialects: list[str],
    metric: str | None = None,
) -> DifferentialResult:
    """Analyze one payload across several dialects to reveal parser divergence.

    A payload that injects under one dialect but not another is a parser
    differential: the same input is data to one engine and code to another.
    Only the dialect-selecting languages can diverge this way; a no-dialect
    analyzer has a single parser and nothing to compare.
    """
    if lang not in _DIALECT_LANGS:
        raise ValueError(
            "differential supports " + ", ".join(_DIALECT_LANGS) + f", not {lang!r}"
        )

    if metric is None:
        metric = "risk" if lang == "crlf" else "command_injected"

    per: dict[str, dict] = {}
    for dialect in dialects:
        result = analyze_lang(template, payload, lang, dialect)
        per[dialect] = {
            "risk": result.risk.value,
            "command_injected": result.breakout.command_injected,
            "context": result.context.value,
        }
    return DifferentialResult(
        template=template,
        payload=payload,
        lang=lang,
        per_dialect=per,
        metric=metric,
    )
