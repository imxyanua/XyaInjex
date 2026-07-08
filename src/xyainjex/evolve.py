"""Self-evolving parser-divergence discovery loop (Phase 9).

Starting from benchmark corpus seeds, mutate and fuzz candidate payloads,
validate each with differential analysis, and surface novel divergences not
already recorded in the built-in regression corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .build import BUILD_LANGS, build
from .corpus.registry import BENCHMARK_LANGS, get_corpus
from .fuzz import differential, fuzz
from .fuzz.engine import parser_divergent

EVOLVE_LANGS = BENCHMARK_LANGS

_DEFAULT_ROUNDS = 3
_MAX_QUEUE = 40
_MAX_FUZZ_PATHS = 24


@dataclass
class EvolveDiscovery:
    template: str
    payload: str
    metric: str
    strategy: str
    round: int
    per_dialect: dict[str, dict]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "metric": self.metric,
            "strategy": self.strategy,
            "round": self.round,
            "per_dialect": self.per_dialect,
        }


@dataclass
class EvolveResult:
    lang: str
    template: str | None
    dialects: list[str]
    rounds_run: int
    candidates_tried: int
    discoveries: list[EvolveDiscovery] = field(default_factory=list)

    @property
    def found(self) -> int:
        return len(self.discoveries)

    def to_dict(self) -> dict:
        return {
            "lang": self.lang,
            "template": self.template,
            "dialects": self.dialects,
            "rounds_run": self.rounds_run,
            "candidates_tried": self.candidates_tried,
            "found": self.found,
            "discoveries": [d.to_dict() for d in self.discoveries],
        }


def _metric_for_lang(lang: str) -> str:
    return "risk" if lang == "crlf" else "command_injected"


def _initial_seeds(
    lang: str,
    cases: tuple,
    template: str | None,
    dialect: str | None,
    goal: str | None,
) -> list[tuple[str, str, str]]:
    seeds: list[tuple[str, str, str]] = []

    for case in cases:
        if not case.divergent:
            continue
        if template is not None and case.template != template:
            continue
        seeds.append((case.template, case.payload, f"corpus:{case.id}"))

    if template and lang in BUILD_LANGS:
        built = build(template, lang=lang, goal=goal, dialect=dialect)
        if built.validated and built.payload:
            seeds.append((template, built.payload, "build"))

    return seeds


def _record_discovery(
    *,
    template: str,
    payload: str,
    lang: str,
    dialects: list[str],
    metric: str,
    strategy: str,
    round_n: int,
    known: set[tuple[str, str]],
    tried: set[tuple[str, str]],
    discoveries: list[EvolveDiscovery],
) -> bool:
    key = (template, payload)
    if key in tried:
        return False
    tried.add(key)

    diff = differential(template, payload, lang, dialects)
    if not parser_divergent(diff.per_dialect, metric):
        return False
    if key in known:
        return False

    discoveries.append(
        EvolveDiscovery(
            template=template,
            payload=payload,
            metric=metric,
            strategy=strategy,
            round=round_n,
            per_dialect=diff.per_dialect,
        )
    )
    known.add(key)
    return True


def evolve(
    lang: str = "shell",
    template: str | None = None,
    dialect: str | None = None,
    max_rounds: int = _DEFAULT_ROUNDS,
    goal: str | None = None,
) -> EvolveResult:
    """Search for novel parser-divergence payloads beyond the benchmark corpus.

    Each round fuzzes and re-tests seeds; discoveries are payloads whose
    template/payload pair is divergent across dialects but not yet in the corpus.
    """
    lang = lang.strip().lower()
    if lang not in EVOLVE_LANGS:
        raise ValueError(
            "evolve supports " + ", ".join(EVOLVE_LANGS) + f", not {lang!r}"
        )

    max_rounds = max(1, min(max_rounds, 10))
    cases, dialects = get_corpus(lang)
    metric = _metric_for_lang(lang)
    known = {(c.template, c.payload) for c in cases}
    tried: set[tuple[str, str]] = set()
    discoveries: list[EvolveDiscovery] = []
    candidates_tried = 0

    queue = _initial_seeds(lang, cases, template, dialect, goal)
    rounds_run = 0

    for round_n in range(1, max_rounds + 1):
        if not queue:
            break
        rounds_run = round_n
        next_queue: list[tuple[str, str, str]] = []

        for tmpl, payload, strategy in queue[:_MAX_QUEUE]:
            candidates_tried += 1
            if _record_discovery(
                template=tmpl,
                payload=payload,
                lang=lang,
                dialects=dialects,
                metric=metric,
                strategy=strategy,
                round_n=round_n,
                known=known,
                tried=tried,
                discoveries=discoveries,
            ):
                next_queue.append((tmpl, payload, strategy))

            fuzz_result = fuzz(
                tmpl, lang=lang, dialect=dialect, extra_seeds=[payload]
            )
            for path in fuzz_result.paths[:_MAX_FUZZ_PATHS]:
                candidates_tried += 1
                if _record_discovery(
                    template=tmpl,
                    payload=path.payload,
                    lang=lang,
                    dialects=dialects,
                    metric=metric,
                    strategy=path.strategy,
                    round_n=round_n,
                    known=known,
                    tried=tried,
                    discoveries=discoveries,
                ):
                    next_queue.append((tmpl, path.payload, path.strategy))

        queue = next_queue

    return EvolveResult(
        lang=lang,
        template=template,
        dialects=dialects,
        rounds_run=rounds_run,
        candidates_tried=candidates_tried,
        discoveries=discoveries,
    )
