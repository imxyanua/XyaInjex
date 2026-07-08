"""Self-evolving parser-divergence discovery loop (Phase 9).

Starting from benchmark corpus seeds, mutate and fuzz candidate payloads,
validate each with differential analysis, and surface novel divergences not
already recorded in the built-in regression corpus.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .build import BUILD_LANGS, build
from .corpus.registry import BENCHMARK_LANGS, get_corpus
from .encode import encode
from .fuzz import differential, fuzz
from .fuzz.engine import parser_divergent

EVOLVE_LANGS = BENCHMARK_LANGS

_DEFAULT_ROUNDS = 3
_MAX_QUEUE = 40
_MAX_FUZZ_PATHS = 24
_MAX_ENCODE_VARIANTS = 16
_MAX_CROSS_TEMPLATES = 12

_RISK_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
}


@dataclass
class EvolveDiscovery:
    template: str
    payload: str
    metric: str
    strategy: str
    round: int
    per_dialect: dict[str, dict]
    score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "metric": self.metric,
            "strategy": self.strategy,
            "round": self.round,
            "score": self.score,
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
    stopped_reason: str | None = None

    @property
    def found(self) -> int:
        return len(self.discoveries)

    def to_dict(self, *, emit_corpus: bool = False) -> dict:
        data = {
            "lang": self.lang,
            "template": self.template,
            "dialects": self.dialects,
            "rounds_run": self.rounds_run,
            "candidates_tried": self.candidates_tried,
            "found": self.found,
            "stopped_reason": self.stopped_reason,
            "discoveries": [d.to_dict() for d in self.discoveries],
        }
        if emit_corpus and self.discoveries:
            data["corpus_snippets"] = corpus_snippets(self)
        return data


def discovery_score(per_dialect: dict[str, dict], metric: str) -> float:
    """Rank a divergence by dialect spread (inject split or risk delta)."""
    if not per_dialect:
        return 0.0
    if metric == "risk":
        risks = [_RISK_ORDER.get(info["risk"], 0) for info in per_dialect.values()]
        spread = max(risks) - min(risks)
        unique = len({info["risk"] for info in per_dialect.values()})
        return spread * 10.0 + unique * 5.0
    injects = [info["command_injected"] for info in per_dialect.values()]
    minority = min(sum(injects), len(injects) - sum(injects))
    return minority * 10.0 + len(injects) * 2.0


def corpus_case_snippet(
    discovery: EvolveDiscovery,
    case_id: str,
    note: str | None = None,
) -> str:
    """Format one discovery as a ``CorpusCase(...)`` Python snippet."""
    if note is None:
        note = (
            f"Evolved via {discovery.strategy} (round {discovery.round}, "
            f"score {discovery.score:.0f}); review before adding to the corpus."
        )
    return (
        "    CorpusCase(\n"
        f'        id="{case_id}",\n'
        f"        template={discovery.template!r},\n"
        f"        payload={discovery.payload!r},\n"
        f"        note={note!r},\n"
        "        divergent=True,\n"
        f"        metric={discovery.metric!r},\n"
        "    ),"
    )


def corpus_snippets(result: EvolveResult, id_prefix: str = "evolved") -> list[dict]:
    """Return review-ready ``CorpusCase`` snippets for each discovery."""
    snippets: list[dict] = []
    for index, discovery in enumerate(result.discoveries, start=1):
        slug = discovery.strategy.replace(":", "-").replace("/", "-")[:20]
        case_id = f"{id_prefix}-{result.lang}-{slug}-{index}"
        snippets.append(
            {
                "case_id": case_id,
                "snippet": corpus_case_snippet(discovery, case_id),
            }
        )
    return snippets


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


def _alternate_templates(
    cases: tuple, current: str, limit: int = _MAX_CROSS_TEMPLATES
) -> list[str]:
    """Other divergent corpus templates to try cross-template transfer on."""
    seen: set[str] = set()
    templates: list[str] = []
    for case in cases:
        if not case.divergent or case.template == current:
            continue
        if case.template in seen:
            continue
        seen.add(case.template)
        templates.append(case.template)
        if len(templates) >= limit:
            break
    return templates


def _budget_exceeded(
    *,
    candidates_tried: int,
    max_candidates: int | None,
    started: float,
    timeout: float | None,
) -> str | None:
    if max_candidates is not None and candidates_tried >= max_candidates:
        return "max_candidates"
    if timeout is not None and (time.monotonic() - started) >= timeout:
        return "timeout"
    return None


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

    diff = differential(template, payload, lang, dialects, metric=metric)
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
            score=discovery_score(diff.per_dialect, metric),
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
    *,
    cross_template: bool = True,
    max_candidates: int | None = None,
    timeout: float | None = None,
) -> EvolveResult:
    """Search for novel parser-divergence payloads beyond the benchmark corpus.

    Each round fuzzes and re-tests seeds; discoveries are payloads whose
    template/payload pair is divergent across dialects but not yet in the corpus.
    Discoveries are ranked by ``discovery_score`` (dialect spread).
    """
    lang = lang.strip().lower()
    if lang not in EVOLVE_LANGS:
        raise ValueError(
            "evolve supports " + ", ".join(EVOLVE_LANGS) + f", not {lang!r}"
        )

    max_rounds = max(1, min(max_rounds, 10))
    if max_candidates is not None:
        max_candidates = max(1, max_candidates)
    if timeout is not None:
        timeout = max(0.1, timeout)

    cases, dialects = get_corpus(lang)
    metric = _metric_for_lang(lang)
    known = {(c.template, c.payload) for c in cases}
    tried: set[tuple[str, str]] = set()
    discoveries: list[EvolveDiscovery] = []
    candidates_tried = 0
    stopped_reason: str | None = None
    started = time.monotonic()

    queue = _initial_seeds(lang, cases, template, dialect, goal)
    rounds_run = 0

    def try_candidate(tmpl: str, payload: str, strategy: str, round_n: int) -> bool:
        nonlocal candidates_tried, stopped_reason
        if stopped_reason is not None:
            return False
        reason = _budget_exceeded(
            candidates_tried=candidates_tried,
            max_candidates=max_candidates,
            started=started,
            timeout=timeout,
        )
        if reason is not None:
            stopped_reason = reason
            return False

        candidates_tried += 1
        found = _record_discovery(
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
        )
        if not found or not cross_template:
            return found

        for alt_tmpl in _alternate_templates(cases, tmpl):
            if stopped_reason is not None:
                break
            reason = _budget_exceeded(
                candidates_tried=candidates_tried,
                max_candidates=max_candidates,
                started=started,
                timeout=timeout,
            )
            if reason is not None:
                stopped_reason = reason
                break
            candidates_tried += 1
            alt_strategy = f"cross-template:{alt_tmpl[:24]}"
            if _record_discovery(
                template=alt_tmpl,
                payload=payload,
                lang=lang,
                dialects=dialects,
                metric=metric,
                strategy=alt_strategy,
                round_n=round_n,
                known=known,
                tried=tried,
                discoveries=discoveries,
            ):
                found = True
        return found

    for round_n in range(1, max_rounds + 1):
        if not queue or stopped_reason is not None:
            break
        rounds_run = round_n
        next_queue: list[tuple[str, str, str]] = []

        for tmpl, payload, strategy in queue[:_MAX_QUEUE]:
            if stopped_reason is not None:
                break
            if try_candidate(tmpl, payload, strategy, round_n):
                next_queue.append((tmpl, payload, strategy))

            if stopped_reason is not None:
                break

            fuzz_result = fuzz(tmpl, lang=lang, dialect=dialect, extra_seeds=[payload])
            for path in fuzz_result.paths[:_MAX_FUZZ_PATHS]:
                if stopped_reason is not None:
                    break
                if try_candidate(tmpl, path.payload, path.strategy, round_n):
                    next_queue.append((tmpl, path.payload, path.strategy))

            if stopped_reason is not None:
                break

            try:
                enc = encode(payload, lang=lang, template=tmpl, dialect=dialect)
            except ValueError:
                enc = None
            if enc is not None:
                for variant in enc.variants[:_MAX_ENCODE_VARIANTS]:
                    if stopped_reason is not None:
                        break
                    strategy = f"encode:{variant.strategy}"
                    if try_candidate(tmpl, variant.payload, strategy, round_n):
                        next_queue.append((tmpl, variant.payload, strategy))

        queue = next_queue

    discoveries.sort(key=lambda d: d.score, reverse=True)

    return EvolveResult(
        lang=lang,
        template=template,
        dialects=dialects,
        rounds_run=rounds_run,
        candidates_tried=candidates_tried,
        discoveries=discoveries,
        stopped_reason=stopped_reason,
    )
