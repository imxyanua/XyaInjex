"""Fuzz seed payloads derived from parser-divergence benchmark cases."""

from __future__ import annotations

from ..dispatch import analyze_lang
from .registry import BENCHMARK_LANGS, get_corpus

__all__ = ["corpus_seeds"]


def corpus_seeds(
    template: str, lang: str, dialect: str | None = None
) -> list[tuple[str, str]]:
    """Return corpus payloads that break out for ``template`` under ``dialect``.

    Each item is ``(payload, strategy)`` where ``strategy`` is ``corpus:<case_id>``.
    Only divergent benchmark cases whose template matches and whose payload injects
    under the active dialect are returned.
    """
    key = lang.strip().lower()
    if key not in BENCHMARK_LANGS:
        return []
    cases, _ = get_corpus(key)
    seeds: list[tuple[str, str]] = []
    for case in cases:
        if not case.divergent or case.template != template:
            continue
        result = analyze_lang(template, case.payload, key, dialect)
        if result.breakout.command_injected:
            seeds.append((case.payload, f"corpus:{case.id}"))
    return seeds
