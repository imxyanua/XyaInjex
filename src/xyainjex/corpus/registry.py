"""Registry of built-in benchmark corpora."""

from __future__ import annotations

from .models import CorpusCase
from .shell import SHELL_CASES, SHELL_DIALECTS

BENCHMARK_LANGS: tuple[str, ...] = ("shell",)

_CORPORA: dict[str, tuple[tuple[CorpusCase, ...], list[str]]] = {
    "shell": (SHELL_CASES, SHELL_DIALECTS),
}


def get_corpus(lang: str) -> tuple[tuple[CorpusCase, ...], list[str]]:
    """Return cases and dialects for a benchmark language."""
    key = lang.strip().lower()
    try:
        return _CORPORA[key]
    except KeyError as exc:
        raise ValueError(
            f"no benchmark corpus for {lang!r}; supported: {', '.join(BENCHMARK_LANGS)}"
        ) from exc
