"""Registry of built-in benchmark corpora."""

from __future__ import annotations

from .code import CODE_CASES, CODE_DIALECTS
from .crlf import CRLF_CASES, CRLF_DIALECTS
from .models import CorpusCase
from .shell import SHELL_CASES, SHELL_DIALECTS
from .sql import SQL_CASES, SQL_DIALECTS
from .template import TEMPLATE_CASES, TEMPLATE_DIALECTS

BENCHMARK_LANGS: tuple[str, ...] = ("shell", "sql", "template", "code", "crlf")

_CORPORA: dict[str, tuple[tuple[CorpusCase, ...], list[str]]] = {
    "shell": (SHELL_CASES, SHELL_DIALECTS),
    "sql": (SQL_CASES, SQL_DIALECTS),
    "template": (TEMPLATE_CASES, TEMPLATE_DIALECTS),
    "code": (CODE_CASES, CODE_DIALECTS),
    "crlf": (CRLF_CASES, CRLF_DIALECTS),
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
