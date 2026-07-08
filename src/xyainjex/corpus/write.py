"""Append evolved discoveries to on-disk benchmark corpus modules (dev workflow)."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..evolve import EvolveDiscovery, EvolveResult, corpus_snippets
from ..fuzz import differential
from ..fuzz.engine import parser_divergent
from .benchmark import benchmark
from .registry import BENCHMARK_LANGS, get_corpus

_LANG_MODULES = {
    "shell": "xyainjex.corpus.shell",
    "sql": "xyainjex.corpus.sql",
    "template": "xyainjex.corpus.template",
    "code": "xyainjex.corpus.code",
    "crlf": "xyainjex.corpus.crlf",
}


@dataclass
class WrittenCase:
    case_id: str
    template: str
    payload: str

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "template": self.template,
            "payload": self.payload,
        }


@dataclass
class SkippedCase:
    case_id: str
    reason: str

    def to_dict(self) -> dict:
        return {"case_id": self.case_id, "reason": self.reason}


@dataclass
class WriteCorpusResult:
    lang: str
    written: list[WrittenCase] = field(default_factory=list)
    skipped: list[SkippedCase] = field(default_factory=list)
    benchmark_ok: bool = True
    benchmark_total: int = 0
    benchmark_failed: int = 0
    reverted: bool = False

    @property
    def ok(self) -> bool:
        return self.benchmark_ok and not self.reverted

    def to_dict(self) -> dict:
        return {
            "lang": self.lang,
            "written": [w.to_dict() for w in self.written],
            "skipped": [s.to_dict() for s in self.skipped],
            "benchmark_ok": self.benchmark_ok,
            "benchmark_total": self.benchmark_total,
            "benchmark_failed": self.benchmark_failed,
            "reverted": self.reverted,
        }


def corpus_file_path(lang: str, *, corpus_dir: Path | None = None) -> Path:
    lang = lang.strip().lower()
    if lang not in BENCHMARK_LANGS:
        raise ValueError(
            "write-corpus supports " + ", ".join(BENCHMARK_LANGS) + f", not {lang!r}"
        )
    root = corpus_dir if corpus_dir is not None else Path(__file__).parent
    return root / f"{lang}.py"


def _case_ids_in_content(content: str) -> set[str]:
    return set(re.findall(r'id="([^"]+)"', content))


def _insert_before_tuple_close(content: str, snippet: str) -> str:
    marker = content.rfind("    ),")
    if marker == -1:
        raise ValueError("corpus file missing expected CorpusCase tuple terminator")
    insert_at = marker + len("    ),")
    return content[:insert_at] + "\n" + snippet + content[insert_at:]


def _reload_corpus(lang: str) -> None:
    module_name = _LANG_MODULES[lang.strip().lower()]
    module = importlib.import_module(module_name)
    importlib.reload(module)
    registry = importlib.import_module("xyainjex.corpus.registry")
    importlib.reload(registry)


def _validate_discovery(
    discovery: EvolveDiscovery, lang: str, dialects: list[str]
) -> bool:
    diff = differential(
        discovery.template,
        discovery.payload,
        lang,
        dialects,
        metric=discovery.metric,
    )
    return parser_divergent(diff.per_dialect, discovery.metric)


def write_corpus_discoveries(
    result: EvolveResult,
    *,
    id_prefix: str = "evolved",
    corpus_dir: Path | None = None,
) -> WriteCorpusResult:
    """Append evolve discoveries to ``corpus/{lang}.py`` and verify via benchmark.

    On benchmark failure the corpus file is restored to its original content.
    """
    lang = result.lang.strip().lower()
    path = corpus_file_path(lang, corpus_dir=corpus_dir)
    original = path.read_text(encoding="utf-8")
    content = original
    existing_ids = _case_ids_in_content(content)
    cases, dialects = get_corpus(lang)
    known_pairs = {(c.template, c.payload) for c in cases}

    write_result = WriteCorpusResult(lang=lang)
    snippets = corpus_snippets(result, id_prefix=id_prefix)

    for index, discovery in enumerate(result.discoveries):
        case_id = snippets[index]["case_id"]
        if case_id in existing_ids:
            write_result.skipped.append(
                SkippedCase(case_id, "id already in corpus file")
            )
            continue
        pair = (discovery.template, discovery.payload)
        if pair in known_pairs:
            write_result.skipped.append(
                SkippedCase(case_id, "template/payload already in corpus")
            )
            continue
        if not _validate_discovery(discovery, lang, dialects):
            write_result.skipped.append(
                SkippedCase(case_id, "no longer divergent across dialects")
            )
            continue

        snippet = snippets[index]["snippet"]
        content = _insert_before_tuple_close(content, snippet)
        existing_ids.add(case_id)
        known_pairs.add(pair)
        write_result.written.append(
            WrittenCase(case_id, discovery.template, discovery.payload)
        )

    if not write_result.written:
        return write_result

    path.write_text(content, encoding="utf-8")
    try:
        _reload_corpus(lang)
        bench = benchmark(lang)
        write_result.benchmark_total = bench.total
        write_result.benchmark_failed = bench.failed
        write_result.benchmark_ok = bench.ok
        if not bench.ok:
            path.write_text(original, encoding="utf-8")
            _reload_corpus(lang)
            write_result.reverted = True
    except Exception:
        path.write_text(original, encoding="utf-8")
        _reload_corpus(lang)
        raise

    return write_result
