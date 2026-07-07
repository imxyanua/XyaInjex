"""Run parser-divergence benchmarks from built-in corpora."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..fuzz import differential
from .models import CorpusCase
from .registry import BENCHMARK_LANGS, get_corpus

__all__ = [
    "BENCHMARK_LANGS",
    "BenchmarkResult",
    "CaseResult",
    "CorpusCase",
    "benchmark",
    "load_corpus",
]


@dataclass
class CaseResult:
    case_id: str
    template: str
    payload: str
    expected_divergent: bool
    actual_divergent: bool
    passed: bool
    per_dialect: dict[str, dict]
    note: str

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "template": self.template,
            "payload": self.payload,
            "expected_divergent": self.expected_divergent,
            "actual_divergent": self.actual_divergent,
            "passed": self.passed,
            "per_dialect": self.per_dialect,
            "note": self.note,
        }


@dataclass
class BenchmarkResult:
    lang: str
    dialects: list[str]
    total: int
    passed: int
    failed: int
    results: list[CaseResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict:
        return {
            "lang": self.lang,
            "dialects": self.dialects,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "results": [r.to_dict() for r in self.results],
        }


def load_corpus(lang: str) -> tuple[list[CorpusCase], list[str]]:
    """Load benchmark cases and dialect list for ``lang``."""
    cases, dialects = get_corpus(lang)
    return list(cases), list(dialects)


def benchmark(lang: str = "shell") -> BenchmarkResult:
    """Run every corpus case for ``lang`` and check expected parser divergence."""
    lang = lang.strip().lower()
    cases, dialects = load_corpus(lang)
    results: list[CaseResult] = []

    for case in cases:
        diff = differential(case.template, case.payload, lang, dialects)
        passed = diff.divergent == case.divergent
        results.append(
            CaseResult(
                case_id=case.id,
                template=case.template,
                payload=case.payload,
                expected_divergent=case.divergent,
                actual_divergent=diff.divergent,
                passed=passed,
                per_dialect=diff.per_dialect,
                note=case.note,
            )
        )

    passed_n = sum(1 for r in results if r.passed)
    return BenchmarkResult(
        lang=lang,
        dialects=dialects,
        total=len(results),
        passed=passed_n,
        failed=len(results) - passed_n,
        results=results,
    )
