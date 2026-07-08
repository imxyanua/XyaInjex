"""Regression tests for CRLF parser-divergence corpus."""

from __future__ import annotations

import json

from xyainjex.cli import main
from xyainjex.corpus import benchmark, load_corpus
from xyainjex.corpus.crlf import CRLF_CASES


def test_crlf_corpus_loads():
    cases, dialects = load_corpus("crlf")
    assert len(cases) == len(CRLF_CASES)
    assert dialects == ["header", "log"]
    assert {c.id for c in cases} == {c.id for c in CRLF_CASES}


def test_crlf_benchmark_all_pass():
    result = benchmark("crlf")
    assert result.total == len(CRLF_CASES)
    assert result.failed == 0
    assert result.ok


def test_all_benchmark_corpora_pass():
    from xyainjex.corpus import BENCHMARK_LANGS, benchmark

    for lang in BENCHMARK_LANGS:
        result = benchmark(lang)
        assert result.ok, f"{lang}: {result.failed} failed"


def test_cli_benchmark_crlf_json(capsys):
    code = main(["--benchmark", "-l", "crlf", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["lang"] == "crlf"
    assert data["failed"] == 0
