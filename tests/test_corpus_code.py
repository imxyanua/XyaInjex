"""Regression tests for code-eval parser-divergence corpus."""

from __future__ import annotations

import json

from xyainjex.cli import main
from xyainjex.corpus import benchmark, load_corpus
from xyainjex.corpus.code import CODE_CASES


def test_code_corpus_loads():
    cases, dialects = load_corpus("code")
    assert len(cases) == len(CODE_CASES)
    assert dialects == ["python", "javascript", "php"]
    assert {c.id for c in cases} == {c.id for c in CODE_CASES}


def test_code_benchmark_all_pass():
    result = benchmark("code")
    assert result.total == len(CODE_CASES)
    assert result.failed == 0
    assert result.ok


def test_code_corpus_divergent_cases():
    result = benchmark("code")
    divergent = {r.case_id for r in result.results if r.expected_divergent}
    assert "js-template-literal-eval" in divergent
    assert len(divergent) >= 2


def test_cli_benchmark_code_json(capsys):
    code = main(["--benchmark", "-l", "code", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["lang"] == "code"
    assert data["failed"] == 0
