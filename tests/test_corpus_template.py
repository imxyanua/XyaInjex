"""Regression tests for template parser-divergence corpus."""

from __future__ import annotations

import json

from xyainjex.cli import main
from xyainjex.corpus import benchmark, load_corpus
from xyainjex.corpus.template import TEMPLATE_CASES


def test_template_corpus_loads():
    cases, dialects = load_corpus("template")
    assert len(cases) == len(TEMPLATE_CASES)
    assert len(dialects) == 9
    assert {c.id for c in cases} == {c.id for c in TEMPLATE_CASES}


def test_template_benchmark_all_pass():
    result = benchmark("template")
    assert result.total == len(TEMPLATE_CASES)
    assert result.failed == 0
    assert result.ok


def test_template_corpus_divergent_cases():
    result = benchmark("template")
    divergent = {r.case_id for r in result.results if r.expected_divergent}
    assert "jinja-mustache-hello" in divergent
    assert "freemarker-dollar" in divergent
    assert len(divergent) >= 8


def test_cli_benchmark_template_json(capsys):
    code = main(["--benchmark", "-l", "template", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["lang"] == "template"
    assert data["failed"] == 0
