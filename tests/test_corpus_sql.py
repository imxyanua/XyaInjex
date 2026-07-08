"""Regression tests for SQL parser-divergence corpus."""

from __future__ import annotations

import json

from xyainjex.cli import main
from xyainjex.corpus import benchmark, load_corpus
from xyainjex.corpus.sql import SQL_CASES


def test_sql_corpus_loads():
    cases, dialects = load_corpus("sql")
    assert len(cases) == len(SQL_CASES)
    assert dialects == ["mysql", "postgres", "mssql", "sqlite", "ansi", "oracle"]
    assert {c.id for c in cases} == {c.id for c in SQL_CASES}


def test_sql_benchmark_all_pass():
    result = benchmark("sql")
    assert result.total == len(SQL_CASES)
    assert result.failed == 0
    assert result.ok


def test_sql_corpus_divergent_cases():
    result = benchmark("sql")
    divergent = {r.case_id for r in result.results if r.expected_divergent}
    assert "mysql-backslash-escape" in divergent
    assert "postgres-dollar-quote" in divergent
    assert "oracle-q-bracket-close" in divergent
    assert len(divergent) >= 7


def test_cli_benchmark_sql_json(capsys):
    code = main(["--benchmark", "-l", "sql", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code == 0
    assert data["lang"] == "sql"
    assert data["failed"] == 0
    assert data["total"] == len(SQL_CASES)
