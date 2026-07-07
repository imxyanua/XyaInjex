"""Regression tests for shell parser-divergence corpus."""

from __future__ import annotations

import json

import pytest

from xyainjex.cli import main
from xyainjex.corpus import benchmark, load_corpus
from xyainjex.corpus.shell import SHELL_CASES


def test_shell_corpus_loads():
    cases, dialects = load_corpus("shell")
    assert len(cases) == len(SHELL_CASES)
    assert dialects == ["posix", "cmd", "powershell", "fish"]
    assert {c.id for c in cases} == {c.id for c in SHELL_CASES}


def test_shell_benchmark_all_pass():
    result = benchmark("shell")
    assert result.total == len(SHELL_CASES)
    assert result.failed == 0
    assert result.ok


def test_shell_corpus_divergent_cases():
    result = benchmark("shell")
    divergent = {r.case_id for r in result.results if r.expected_divergent}
    assert "semicolon-unquoted" in divergent
    assert "hash-newline-cmd" in divergent
    assert len(divergent) >= 8


def test_cli_benchmark_shell_json(capsys):
    code = main(["--benchmark", "-l", "shell", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code == 0
    assert data["lang"] == "shell"
    assert data["failed"] == 0
    assert data["total"] == len(SHELL_CASES)


def test_cli_benchmark_shell_text(capsys):
    code = main(["--benchmark", "-l", "shell"])
    out = capsys.readouterr().out
    assert code == 0
    assert "parser divergence benchmark" in out
    assert "Passed:" in out


def test_cli_benchmark_rejects_unsupported_lang():
    with pytest.raises(SystemExit):
        main(["--benchmark", "-l", "ssrf"])
