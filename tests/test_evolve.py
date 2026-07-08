"""Tests for the self-evolving parser-divergence discovery loop."""

from __future__ import annotations

import json

import pytest

from xyainjex.cli import main
from xyainjex.corpus.shell import SHELL_CASES
from xyainjex.evolve import evolve


def test_evolve_runs_for_shell_template():
    result = evolve(lang="shell", template='curl "{INPUT}"', max_rounds=1)
    assert result.lang == "shell"
    assert result.rounds_run == 1
    assert result.candidates_tried > 0
    assert result.template == 'curl "{INPUT}"'


def test_evolve_skips_known_corpus_pairs():
    case = next(c for c in SHELL_CASES if c.id == "double-quote-curl")
    result = evolve(lang="shell", template=case.template, max_rounds=1)
    assert all(
        d.template != case.template or d.payload != case.payload
        for d in result.discoveries
    )


def test_evolve_rejects_unknown_lang():
    with pytest.raises(ValueError):
        evolve(lang="xss", template="{INPUT}")


def test_evolve_to_dict():
    data = evolve(lang="shell", template="ping {INPUT}", max_rounds=1).to_dict()
    keys = {"lang", "rounds_run", "candidates_tried", "discoveries", "found"}
    assert keys <= set(data)


def test_cli_evolve_json(capsys):
    code = main(["--evolve", "-l", "shell", "--rounds", "1", "--json", 'ping {INPUT}'])
    data = json.loads(capsys.readouterr().out)
    assert code in (0, 2)
    assert data["lang"] == "shell"
    assert data["rounds_run"] == 1
