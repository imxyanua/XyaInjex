"""Tests for the self-evolving parser-divergence discovery loop."""

from __future__ import annotations

import json

import pytest

from xyainjex.cli import main
from xyainjex.corpus.shell import SHELL_CASES
from xyainjex.evolve import (
    EvolveDiscovery,
    EvolveResult,
    corpus_case_snippet,
    discovery_score,
    evolve,
)


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
    code = main(["--evolve", "-l", "shell", "--rounds", "1", "--json", "ping {INPUT}"])
    data = json.loads(capsys.readouterr().out)
    assert code in (0, 2)
    assert data["lang"] == "shell"
    assert data["rounds_run"] == 1


def test_corpus_case_snippet_format():
    discovery = EvolveDiscovery(
        template='curl "{INPUT}"',
        payload="; whoami",
        metric="command_injected",
        strategy="fuzz:quote",
        round=1,
        per_dialect={},
    )
    snippet = corpus_case_snippet(discovery, "evolved-shell-1")
    assert 'id="evolved-shell-1"' in snippet
    assert "CorpusCase(" in snippet
    assert discovery.template in snippet
    assert discovery.payload in snippet


def test_to_dict_emit_corpus():
    discovery = EvolveDiscovery(
        template="ping {INPUT}",
        payload="; id",
        metric="command_injected",
        strategy="test",
        round=1,
        per_dialect={},
    )
    result = EvolveResult(
        lang="shell",
        template="ping {INPUT}",
        dialects=["bash", "sh", "zsh"],
        rounds_run=1,
        candidates_tried=1,
        discoveries=[discovery],
    )
    data = result.to_dict(emit_corpus=True)
    assert "corpus_snippets" in data
    assert len(data["corpus_snippets"]) == 1
    assert data["corpus_snippets"][0]["case_id"].startswith("evolved-shell-")
    assert "CorpusCase(" in data["corpus_snippets"][0]["snippet"]


def test_cli_emit_corpus(capsys):
    code = main(
        [
            "--evolve",
            "-l",
            "shell",
            "--rounds",
            "1",
            "--emit-corpus",
            "ping {INPUT}",
        ]
    )
    out = capsys.readouterr().out
    assert code in (0, 2)
    if "CorpusCase snippets" in out:
        assert "CorpusCase(" in out


def test_discovery_score_inject_split():
    per = {
        "bash": {"command_injected": True, "risk": "HIGH"},
        "sh": {"command_injected": False, "risk": "LOW"},
        "zsh": {"command_injected": True, "risk": "HIGH"},
    }
    assert discovery_score(per, "command_injected") > discovery_score(
        {
            "bash": {"command_injected": True, "risk": "HIGH"},
            "sh": {"command_injected": True, "risk": "HIGH"},
        },
        "command_injected",
    )


def test_discovery_score_risk_spread():
    per = {
        "header": {"command_injected": True, "risk": "CRITICAL"},
        "log": {"command_injected": True, "risk": "HIGH"},
    }
    assert discovery_score(per, "risk") == 20.0


def test_evolve_discoveries_sorted_by_score():
    result = evolve(lang="shell", template='curl "{INPUT}"', max_rounds=1)
    if len(result.discoveries) >= 2:
        scores = [d.score for d in result.discoveries]
        assert scores == sorted(scores, reverse=True)


def test_evolve_respects_max_candidates():
    result = evolve(
        lang="shell",
        template='curl "{INPUT}"',
        max_rounds=3,
        max_candidates=5,
    )
    assert result.candidates_tried <= 5
    assert result.stopped_reason == "max_candidates"


def test_evolve_cross_template_can_be_disabled():
    with_cross = evolve(
        lang="shell",
        template='curl "{INPUT}"',
        max_rounds=1,
        cross_template=True,
        max_candidates=200,
    )
    without_cross = evolve(
        lang="shell",
        template='curl "{INPUT}"',
        max_rounds=1,
        cross_template=False,
        max_candidates=200,
    )
    assert without_cross.candidates_tried <= with_cross.candidates_tried


def test_evolve_crlf_uses_risk_metric():
    result = evolve(
        lang="crlf", template="Host: {INPUT}", max_rounds=1, max_candidates=20
    )
    assert result.discoveries or result.candidates_tried > 0
    for discovery in result.discoveries:
        assert discovery.metric == "risk"


def test_evolve_to_dict_includes_score_and_stopped_reason():
    discovery = EvolveDiscovery(
        template="ping {INPUT}",
        payload="; id",
        metric="command_injected",
        strategy="test",
        round=1,
        per_dialect={},
        score=42.0,
    )
    result = EvolveResult(
        lang="shell",
        template="ping {INPUT}",
        dialects=["bash"],
        rounds_run=1,
        candidates_tried=1,
        discoveries=[discovery],
        stopped_reason="max_candidates",
    )
    data = result.to_dict()
    assert data["discoveries"][0]["score"] == 42.0
    assert data["stopped_reason"] == "max_candidates"
