"""Tests for appending evolve discoveries to corpus files."""

from __future__ import annotations

from pathlib import Path

from xyainjex.cli import main
from xyainjex.corpus.benchmark import BenchmarkResult
from xyainjex.corpus.write import (
    WriteCorpusResult,
    WrittenCase,
    _insert_before_tuple_close,
    write_corpus_discoveries,
)
from xyainjex.evolve import EvolveDiscovery, EvolveResult

_DATA_DIR = Path(__file__).parent / "data" / "write_corpus"

_MINIMAL_SHELL = '''"""Shell test corpus."""

from __future__ import annotations

from .models import CorpusCase

SHELL_DIALECTS = ["posix", "cmd"]
SHELL_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="seed",
        template="ping {INPUT}",
        payload="; whoami",
        note="seed case",
        divergent=True,
    ),
)
'''


def _corpus_dir() -> Path:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    return _DATA_DIR


def test_insert_before_tuple_close():
    content = "CASES = (\n    CorpusCase(...),\n    CorpusCase(...),\n    ),\n)\n"
    updated = _insert_before_tuple_close(content, "    CorpusCase(new),\n")
    assert "CorpusCase(new)," in updated
    assert updated.index("CorpusCase(new),") < updated.rindex(")\n")


def test_write_skips_known_pairs(monkeypatch):
    corpus_dir = _corpus_dir()
    path = corpus_dir / "shell.py"
    path.write_text(_MINIMAL_SHELL, encoding="utf-8")
    monkeypatch.setattr("xyainjex.corpus.write._reload_corpus", lambda lang: None)
    monkeypatch.setattr(
        "xyainjex.corpus.write.benchmark",
        lambda lang: BenchmarkResult(lang, ["posix", "cmd"], 1, 1, 0),
    )

    discovery = EvolveDiscovery(
        template="ping {INPUT}",
        payload="; whoami",
        metric="command_injected",
        strategy="corpus:seed",
        round=1,
        per_dialect={},
        score=20.0,
    )
    result = EvolveResult(
        lang="shell",
        template="ping {INPUT}",
        dialects=["posix", "cmd"],
        rounds_run=1,
        candidates_tried=1,
        discoveries=[discovery],
    )
    write_result = write_corpus_discoveries(result, corpus_dir=corpus_dir)
    assert write_result.written == []
    assert any(
        s.reason == "template/payload already in corpus" for s in write_result.skipped
    )
    assert path.read_text(encoding="utf-8") == _MINIMAL_SHELL


def test_write_appends_and_runs_benchmark(monkeypatch):
    corpus_dir = _corpus_dir()
    path = corpus_dir / "shell.py"
    path.write_text(_MINIMAL_SHELL, encoding="utf-8")
    monkeypatch.setattr(
        "xyainjex.corpus.write.get_corpus",
        lambda lang: ([], ["posix", "cmd"]),
    )
    monkeypatch.setattr("xyainjex.corpus.write._reload_corpus", lambda lang: None)
    monkeypatch.setattr(
        "xyainjex.corpus.write.benchmark",
        lambda lang: BenchmarkResult(lang, ["posix", "cmd"], 2, 2, 0),
    )
    monkeypatch.setattr("xyainjex.corpus.write._validate_discovery", lambda *args: True)

    discovery = EvolveDiscovery(
        template='curl "{INPUT}"',
        payload='"; id ; #',
        metric="command_injected",
        strategy="fuzz:quote",
        round=1,
        per_dialect={},
        score=30.0,
    )
    result = EvolveResult(
        lang="shell",
        template='curl "{INPUT}"',
        dialects=["posix", "cmd"],
        rounds_run=1,
        candidates_tried=1,
        discoveries=[discovery],
    )
    write_result = write_corpus_discoveries(
        result, id_prefix="test", corpus_dir=corpus_dir
    )
    assert len(write_result.written) == 1
    assert write_result.benchmark_ok
    content = path.read_text(encoding="utf-8")
    assert 'id="test-shell-fuzz-quote-1"' in content
    assert 'template=\'curl "{INPUT}"\'' in content
    path.write_text(_MINIMAL_SHELL, encoding="utf-8")


def test_write_reverts_on_benchmark_failure(monkeypatch):
    corpus_dir = _corpus_dir()
    path = corpus_dir / "shell.py"
    original = _MINIMAL_SHELL
    path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(
        "xyainjex.corpus.write.get_corpus",
        lambda lang: ([], ["posix", "cmd"]),
    )
    monkeypatch.setattr("xyainjex.corpus.write._reload_corpus", lambda lang: None)
    monkeypatch.setattr(
        "xyainjex.corpus.write.benchmark",
        lambda lang: BenchmarkResult(lang, ["posix", "cmd"], 2, 1, 1),
    )
    monkeypatch.setattr("xyainjex.corpus.write._validate_discovery", lambda *args: True)

    discovery = EvolveDiscovery(
        template='curl "{INPUT}"',
        payload='"; id ; #',
        metric="command_injected",
        strategy="fuzz:quote",
        round=1,
        per_dialect={},
    )
    result = EvolveResult(
        lang="shell",
        template='curl "{INPUT}"',
        dialects=["posix", "cmd"],
        rounds_run=1,
        candidates_tried=1,
        discoveries=[discovery],
    )
    write_result = write_corpus_discoveries(
        result, id_prefix="test", corpus_dir=corpus_dir
    )
    assert write_result.reverted
    assert not write_result.ok
    assert path.read_text(encoding="utf-8") == original


def test_cli_write_corpus_flag(monkeypatch, capsys):
    fake_write = WriteCorpusResult(
        lang="shell",
        written=[WrittenCase("test-1", "ping {INPUT}", "; id")],
        skipped=[],
        benchmark_ok=True,
    )
    monkeypatch.setattr(
        "xyainjex.cli.write_corpus_discoveries",
        lambda result: fake_write,
    )
    monkeypatch.setattr(
        "xyainjex.cli.evolve",
        lambda **kwargs: EvolveResult(
            lang="shell",
            template="ping {INPUT}",
            dialects=["posix"],
            rounds_run=1,
            candidates_tried=1,
            discoveries=[
                EvolveDiscovery(
                    template="ping {INPUT}",
                    payload="; id",
                    metric="command_injected",
                    strategy="test",
                    round=1,
                    per_dialect={},
                )
            ],
        ),
    )

    code = main(
        ["--evolve", "-l", "shell", "--write-corpus", "--rounds", "1", "ping {INPUT}"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "write-corpus" in out
