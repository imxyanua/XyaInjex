"""Tests for corpus-derived fuzz seeds."""

from __future__ import annotations

from xyainjex.corpus import corpus_seeds


def test_corpus_seeds_match_template_only():
    seeds = corpus_seeds('curl "{INPUT}"', "shell", "posix")
    assert ("\"; id ; #", "corpus:double-quote-curl") in seeds


def test_corpus_seeds_require_breakout_for_dialect():
    tmpl = "SELECT * FROM users WHERE name = '{INPUT}'"
    assert corpus_seeds(tmpl, "sql", "mysql") == []
    assert any(
        strategy == "corpus:mysql-backslash-escape"
        for _, strategy in corpus_seeds(tmpl, "sql", "postgres")
    )


def test_corpus_seeds_skip_uniform_cases():
    seeds = corpus_seeds(
        "SELECT * FROM users WHERE name = '{INPUT}'", "sql", "mysql"
    )
    ids = {strategy for _, strategy in seeds}
    assert "corpus:classic-or-comment" not in ids


def test_corpus_seeds_empty_for_unknown_template():
    assert corpus_seeds("custom sink {INPUT}", "shell") == []


def test_corpus_seeds_empty_for_non_benchmark_lang():
    assert corpus_seeds("{INPUT}", "xss") == []
