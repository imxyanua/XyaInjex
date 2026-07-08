"""SQL parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

SQL_DIALECTS = ["mysql", "postgres", "mssql", "sqlite", "ansi"]

SQL_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="mysql-backslash-escape",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="\\' OR 1=1 -- ",
        note="MySQL treats backslash as escape inside strings; others do not.",
        divergent=True,
    ),
    CorpusCase(
        id="postgres-dollar-quote",
        template="SELECT * FROM users WHERE name = $${INPUT}$$",
        payload="1; SELECT 1",
        note="Postgres dollar quotes keep payload in a string; others see numeric SQL.",
        divergent=True,
    ),
    CorpusCase(
        id="postgres-dollar-tagged",
        template="SELECT * FROM users WHERE name = $tag${INPUT}$tag$",
        payload="1; SELECT 1",
        note="Tagged dollar quotes behave like plain dollar quotes for divergence.",
        divergent=True,
    ),
    CorpusCase(
        id="qquote-backslash",
        template="SELECT * FROM users WHERE name = q'[{INPUT}]'",
        payload="\\' OR 1=1 -- ",
        note="Alternative quoting with a backslash-escape divergence across dialects.",
        divergent=True,
    ),
    CorpusCase(
        id="classic-or-comment",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' OR 1=1 -- ",
        note="Classic string breakout with a trailing line comment.",
        divergent=False,
    ),
    CorpusCase(
        id="tautology",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' OR '1'='1",
        note="Tautology without a comment terminator.",
        divergent=False,
    ),
    CorpusCase(
        id="hash-comment",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' OR 1=1#",
        note="MySQL-style hash comment after a string breakout.",
        divergent=False,
    ),
    CorpusCase(
        id="numeric-stacked",
        template="SELECT * FROM users WHERE id = {INPUT}",
        payload="1; DROP TABLE users",
        note="Stacked query from a numeric injection point.",
        divergent=False,
    ),
    CorpusCase(
        id="union-select",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' UNION SELECT null-- ",
        note="UNION-based injection after closing the string.",
        divergent=False,
    ),
    CorpusCase(
        id="block-comment-open",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' OR 1=1/*",
        note="Open block comment to swallow the rest of the statement.",
        divergent=False,
    ),
    CorpusCase(
        id="insert-values-break",
        template="INSERT INTO t (n) VALUES('{INPUT}')",
        payload="',('x')--",
        note="Break out of a quoted INSERT value.",
        divergent=False,
    ),
    CorpusCase(
        id="and-clause-break",
        template="SELECT * FROM t WHERE x='{INPUT}' AND y=1",
        payload="' OR '1'='1' -- ",
        note="Break out mid-WHERE with a trailing AND clause.",
        divergent=False,
    ),
    CorpusCase(
        id="backtick-identifier-close",
        template="SELECT * FROM t WHERE x = `{INPUT}`",
        payload="` OR 1=1",
        note="Close a MySQL backtick-quoted identifier and inject.",
        divergent=False,
    ),
    CorpusCase(
        id="double-quote-template-inject",
        template='SELECT * FROM users WHERE name = "{INPUT}"',
        payload='" OR 1=1 -- ',
        note="Close a double-quoted value and inject; all dialects agree here.",
        divergent=False,
    ),
    CorpusCase(
        id="benign-literal",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="admin",
        note="Benign data with no breakout.",
        divergent=False,
    ),
    CorpusCase(
        id="numeric-benign",
        template="SELECT * FROM users WHERE id = {INPUT}",
        payload="42",
        note="Benign numeric input.",
        divergent=False,
    ),
    CorpusCase(
        id="doubled-quote-escape",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="'' OR '1'='1",
        note="Doubled-quote escape stays inside the string for every dialect.",
        divergent=False,
    ),
    CorpusCase(
        id="substitution-in-string",
        template="SELECT * FROM users WHERE name = '{INPUT}'",
        payload="' OR ''='",
        note="Empty-string tautology variant without comment truncation.",
        divergent=False,
    ),
)
