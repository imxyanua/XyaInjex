"""Code-eval parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

CODE_DIALECTS = ["python", "javascript", "php"]

CODE_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="js-template-literal-eval",
        template="eval(`{INPUT}`)",
        payload="${7*7}",
        note="JS template-literal substitution; python and php ignore backticks.",
        divergent=True,
    ),
    CorpusCase(
        id="js-function-template-literal",
        template="new Function(`{INPUT}`)",
        payload="${7*7}",
        note="Function constructor with a JS template literal body.",
        divergent=True,
    ),
    CorpusCase(
        id="python-eval-system",
        template="eval('{INPUT}')",
        payload="__import__('os').system('id')",
        note="Classic python eval breakout with an import call.",
        divergent=False,
    ),
    CorpusCase(
        id="double-quote-eval-break",
        template='eval("{INPUT}")',
        payload='");import os;os.system("id");#',
        note="Close a double-quoted eval argument and inject.",
        divergent=False,
    ),
    CorpusCase(
        id="php-eval-system",
        template="<?php eval('{INPUT}'); ?>",
        payload="'); system('id'); //",
        note="Break out of a single-quoted PHP eval string.",
        divergent=False,
    ),
    CorpusCase(
        id="python-fstring-exec",
        template="f'{INPUT}'",
        payload="{__import__('os').system('id')}",
        note="Expression inside a Python f-string.",
        divergent=False,
    ),
    CorpusCase(
        id="eval-numeric-literal",
        template="eval('{INPUT}')",
        payload="1+1",
        note="Benign numeric expression with no breakout.",
        divergent=False,
    ),
    CorpusCase(
        id="php-system-contained",
        template="<?php eval('{INPUT}'); ?>",
        payload="system('id')",
        note="Function call that remains inside the quoted eval argument.",
        divergent=False,
    ),
    CorpusCase(
        id="backtick-word-contained",
        template="`{INPUT}`",
        payload="`id`",
        note="Backticks inside an unquoted word stay contained for these analyzers.",
        divergent=False,
    ),
    CorpusCase(
        id="benign-identifier",
        template="eval('{INPUT}')",
        payload="benign",
        note="Simple identifier with no metacharacters.",
        divergent=False,
    ),
)
