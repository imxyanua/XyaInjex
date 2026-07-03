"""Classify the code context surrounding the injection point."""

from __future__ import annotations

from ..models import CodeLang, Context
from ..scan import BACKTICK, CMDSUB, DOUBLE, SINGLE
from ..shell.context import split_template
from .scanner import CodeScanner


def analyze_code_context(template: str, lang: CodeLang = CodeLang.PYTHON) -> Context:
    """Return the code context surrounding the injection point."""
    parts = split_template(template)
    scanner = CodeScanner(lang)
    scanner.feed(parts.prefix, record=False)
    top = scanner.state.top
    if top in (SINGLE, DOUBLE):
        return Context.CODE_STRING
    if top == BACKTICK:
        return Context.CODE_TEMPLATE
    if top == CMDSUB:
        # Inside a ${ ... } substitution the input is already evaluated code.
        return Context.CODE_EXPRESSION
    return Context.CODE_EXPRESSION


def parse_code_lang(name: str) -> CodeLang:
    """Resolve a user supplied code language name, with friendly aliases."""
    key = name.strip().lower()
    aliases = {
        "python": CodeLang.PYTHON,
        "py": CodeLang.PYTHON,
        "javascript": CodeLang.JAVASCRIPT,
        "js": CodeLang.JAVASCRIPT,
        "node": CodeLang.JAVASCRIPT,
        "nodejs": CodeLang.JAVASCRIPT,
        "php": CodeLang.PHP,
    }
    if key not in aliases:
        valid = ", ".join(sorted(aliases))
        raise ValueError(f"unknown code language {name!r}; valid values: {valid}")
    return aliases[key]
