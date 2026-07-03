"""Classify the expression-language context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..scan import DOUBLE, SINGLE
from ..shell.context import split_template
from .scanner import EXPR, ElScanner


def analyze_el_context(template: str) -> Context:
    """Return the expression-language context surrounding the injection point."""
    parts = split_template(template)
    scanner = ElScanner()
    scanner.feed(parts.prefix, record=False)
    top = scanner.state.top
    if top in (SINGLE, DOUBLE):
        return Context.EL_STRING
    if top == EXPR:
        return Context.EL_EXPRESSION
    return Context.EL_TEXT
