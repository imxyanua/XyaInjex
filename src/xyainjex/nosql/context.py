"""Classify the NoSQL context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..scan import DOUBLE
from ..shell.context import split_template
from .scanner import NoSqlScanner


def analyze_nosql_context(template: str) -> Context:
    """Return the NoSQL context surrounding the injection point."""
    parts = split_template(template)
    scanner = NoSqlScanner()
    scanner.feed(parts.prefix, record=False)
    if scanner.state.top == DOUBLE:
        return Context.NOSQL_STRING
    return Context.NOSQL_VALUE
