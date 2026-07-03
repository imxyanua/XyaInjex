"""Classify the GraphQL context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..scan import DOUBLE
from ..shell.context import split_template
from .scanner import BLOCK, GraphqlScanner


def analyze_graphql_context(template: str) -> Context:
    """Return the GraphQL context surrounding the injection point."""
    parts = split_template(template)
    scanner = GraphqlScanner()
    scanner.feed(parts.prefix, record=False)
    if scanner.state.top in (DOUBLE, BLOCK):
        return Context.GQL_STRING
    return Context.GQL_ARG
