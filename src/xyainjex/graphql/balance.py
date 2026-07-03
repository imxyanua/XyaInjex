"""Syntax balance engine for rendered GraphQL."""

from __future__ import annotations

from ..models import Balance
from ..scan import DOUBLE
from .scanner import BLOCK, BRACE, PAREN, GraphqlScanner


def graphql_balance(rendered: str) -> Balance:
    """Report unclosed strings, selections, and argument lists."""
    st = GraphqlScanner().feed(rendered, record=False)

    string_open = any(f.kind in (DOUBLE, BLOCK) for f in st.stack)
    brace_open = sum(1 for f in st.stack if f.kind == BRACE)
    paren_open = sum(1 for f in st.stack if f.kind == PAREN)

    unbalanced: dict[str, int] = {}
    if brace_open:
        unbalanced["{}"] = brace_open
    if paren_open:
        unbalanced["()"] = paren_open

    return Balance(
        quotes_balanced=not string_open,
        single_quote_open=False,
        double_quote_open=string_open,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
