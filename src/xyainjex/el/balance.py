"""Syntax balance engine for rendered expression-language snippets."""

from __future__ import annotations

from ..models import Balance
from ..scan import DOUBLE, SINGLE
from .scanner import EXPR, ElScanner


def el_balance(rendered: str) -> Balance:
    """Report an unclosed expression or string literal."""
    st = ElScanner().feed(rendered, record=False)

    expr_open = sum(1 for f in st.stack if f.kind == EXPR)
    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)

    unbalanced: dict[str, int] = {}
    if expr_open:
        unbalanced["${}"] = expr_open

    return Balance(
        quotes_balanced=not (single_open or double_open),
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
