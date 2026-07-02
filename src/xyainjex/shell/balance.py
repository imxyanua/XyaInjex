"""Syntax balance engine for rendered commands, across dialects."""

from __future__ import annotations

from ..dialects import get_spec
from ..models import Balance, Dialect
from ..scan import ARITH, BACKTICK, CMDSUB, DOUBLE, PARAM, SINGLE, SUBEXPR

# Human readable labels for unclosed expansion frames.
_EXPANSION_LABELS = {
    CMDSUB: "$()",
    SUBEXPR: "$()",
    ARITH: "$(())",
    PARAM: "${}",
}


def balance(rendered: str, dialect: Dialect = Dialect.POSIX) -> Balance:
    """Analyze quote and bracket balance across a rendered command."""
    scanner = get_spec(dialect).scanner()
    st = scanner.feed(rendered, record=False)

    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)
    backtick_open = any(f.kind == BACKTICK for f in st.stack)

    unbalanced = {k: v for k, v in st.brackets.items() if v != 0}
    for kind, label in _EXPANSION_LABELS.items():
        count = sum(1 for f in st.stack if f.kind == kind)
        if count:
            unbalanced[label] = unbalanced.get(label, 0) + count

    quotes_balanced = not (single_open or double_open or backtick_open)

    return Balance(
        quotes_balanced=quotes_balanced,
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=backtick_open,
        unbalanced_pairs=unbalanced,
    )
