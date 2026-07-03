"""Syntax balance engine for rendered XPath expressions."""

from __future__ import annotations

from ..models import Balance
from ..scan import DOUBLE, SINGLE
from .scanner import XPathScanner


def xpath_balance(rendered: str) -> Balance:
    """Analyze string, parenthesis, and predicate balance."""
    st = XPathScanner().feed(rendered, record=False)

    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)

    unbalanced = {k: v for k, v in st.brackets.items() if v != 0}
    quotes_balanced = not (single_open or double_open)

    return Balance(
        quotes_balanced=quotes_balanced,
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
