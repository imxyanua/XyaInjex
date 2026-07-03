"""Syntax balance engine for rendered code snippets."""

from __future__ import annotations

from ..models import Balance, CodeLang
from ..scan import BACKTICK, CMDSUB, DOUBLE, SINGLE
from .scanner import CodeScanner


def code_balance(rendered: str, lang: CodeLang = CodeLang.PYTHON) -> Balance:
    """Analyze string and template-literal balance across a code snippet."""
    st = CodeScanner(lang).feed(rendered, record=False)

    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)
    backtick_open = any(f.kind == BACKTICK for f in st.stack)
    sub_open = sum(1 for f in st.stack if f.kind == CMDSUB)

    unbalanced = {"${}": sub_open} if sub_open else {}
    quotes_balanced = not (single_open or double_open or backtick_open)

    return Balance(
        quotes_balanced=quotes_balanced,
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=backtick_open,
        unbalanced_pairs=unbalanced,
    )
