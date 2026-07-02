"""Syntax balance engine for rendered shell commands."""

from __future__ import annotations

from ..models import Balance
from .scanner import BACKTICK, CMDSUB, DOUBLE, SINGLE, ShellScanner


def balance(rendered: str) -> Balance:
    """Analyze quote and bracket balance across a rendered command."""
    scanner = ShellScanner()
    st = scanner.feed(rendered, record=False)

    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)
    backtick_open = any(f.kind == BACKTICK for f in st.stack)
    cmdsub_open = sum(1 for f in st.stack if f.kind == CMDSUB)

    unbalanced = {k: v for k, v in st.brackets.items() if v != 0}
    if cmdsub_open:
        unbalanced["$()"] = cmdsub_open

    quotes_balanced = not (single_open or double_open or backtick_open)

    return Balance(
        quotes_balanced=quotes_balanced,
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=backtick_open,
        unbalanced_pairs=unbalanced,
    )
