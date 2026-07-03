"""Syntax balance engine for rendered HTML."""

from __future__ import annotations

from ..models import Balance
from .scanner import ATTR_D, ATTR_S, COMMENT, SCRIPT, TAG, XssScanner

_LABELS = {
    TAG: "<>",
    ATTR_D: '""',
    ATTR_S: "''",
    SCRIPT: "<script></script>",
    COMMENT: "<!---->",
}


def xss_balance(rendered: str) -> Balance:
    """Report an unclosed tag, attribute, script block, or comment."""
    st = XssScanner().feed(rendered, record=False)

    unbalanced: dict[str, int] = {}
    for frame in st.stack:
        label = _LABELS.get(frame.kind)
        if label:
            unbalanced[label] = unbalanced.get(label, 0) + 1

    attr_open = any(f.kind in (ATTR_D, ATTR_S) for f in st.stack)

    return Balance(
        quotes_balanced=not attr_open,
        single_quote_open=any(f.kind == ATTR_S for f in st.stack),
        double_quote_open=any(f.kind == ATTR_D for f in st.stack),
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
