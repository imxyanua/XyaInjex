"""Syntax balance engine for rendered XML."""

from __future__ import annotations

from ..models import Balance
from .scanner import ATTR_D, ATTR_S, CDATA, COMMENT, TAG, XmlScanner

_LABELS = {
    TAG: "<>",
    ATTR_D: '""',
    ATTR_S: "''",
    CDATA: "<![CDATA[]]>",
    COMMENT: "<!---->",
}


def xml_balance(rendered: str) -> Balance:
    """Report unclosed tags, attributes, CDATA, and comments."""
    st = XmlScanner().feed(rendered, record=False)

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
