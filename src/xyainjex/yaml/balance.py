"""Syntax balance engine for rendered YAML scalars."""

from __future__ import annotations

from ..models import Balance
from ..scan import DOUBLE, SINGLE
from .scanner import YamlScanner


def yaml_balance(rendered: str) -> Balance:
    """Report an unterminated quoted scalar."""
    st = YamlScanner().feed(rendered, record=False)

    single_open = any(f.kind == SINGLE for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)

    unbalanced: dict[str, int] = {}
    if single_open:
        unbalanced["''"] = 1
    if double_open:
        unbalanced['""'] = 1

    return Balance(
        quotes_balanced=not (single_open or double_open),
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
