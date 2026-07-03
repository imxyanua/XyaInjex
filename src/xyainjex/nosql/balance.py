"""Syntax balance engine for rendered NoSQL query documents."""

from __future__ import annotations

from ..models import Balance
from ..scan import DOUBLE
from .scanner import ARR, OBJ, NoSqlScanner


def nosql_balance(rendered: str) -> Balance:
    """Analyze JSON string, object, and array balance."""
    st = NoSqlScanner().feed(rendered, record=False)

    double_open = any(f.kind == DOUBLE for f in st.stack)
    obj_open = sum(1 for f in st.stack if f.kind == OBJ)
    arr_open = sum(1 for f in st.stack if f.kind == ARR)

    unbalanced: dict[str, int] = {}
    if obj_open:
        unbalanced["{}"] = obj_open
    if arr_open:
        unbalanced["[]"] = arr_open

    return Balance(
        quotes_balanced=not double_open,
        single_quote_open=False,
        double_quote_open=double_open,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
