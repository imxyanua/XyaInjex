"""Syntax balance engine for rendered SQL statements."""

from __future__ import annotations

from ..models import Balance, SqlDialect
from ..scan import BACKTICK, DOUBLE, SINGLE
from .scanner import BRACKET, DOLLAR, QQUOTE, SqlScanner

_STRING_KINDS = (SINGLE, DOLLAR, QQUOTE)
_IDENT_KINDS = (BACKTICK, BRACKET)


def sql_balance(rendered: str, dialect: SqlDialect = SqlDialect.MYSQL) -> Balance:
    """Analyze quote, identifier, parenthesis, and comment balance."""
    scanner = SqlScanner(dialect)
    st = scanner.feed(rendered, record=False)

    single_open = any(f.kind in _STRING_KINDS for f in st.stack)
    double_open = any(f.kind == DOUBLE for f in st.stack)
    backtick_open = any(f.kind in _IDENT_KINDS for f in st.stack)

    unbalanced = {k: v for k, v in st.brackets.items() if v != 0}
    if scanner.in_block:
        unbalanced["/* */"] = 1

    quotes_balanced = not (single_open or double_open or backtick_open)

    return Balance(
        quotes_balanced=quotes_balanced,
        single_quote_open=single_open,
        double_quote_open=double_open,
        backtick_open=backtick_open,
        unbalanced_pairs=unbalanced,
    )
