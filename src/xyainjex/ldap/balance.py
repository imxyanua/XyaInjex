"""Syntax balance engine for rendered LDAP filters."""

from __future__ import annotations

from ..models import Balance
from .scanner import PAREN, LdapScanner


def ldap_balance(rendered: str) -> Balance:
    """Analyze parenthesis balance across a rendered filter."""
    st = LdapScanner().feed(rendered, record=False)

    open_parens = sum(1 for f in st.stack if f.kind == PAREN)
    unbalanced = {"()": open_parens} if open_parens else {}

    return Balance(
        quotes_balanced=open_parens == 0,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
