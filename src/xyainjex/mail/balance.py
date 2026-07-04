"""Balance for mail injection (always valid; the risk is the line break)."""

from __future__ import annotations

from ..models import Balance


def mail_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
