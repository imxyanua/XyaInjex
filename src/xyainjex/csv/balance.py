"""Balance for CSV injection (always valid; risk is in the formula trigger)."""

from __future__ import annotations

from ..models import Balance


def csv_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
