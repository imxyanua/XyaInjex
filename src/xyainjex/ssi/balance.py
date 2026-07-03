"""Balance for SSI injection (always valid; risk is in the directive)."""

from __future__ import annotations

from ..models import Balance


def ssi_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
