"""Balance for argument injection (always valid; risk is the injected flag)."""

from __future__ import annotations

from ..models import Balance


def argument_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
