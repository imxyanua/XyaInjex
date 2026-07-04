"""Balance for prototype pollution (always valid; risk is the polluted key)."""

from __future__ import annotations

from ..models import Balance


def prototype_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
