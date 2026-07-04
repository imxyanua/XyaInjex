"""Balance for path traversal (always valid; the risk is in the target path)."""

from __future__ import annotations

from ..models import Balance


def path_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
