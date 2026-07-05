"""Balance for host header injection (always valid; risk is the host value)."""

from __future__ import annotations

from ..models import Balance


def host_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
