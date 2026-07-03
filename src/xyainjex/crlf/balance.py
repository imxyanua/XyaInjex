"""Balance for CRLF injection.

CRLF injection is not a balanced-delimiter problem, so a rendered value is always
considered syntactically valid; the risk comes from the injected line breaks.
"""

from __future__ import annotations

from ..models import Balance


def crlf_balance(rendered: str) -> Balance:
    return Balance(
        quotes_balanced=True,
        single_quote_open=False,
        double_quote_open=False,
        backtick_open=False,
        unbalanced_pairs={},
    )
