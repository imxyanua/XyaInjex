"""Syntax balance engine for rendered templates."""

from __future__ import annotations

from ..models import Balance, TemplateEngine
from .engines import get_template_spec
from .scanner import TemplateScanner


def template_balance(
    rendered: str, engine: TemplateEngine = TemplateEngine.JINJA2
) -> Balance:
    """Report whether every template region and string literal is closed."""
    scanner = TemplateScanner(get_template_spec(engine))
    st = scanner.feed(rendered, record=False)

    region_open = st.kind != "text"
    string_open = st.in_string is not None

    unbalanced: dict[str, int] = {}
    if region_open:
        label = f"{st.open_token} {st.close_token}"
        unbalanced[label] = 1

    return Balance(
        quotes_balanced=not string_open,
        single_quote_open=string_open and st.in_string == "'",
        double_quote_open=string_open and st.in_string == '"',
        backtick_open=False,
        unbalanced_pairs=unbalanced,
    )
