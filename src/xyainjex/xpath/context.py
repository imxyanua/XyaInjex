"""Classify the XPath context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..scan import DOUBLE, SINGLE
from ..shell.context import split_template
from .scanner import XPathScanner


def analyze_xpath_context(template: str) -> Context:
    """Return the XPath context surrounding the injection point."""
    parts = split_template(template)
    scanner = XPathScanner()
    scanner.feed(parts.prefix, record=False)
    if scanner.state.top in (SINGLE, DOUBLE):
        return Context.XPATH_STRING
    return Context.XPATH_EXPRESSION
