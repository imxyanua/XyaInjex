"""Classify the HTML context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template
from .scanner import ATTR_D, ATTR_S, COMMENT, SCRIPT, TAG, XssScanner

_TOP_TO_CONTEXT = {
    ATTR_D: Context.HTML_ATTR,
    ATTR_S: Context.HTML_ATTR,
    TAG: Context.HTML_ATTR,
    SCRIPT: Context.HTML_SCRIPT,
    COMMENT: Context.HTML_COMMENT,
}


def analyze_xss_context(template: str) -> Context:
    """Return the HTML context surrounding the injection point."""
    parts = split_template(template)
    scanner = XssScanner()
    scanner.feed(parts.prefix, record=False)
    return _TOP_TO_CONTEXT.get(scanner.state.top, Context.HTML_TEXT)
