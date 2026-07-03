"""Classify the YAML context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..scan import DOUBLE, SINGLE
from ..shell.context import split_template
from .scanner import YamlScanner

_TOP_TO_CONTEXT = {
    SINGLE: Context.YAML_SINGLE,
    DOUBLE: Context.YAML_DOUBLE,
}


def analyze_yaml_context(template: str) -> Context:
    """Return the YAML context surrounding the injection point."""
    parts = split_template(template)
    scanner = YamlScanner()
    scanner.feed(parts.prefix, record=False)
    return _TOP_TO_CONTEXT.get(scanner.state.top, Context.YAML_PLAIN)
