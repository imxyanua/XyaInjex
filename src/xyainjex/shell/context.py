"""Locate the injection point in a template and classify its shell context."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Context
from .scanner import ShellScanner, SINGLE, DOUBLE, BACKTICK, CMDSUB

INPUT_MARKER = "{INPUT}"

_FRAME_TO_CONTEXT = {
    SINGLE: Context.SINGLE_QUOTE,
    DOUBLE: Context.DOUBLE_QUOTE,
    BACKTICK: Context.BACKTICK,
    CMDSUB: Context.COMMAND_SUBSTITUTION,
}


@dataclass
class TemplateParts:
    prefix: str
    suffix: str
    marker_index: int


def split_template(template: str) -> TemplateParts:
    """Split ``template`` around the ``{INPUT}`` marker.

    Raises ``ValueError`` when the marker is absent so callers get a clear
    error instead of a silently mis-analyzed command.
    """
    idx = template.find(INPUT_MARKER)
    if idx == -1:
        raise ValueError(f"template does not contain the {INPUT_MARKER!r} marker")
    prefix = template[:idx]
    suffix = template[idx + len(INPUT_MARKER):]
    return TemplateParts(prefix=prefix, suffix=suffix, marker_index=idx)


def analyze_context(template: str) -> Context:
    """Return the lexical context surrounding the injection point."""
    parts = split_template(template)
    scanner = ShellScanner()
    scanner.feed(parts.prefix, record=False)
    top = scanner.state.top
    return _FRAME_TO_CONTEXT.get(top, Context.UNQUOTED)
