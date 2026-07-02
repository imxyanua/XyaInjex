"""Locate the injection point in a template and classify its context."""

from __future__ import annotations

from dataclasses import dataclass

from ..dialects import get_spec
from ..models import Context, Dialect

INPUT_MARKER = "{INPUT}"


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
    suffix = template[idx + len(INPUT_MARKER) :]
    return TemplateParts(prefix=prefix, suffix=suffix, marker_index=idx)


def analyze_context(template: str, dialect: Dialect = Dialect.POSIX) -> Context:
    """Return the lexical context surrounding the injection point."""
    parts = split_template(template)
    spec = get_spec(dialect)
    scanner = spec.scanner()
    scanner.feed(parts.prefix, record=False)
    return spec.context_of(scanner.state.top)
