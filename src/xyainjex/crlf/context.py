"""Classify the CRLF context and resolve the sink kind."""

from __future__ import annotations

from ..models import Context, CrlfKind
from ..shell.context import split_template

_KIND_TO_CONTEXT = {
    CrlfKind.HEADER: Context.HTTP_HEADER,
    CrlfKind.LOG: Context.LOG_LINE,
}


def analyze_crlf_context(template: str, kind: CrlfKind = CrlfKind.HEADER) -> Context:
    """Return the CRLF context for the sink ``kind``.

    The context is not derived lexically; it is the chosen sink (an HTTP header
    value or a log line). The marker is validated to be present.
    """
    split_template(template)
    return _KIND_TO_CONTEXT[kind]


def parse_crlf_kind(name: str) -> CrlfKind:
    """Resolve a user supplied CRLF sink kind, with friendly aliases."""
    key = name.strip().lower()
    aliases = {
        "header": CrlfKind.HEADER,
        "http": CrlfKind.HEADER,
        "response": CrlfKind.HEADER,
        "log": CrlfKind.LOG,
        "logging": CrlfKind.LOG,
    }
    if key not in aliases:
        valid = ", ".join(sorted(aliases))
        raise ValueError(f"unknown CRLF kind {name!r}; valid values: {valid}")
    return aliases[key]
