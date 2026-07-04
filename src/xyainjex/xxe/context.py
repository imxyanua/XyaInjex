"""Classify where the injection point sits within an XML document (XXE)."""

from __future__ import annotations

import re

from ..models import Context
from ..shell.context import split_template

# Only an XML declaration / whitespace may precede a DOCTYPE.
_ONLY_DECL = re.compile(r"^\s*(<\?xml\b[^>]*\?>)?\s*$", re.IGNORECASE)


def analyze_xxe_context(template: str) -> Context:
    """Return the XXE context surrounding the injection point.

    - ``XXE_DOCUMENT`` the input starts the document, so it can introduce a
      ``<!DOCTYPE>`` and external entities.
    - ``XXE_CONTENT``  the input lands inside an element, where a new DOCTYPE
      will not parse; only a reference to an already-declared entity applies.
    """
    prefix = split_template(template).prefix
    if _ONLY_DECL.match(prefix):
        return Context.XXE_DOCUMENT
    return Context.XXE_CONTENT
