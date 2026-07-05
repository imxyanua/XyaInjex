"""Classify whether the input is an ORM filter key or a filter value."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_orm_context(template: str) -> Context:
    """Return the ORM lookup context.

    - ``ORM_LOOKUP_KEY``   the input is (part of) a filter key, where a
      ``field__lookup`` or a ``relation__field`` traversal changes the query.
    - ``ORM_LOOKUP_VALUE`` the input is a filter value, where a ``__`` is plain
      data.
    """
    parts = split_template(template)
    suffix = parts.suffix.lstrip()
    prefix = parts.prefix.rstrip()

    if suffix.startswith("="):
        return Context.ORM_LOOKUP_KEY
    if prefix.endswith("="):
        return Context.ORM_LOOKUP_VALUE
    return Context.ORM_LOOKUP_KEY
