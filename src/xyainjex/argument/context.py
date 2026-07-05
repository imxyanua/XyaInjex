"""Classify where the injection point sits in a command's argument list."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_argument_context(template: str) -> Context:
    """Return the argument-injection context.

    - ``ARG_OPTION`` the input occupies its own argument slot (the prefix ends at
      a word boundary), so a leading ``-`` is parsed as an option.
    - ``ARG_VALUE``  the input is glued to a preceding token (e.g. ``--file=`` or
      ``-o``), so option injection needs the runner to word-split the value.
    """
    prefix = split_template(template).prefix
    if prefix == "" or prefix[-1].isspace():
        return Context.ARG_OPTION
    return Context.ARG_VALUE
