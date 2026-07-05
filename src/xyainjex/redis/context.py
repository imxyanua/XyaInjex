"""Classify where the input sits in a Redis (RESP) command."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_redis_context(template: str) -> Context:
    """Return the Redis injection context.

    - ``REDIS_INLINE``   the input is (or starts) the command line, so a command
      word is injected directly.
    - ``REDIS_ARGUMENT`` the input is an argument of an existing command, so a
      CRLF is needed to break onto a new command line.
    """
    prefix = split_template(template).prefix
    if prefix == "" or prefix.isspace():
        return Context.REDIS_INLINE
    return Context.REDIS_ARGUMENT
