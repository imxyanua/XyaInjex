"""Classify which HTTP host header the input controls."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_host_context(template: str) -> Context:
    """Return the host-header context.

    - ``HOST_FORWARDED`` the input is an ``X-Forwarded-Host`` / ``X-Host`` /
      ``Forwarded`` value, which apps often trust while validating ``Host``.
    - ``HOST_HEADER``    the input is the primary ``Host`` value.
    """
    prefix = split_template(template).prefix.lower()
    if "x-forwarded" in prefix or "x-host" in prefix or "forwarded:" in prefix:
        return Context.HOST_FORWARDED
    return Context.HOST_HEADER
