"""Classify where the injection point sits within a URL."""

from __future__ import annotations

import re

from ..models import Context
from ..shell.context import split_template

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def analyze_ssrf_context(template: str) -> Context:
    """Return the URL context surrounding the injection point.

    - ``SSRF_URL``   the input forms the whole URL (the server fetches it as-is).
    - ``SSRF_HOST``  the input lands in the authority (host[:port]) position.
    - ``SSRF_PATH``  the input lands in the URL path.
    - ``SSRF_QUERY`` the input is a query-string value (often a ``url=`` param
      that the server fetches).
    """
    prefix = split_template(template).prefix

    match = _SCHEME.search(prefix)
    if not match:
        # No scheme before the marker: the input supplies the whole target URL.
        return Context.SSRF_URL

    rest = prefix[match.end() :]
    if "?" in rest or "#" in rest:
        return Context.SSRF_QUERY
    if "/" in rest:
        return Context.SSRF_PATH
    return Context.SSRF_HOST
