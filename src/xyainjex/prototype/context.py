"""Classify the prototype-pollution injection vector from the template."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_prototype_context(template: str) -> Context:
    """Return the prototype-pollution context.

    - ``PP_PATH`` the input is a property path (bracket / dot / query notation,
      e.g. ``settings[{INPUT}]=1``) parsed into an object.
    - ``PP_JSON`` the input is (or sits within) a JSON object that is deep-merged.
    """
    parts = split_template(template)
    around = parts.prefix + parts.suffix

    json_ish = "{" in around or "}" in around or ":" in parts.prefix
    path_ish = "[" in around or "]" in around or "=" in around

    if path_ish and not json_ish:
        return Context.PP_PATH
    return Context.PP_JSON
