"""Classify where the injection point sits within a filesystem path."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template

_SEPARATORS = ("/", "\\")


def analyze_path_context(template: str) -> Context:
    """Return the filesystem-path context surrounding the injection point.

    - ``PATH_FULL`` the input forms the whole path (no directory prefix).
    - ``PATH_EXT``  a fixed suffix follows the input (e.g. a ``.php`` extension
      that a null byte or truncation can bypass).
    - ``PATH_BASE`` the input is a path component appended under a base
      directory.
    """
    parts = split_template(template)
    prefix, suffix = parts.prefix, parts.suffix

    if not any(sep in prefix for sep in _SEPARATORS):
        return Context.PATH_FULL
    if suffix and suffix[0] not in _SEPARATORS:
        return Context.PATH_EXT
    return Context.PATH_BASE
