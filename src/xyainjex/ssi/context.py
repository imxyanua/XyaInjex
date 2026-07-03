"""Classify the SSI context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_ssi_context(template: str) -> Context:
    """Return the SSI context.

    SSI directives are parsed anywhere in the page body, so a single text context
    is used. The marker is validated to be present.
    """
    split_template(template)
    return Context.SSI_TEXT
