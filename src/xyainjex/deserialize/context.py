"""Classify the delivery form of an insecure-deserialization payload."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_deserialize_context(template: str) -> Context:
    """Return the nominal deserialization context.

    The real distinction (raw vs base64 / hex encoded serialized data) depends on
    the payload, so the breakout sets it; the template only names the sink. This
    returns ``DESERIALIZE_RAW`` and validates the ``{INPUT}`` marker.
    """
    split_template(template)
    return Context.DESERIALIZE_RAW
