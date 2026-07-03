"""Classify the LDAP context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template


def analyze_ldap_context(template: str) -> Context:
    """Return the LDAP context surrounding the injection point.

    The marker must be present; LDAP injection is always into a search filter,
    so the context is uniform.
    """
    split_template(template)  # validate the {INPUT} marker is present
    return Context.LDAP_FILTER
