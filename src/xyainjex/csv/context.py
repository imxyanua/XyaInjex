"""Classify the CSV context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template

# Characters that end the previous cell, so the input begins a fresh cell.
_CELL_START = set(',;\t\n\r"')


def analyze_csv_context(template: str) -> Context:
    """Return the CSV context surrounding the injection point.

    A spreadsheet only evaluates a formula when the cell *begins* with a trigger
    character, so it matters whether the input starts a cell (preceded by a
    delimiter or a quote, or at the very start) or sits mid-cell.
    """
    parts = split_template(template)
    if parts.prefix == "" or parts.prefix[-1] in _CELL_START:
        return Context.CSV_CELL
    return Context.CSV_MIDCELL
