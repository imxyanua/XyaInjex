"""Detect CSV / spreadsheet formula injection breakout."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_csv_context

_TRIGGERS = "=+-@"
# A new cell whose value starts with a formula trigger, injected mid-cell.
_MIDCELL = re.compile(r"[,;\t\n\r][ \t]*[=+\-@]")
# Command execution (DDE) and data exfiltration functions.
_DANGEROUS = re.compile(
    r"cmd\s*\||\bDDE\b|HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTRANGE|IMPORTFEED",
    re.IGNORECASE,
)


def detect_csv_breakout(template: str, payload: str) -> Breakout:
    """Analyze the CSV formula breakout produced by injecting ``payload``.

    ``command_injected`` means the payload makes a cell begin with a formula
    trigger (``=``, ``+``, ``-``, ``@``), which a spreadsheet evaluates.
    """
    parts = split_template(template)
    context = analyze_csv_context(template)

    stripped = payload.lstrip(" \t\r")
    starts_formula = stripped[:1] in _TRIGGERS if stripped else False
    midcell_formula = bool(_MIDCELL.search(payload))
    dangerous = bool(_DANGEROUS.search(payload))

    if context == Context.CSV_CELL:
        command_injected = starts_formula or midcell_formula
    else:  # mid-cell: only a new cell can start a formula
        command_injected = midcell_formula

    tokens: list[str] = []
    if command_injected:
        tokens.append("formula")
    if dangerous:
        tokens.append("dangerous")

    index = len(parts.prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed=False,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=1 if command_injected else 0,
        breakout_index=index,
    )


def score_csv_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a CSV formula breakout to a risk rating."""
    if breakout.command_injected:
        # A dangerous function reaches command execution or exfiltration.
        if "dangerous" in breakout.separators:
            return Risk.CRITICAL
        return Risk.HIGH
    return Risk.LOW
