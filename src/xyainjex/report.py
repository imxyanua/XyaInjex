"""Render analysis results as JSON or as a human readable breakout diagram."""

from __future__ import annotations

import json

from .models import AnalysisResult


def to_json(result: AnalysisResult, *, indent: int = 2) -> str:
    """Serialize an analysis result to JSON."""
    return json.dumps(result.to_dict(), indent=indent)


def _pointer(result: AnalysisResult) -> str | None:
    """A caret line pointing at the breakout position under the rendered text."""
    idx = result.breakout.breakout_index
    if idx is None or idx > len(result.rendered):
        return None
    return " " * idx + "^ breakout point"


def visualize(result: AnalysisResult) -> str:
    """Produce a terminal friendly report with a breakout diagram."""
    b = result.breakout
    lines: list[str] = []
    lines.append("XyaInjex analysis")
    lines.append("=" * 40)
    lines.append(f"Template : {result.template}")
    lines.append(f"Payload  : {result.payload}")
    lines.append(f"Rendered : {result.rendered}")

    pointer = _pointer(result)
    if pointer is not None:
        # Align the caret under the "Rendered : " label.
        lines.append(" " * len("Rendered : ") + pointer)

    lines.append("")
    lines.append(f"Dialect        : {result.dialect.value}")
    lines.append(f"Context        : {result.context.value}")
    lines.append(f"Quote closed   : {b.quote_closed}")
    lines.append(f"Command inject : {b.command_injected}")
    lines.append(f"Separators     : {', '.join(b.separators) or '-'}")
    lines.append(f"Comment term   : {b.comment_terminated}")
    lines.append(f"Syntax valid   : {result.balance.syntax_valid}")
    lines.append(f"Risk           : {result.risk.value}")

    lines.append("")
    lines.append(_flow_diagram(result))

    if result.notes:
        lines.append("")
        lines.append("Notes:")
        for note in result.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)


def _flow_diagram(result: AnalysisResult) -> str:
    """ASCII execution flow reflecting which breakout stages actually fired."""
    b = result.breakout
    stages = ["Original context"]
    if b.quote_closed:
        stages.append("Quote closure")
    if b.command_injected:
        stages.append("Command injection")
    if b.comment_terminated:
        stages.append("Comment truncation")
    if b.command_injected:
        stages.append("Execution")
    else:
        stages.append("No breakout")

    diagram = [stages[0]]
    for stage in stages[1:]:
        diagram.append("      |")
        diagram.append("      v")
        diagram.append(stage)
    return "\n".join(diagram)
