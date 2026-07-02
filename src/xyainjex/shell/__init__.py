"""Shell aware primitives: scanner, context analyzer, balance, breakout."""

from .scanner import ShellScanner, ScanState, SeparatorEvent
from .context import analyze_context, INPUT_MARKER
from .balance import balance
from .breakout import detect_breakout

__all__ = [
    "ShellScanner",
    "ScanState",
    "SeparatorEvent",
    "analyze_context",
    "balance",
    "detect_breakout",
    "INPUT_MARKER",
]
