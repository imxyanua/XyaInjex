"""Shell aware primitives: scanner, context analyzer, balance, breakout."""

from .balance import balance
from .breakout import detect_breakout
from .context import INPUT_MARKER, analyze_context
from .scanner import ScanState, SeparatorEvent, ShellScanner

__all__ = [
    "ShellScanner",
    "ScanState",
    "SeparatorEvent",
    "analyze_context",
    "balance",
    "detect_breakout",
    "INPUT_MARKER",
]
