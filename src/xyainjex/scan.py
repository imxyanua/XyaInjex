"""Shared scanning primitives used by every dialect scanner.

A scanner walks a command string once while maintaining a stack of lexical
frames (quotes, substitutions). It records command separators together with the
stack depth at which they occur, detects comment starts, tracks bracket balance
at the top level, and tracks the minimum stack depth reached. That is exactly
the information the breakout analysis needs, independent of the shell dialect.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Frame kinds shared across dialects.
SINGLE = "'"
DOUBLE = '"'
BACKTICK = "`"
CMDSUB = "$("
ARITH = "$(("
PARAM = "${"
SUBEXPR = "$( )"  # PowerShell subexpression $( ... )
VAR = "%"  # cmd.exe %VAR% / delayed !VAR!
HEREDOC = "<<"  # POSIX here-document body


@dataclass
class Frame:
    kind: str
    depth: int = 0  # nested parenthesis count, used by substitution frames


@dataclass
class SeparatorEvent:
    """A command separator observed while scanning."""

    index: int
    token: str
    stack_depth: int


@dataclass
class CommentEvent:
    index: int
    stack_depth: int


@dataclass
class ScanState:
    """Snapshot of the scanner after consuming some input."""

    stack: list[Frame] = field(default_factory=list)
    separators: list[SeparatorEvent] = field(default_factory=list)
    comment: CommentEvent | None = None
    in_comment: bool = False
    brackets: dict[str, int] = field(
        default_factory=lambda: {"()": 0, "{}": 0, "[]": 0}
    )
    min_depth: int = 0

    @property
    def depth(self) -> int:
        return len(self.stack)

    @property
    def top(self) -> str | None:
        return self.stack[-1].kind if self.stack else None


_BRACKET_OPEN = {"(": "()", "{": "{}", "[": "[]"}
_BRACKET_CLOSE = {")": "()", "}": "{}", "]": "[]"}


class BaseScanner:
    """Common state and recording helpers for concrete dialect scanners.

    Subclasses implement :meth:`feed`; they call the ``_record_*`` helpers so
    every dialect produces a uniform :class:`ScanState`.
    """

    def __init__(self) -> None:
        self.state = ScanState()

    def reset_min(self) -> None:
        """Set the min-depth baseline to the current stack depth.

        Used to measure how far a following chunk pops below the current
        context, for example a payload escaping its surrounding quote.
        """
        self.state.min_depth = self.state.depth

    def _touch_min(self) -> None:
        self.state.min_depth = min(self.state.min_depth, self.state.depth)

    def _record_separator(self, index: int, token: str, record: bool) -> None:
        if record:
            self.state.separators.append(SeparatorEvent(index, token, self.state.depth))

    def _record_comment(self, index: int, record: bool) -> None:
        if record and self.state.comment is None:
            self.state.comment = CommentEvent(index, self.state.depth)
        self.state.in_comment = True

    def _push(self, kind: str) -> None:
        self.state.stack.append(Frame(kind))

    def _bracket(self, c: str) -> None:
        """Track a top-level bracket, only when the stack is empty."""
        if self.state.depth != 0:
            return
        if c in _BRACKET_OPEN:
            self.state.brackets[_BRACKET_OPEN[c]] += 1
        elif c in _BRACKET_CLOSE:
            self.state.brackets[_BRACKET_CLOSE[c]] -= 1

    def feed(self, text: str, *, offset: int = 0, record: bool = True) -> ScanState:
        raise NotImplementedError
