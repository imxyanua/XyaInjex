"""A small POSIX shell aware scanner.

The scanner walks a command string character by character while maintaining a
stack of lexical frames (single quote, double quote, backtick, command
substitution). It is the shared foundation for context detection, syntax
balance checking, and breakout analysis.

It is intentionally lexical rather than a full parser: the goal is to reason
about quoting state and top level command separators, which is exactly what
injection breakout analysis needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SINGLE = "'"
DOUBLE = '"'
BACKTICK = "`"
CMDSUB = "$("

# Characters that, at the shell top level, end a command word so that a
# following ``#`` begins a comment.
_WORD_BREAK = set(" \t\n;&|(")


@dataclass
class Frame:
    kind: str
    depth: int = 0  # parenthesis nesting, only meaningful for CMDSUB


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


class ShellScanner:
    """Incremental scanner that can be fed a string in one or more chunks."""

    def __init__(self) -> None:
        self.state = ScanState()

    def feed(self, text: str, *, offset: int = 0, record: bool = True) -> ScanState:
        """Consume ``text``.

        ``offset`` is added to the reported indexes so callers can align events
        with positions in a larger string. When ``record`` is false the scanner
        still updates its quoting stack but does not log separator or comment
        events (used while scanning a known-safe prefix).
        """
        s = text
        i = 0
        n = len(s)
        st = self.state
        st.min_depth = min(st.min_depth, st.depth)
        while i < n:
            st.min_depth = min(st.min_depth, st.depth)
            c = s[i]

            if st.in_comment:
                if c == "\n":
                    st.in_comment = False
                i += 1
                continue

            top = st.top

            # Inside single quotes everything is literal until the closing quote.
            if top == SINGLE:
                if c == SINGLE:
                    st.stack.pop()
                i += 1
                continue

            # Backslash escape everywhere except single quotes.
            if c == "\\":
                i += 2
                continue

            if top == DOUBLE:
                if c == DOUBLE:
                    st.stack.pop()
                elif c == BACKTICK:
                    st.stack.append(Frame(BACKTICK))
                elif c == "$" and i + 1 < n and s[i + 1] == "(":
                    st.stack.append(Frame(CMDSUB))
                    i += 2
                    continue
                i += 1
                continue

            if top == BACKTICK:
                if c == BACKTICK:
                    st.stack.pop()
                elif c == SINGLE:
                    st.stack.append(Frame(SINGLE))
                elif c == DOUBLE:
                    st.stack.append(Frame(DOUBLE))
                i += 1
                continue

            # Unquoted, or inside a command substitution.
            if c == SINGLE:
                st.stack.append(Frame(SINGLE))
                i += 1
                continue
            if c == DOUBLE:
                st.stack.append(Frame(DOUBLE))
                i += 1
                continue
            if c == BACKTICK:
                st.stack.append(Frame(BACKTICK))
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                st.stack.append(Frame(CMDSUB))
                i += 2
                continue

            if top == CMDSUB:
                if c == "(":
                    st.stack[-1].depth += 1
                    i += 1
                    continue
                if c == ")":
                    if st.stack[-1].depth > 0:
                        st.stack[-1].depth -= 1
                    else:
                        st.stack.pop()
                    i += 1
                    continue

            # Bracket balance is only tracked at the true top level (empty
            # stack); brackets inside quotes or substitutions are handled by
            # their own frames.
            if st.depth == 0:
                if c in "({[":
                    st.brackets[{"(": "()", "{": "{}", "[": "[]"}[c]] += 1
                    i += 1
                    continue
                if c in ")}]":
                    st.brackets[{")": "()", "}": "{}", "]": "[]"}[c]] -= 1
                    i += 1
                    continue

            # Comment start: ``#`` at a word boundary at the current top level.
            if c == "#" and self._prev_is_break(s, i, offset):
                if record:
                    st.comment = CommentEvent(index=i + offset, stack_depth=st.depth)
                st.in_comment = True
                i += 1
                continue

            # Command separators.
            if c == "\n":
                if record:
                    st.separators.append(SeparatorEvent(i + offset, "\n", st.depth))
                i += 1
                continue
            if c == ";":
                if record:
                    st.separators.append(SeparatorEvent(i + offset, ";", st.depth))
                i += 1
                continue
            if c == "|":
                token = "||" if i + 1 < n and s[i + 1] == "|" else "|"
                if record:
                    st.separators.append(SeparatorEvent(i + offset, token, st.depth))
                i += len(token)
                continue
            if c == "&":
                token = "&&" if i + 1 < n and s[i + 1] == "&" else "&"
                if record:
                    st.separators.append(SeparatorEvent(i + offset, token, st.depth))
                i += len(token)
                continue

            i += 1

        st.min_depth = min(st.min_depth, st.depth)
        return st

    def reset_min(self) -> None:
        """Set the min-depth baseline to the current stack depth.

        Used to measure how far a following chunk pops below the current
        context, e.g. to detect a payload escaping its surrounding quote.
        """
        self.state.min_depth = self.state.depth

    @staticmethod
    def _prev_is_break(s: str, i: int, offset: int) -> bool:
        if i == 0:
            # Chunk boundary: only a real word break if this is the very start.
            return offset == 0
        return s[i - 1] in _WORD_BREAK
