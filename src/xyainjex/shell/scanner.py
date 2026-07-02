"""A small POSIX shell aware scanner (bash, sh, zsh, fish).

The scanner walks a command string character by character while maintaining a
stack of lexical frames: single quote, double quote, backtick, command
substitution ``$(...)``, arithmetic expansion ``$((...))``, parameter
expansion ``${...}``, and here-document bodies (``<<EOF``).

It is intentionally lexical rather than a full parser: the goal is to reason
about quoting state and top level command separators, which is what injection
breakout analysis needs.

Here-document bodies are treated as a literal region terminated by a line equal
to the delimiter. This captures the important breakout where a payload closes
the heredoc with its own delimiter line and then injects commands at the top
level. Command substitution inside a heredoc body is not tracked and is a
documented follow-up.
"""

from __future__ import annotations

from ..scan import (
    ARITH,
    BACKTICK,
    CMDSUB,
    DOUBLE,
    HEREDOC,
    PARAM,
    SINGLE,
    BaseScanner,
)

# Characters that, at the shell top level, end a command word so that a
# following ``#`` begins a comment.
_WORD_BREAK = set(" \t\n;&|(")


def _dollar(s: str, i: int, n: int) -> tuple[str, int] | None:
    """Classify a ``$`` sequence into a frame kind and its length."""
    if s.startswith("$((", i):
        return ARITH, 3
    if i + 1 < n and s[i + 1] == "(":
        return CMDSUB, 2
    if i + 1 < n and s[i + 1] == "{":
        return PARAM, 2
    return None


def _parse_heredoc(s: str, i: int, n: int) -> tuple[str, bool, int] | None:
    """Parse a ``<<`` operator into (delimiter, strip_tabs, next_index).

    Returns ``None`` when this is not a heredoc (``<`` redirection or ``<<<``
    here-string).
    """
    if not (i + 1 < n and s[i + 1] == "<"):
        return None
    if i + 2 < n and s[i + 2] == "<":  # ``<<<`` here-string
        return None
    j = i + 2
    strip = False
    if j < n and s[j] == "-":
        strip = True
        j += 1
    while j < n and s[j] in " \t":
        j += 1
    quote = None
    if j < n and s[j] in ("'", '"'):
        quote = s[j]
        j += 1
    elif j < n and s[j] == "\\":
        j += 1
    start = j
    while j < n and (s[j].isalnum() or s[j] == "_"):
        j += 1
    delim = s[start:j]
    if quote is not None and j < n and s[j] == quote:
        j += 1
    if not delim:
        return None
    return delim, strip, j


class ShellScanner(BaseScanner):
    """Incremental POSIX shell scanner, fed in one or more chunks."""

    def __init__(self) -> None:
        super().__init__()
        self._pending_delim: tuple[str, bool] | None = None
        self._hd_delim: str | None = None
        self._hd_strip: bool = False
        self._hd_line: str = ""

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]

            if st.in_comment:
                if c == "\n":
                    st.in_comment = False
                i += 1
                continue

            top = st.top

            # Here-document body: literal until a line equal to the delimiter.
            if top == HEREDOC:
                if c == "\n":
                    line = self._hd_line
                    if self._hd_strip:
                        line = line.lstrip("\t")
                    if line == self._hd_delim:
                        st.stack.pop()
                        self._hd_delim = None
                    self._hd_line = ""
                else:
                    self._hd_line += c
                i += 1
                continue

            # Single quotes: everything literal until the closing quote.
            if top == SINGLE:
                if c == SINGLE:
                    st.stack.pop()
                i += 1
                continue

            # Parameter expansion ${...}: opaque until the closing brace.
            if top == PARAM:
                if c == "}":
                    st.stack.pop()
                i += 1
                continue

            # Backslash escape everywhere except single quotes and ${...}.
            if c == "\\":
                i += 2
                continue

            if top == DOUBLE:
                if c == DOUBLE:
                    st.stack.pop()
                    i += 1
                    continue
                if c == BACKTICK:
                    self._push(BACKTICK)
                    i += 1
                    continue
                if c == "$":
                    hit = _dollar(s, i, n)
                    if hit:
                        self._push(hit[0])
                        i += hit[1]
                        continue
                i += 1
                continue

            if top == BACKTICK:
                if c == BACKTICK:
                    st.stack.pop()
                elif c == SINGLE:
                    self._push(SINGLE)
                elif c == DOUBLE:
                    self._push(DOUBLE)
                i += 1
                continue

            # Arithmetic expansion $((...)): closes on the paired ``))``.
            if top == ARITH:
                if c == "(":
                    st.stack[-1].depth += 1
                    i += 1
                    continue
                if c == ")":
                    if st.stack[-1].depth > 0:
                        st.stack[-1].depth -= 1
                        i += 1
                    else:
                        st.stack.pop()
                        # consume the second ``)`` of the closing ``))``
                        i += 2 if i + 1 < n and s[i + 1] == ")" else 1
                    continue

            # Unquoted, or inside a command substitution.
            if c == SINGLE:
                self._push(SINGLE)
                i += 1
                continue
            if c == DOUBLE:
                self._push(DOUBLE)
                i += 1
                continue
            if c == BACKTICK:
                self._push(BACKTICK)
                i += 1
                continue
            if c == "$":
                hit = _dollar(s, i, n)
                if hit:
                    self._push(hit[0])
                    i += hit[1]
                    continue

            # Here-document operator, only queued at the true top level.
            if st.depth == 0 and c == "<":
                hd = _parse_heredoc(s, i, n)
                if hd is not None:
                    delim, strip, nxt = hd
                    self._pending_delim = (delim, strip)
                    i = nxt
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

            # Bracket balance at the true top level only.
            if st.depth == 0 and c in "(){}[]":
                self._bracket(c)
                i += 1
                continue

            # Comment start: ``#`` at a word boundary at the top level.
            if c == "#" and self._prev_is_break(s, i, offset):
                self._record_comment(i + offset, record)
                i += 1
                continue

            # A newline that follows a heredoc operator opens the body rather
            # than separating commands.
            if c == "\n":
                if self._pending_delim is not None:
                    self._push(HEREDOC)
                    self._hd_delim, self._hd_strip = self._pending_delim
                    self._pending_delim = None
                    self._hd_line = ""
                else:
                    self._record_separator(i + offset, "\n", record)
                i += 1
                continue
            if c == ";":
                self._record_separator(i + offset, ";", record)
                i += 1
                continue
            if c == "|":
                token = "||" if i + 1 < n and s[i + 1] == "|" else "|"
                self._record_separator(i + offset, token, record)
                i += len(token)
                continue
            if c == "&":
                token = "&&" if i + 1 < n and s[i + 1] == "&" else "&"
                self._record_separator(i + offset, token, record)
                i += len(token)
                continue

            i += 1

        # End of input can terminate a heredoc whose delimiter is on the final
        # line without a trailing newline.
        if st.top == HEREDOC:
            line = self._hd_line.lstrip("\t") if self._hd_strip else self._hd_line
            if line == self._hd_delim:
                st.stack.pop()
                self._hd_delim = None

        self._touch_min()
        return st

    @staticmethod
    def _prev_is_break(s: str, i: int, offset: int) -> bool:
        if i == 0:
            # Chunk boundary: only a real word break at the very start.
            return offset == 0
        return s[i - 1] in _WORD_BREAK
