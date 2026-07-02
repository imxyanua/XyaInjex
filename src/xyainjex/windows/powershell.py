"""A PowerShell aware scanner.

PowerShell lexing highlights:

- Single quotes are literal strings; ``''`` escapes a quote inside them.
- Double quotes allow ``$(...)`` subexpressions, ``${...}`` variables, and use
  the backtick as the escape character.
- The backtick ````` is the escape character (not a command substitution as
  in POSIX).
- ``$( ... )`` and ``@( ... )`` are subexpressions; ``${ ... }`` is a variable.
- Command separators are ``;``, ``|``, ``&`` and, in PowerShell 7, ``&&`` and
  ``||``.
- Comments are ``#`` to end of line and ``<# ... #>`` blocks.
"""

from __future__ import annotations

from ..scan import DOUBLE, PARAM, SINGLE, SUBEXPR, BaseScanner

_WORD_BREAK = set(" \t\n;&|(")


class PowerShellScanner(BaseScanner):
    """Incremental PowerShell scanner, fed in one or more chunks."""

    def __init__(self) -> None:
        super().__init__()
        self._in_block = False

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]

            if self._in_block:
                if c == "#" and i + 1 < n and s[i + 1] == ">":
                    self._in_block = False
                    i += 2
                    continue
                i += 1
                continue

            if st.in_comment:
                if c == "\n":
                    st.in_comment = False
                i += 1
                continue

            top = st.top

            # Single quotes are literal.
            if top == SINGLE:
                if c == "'":
                    st.stack.pop()
                i += 1
                continue

            # Backtick escapes the next character outside single quotes.
            if c == "`":
                i += 2
                continue

            if top == DOUBLE:
                if c == '"':
                    st.stack.pop()
                    i += 1
                    continue
                if c == "$" and i + 1 < n and s[i + 1] == "(":
                    self._push(SUBEXPR)
                    i += 2
                    continue
                if c == "$" and i + 1 < n and s[i + 1] == "{":
                    self._push(PARAM)
                    i += 2
                    continue
                i += 1
                continue

            if top == PARAM:
                if c == "}":
                    st.stack.pop()
                i += 1
                continue

            # Unquoted, or inside a subexpression.
            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                self._push(SUBEXPR)
                i += 2
                continue
            if c == "@" and i + 1 < n and s[i + 1] == "(":
                self._push(SUBEXPR)
                i += 2
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "{":
                self._push(PARAM)
                i += 2
                continue
            if c == "<" and i + 1 < n and s[i + 1] == "#":
                self._in_block = True
                i += 2
                continue

            if top == SUBEXPR:
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

            if st.depth == 0 and c in "(){}[]":
                self._bracket(c)
                i += 1
                continue

            if c == "#" and self._prev_is_break(s, i, offset):
                self._record_comment(i + offset, record)
                i += 1
                continue

            if c == "\n":
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

        self._touch_min()
        return st

    @staticmethod
    def _prev_is_break(s: str, i: int, offset: int) -> bool:
        if i == 0:
            return offset == 0
        return s[i - 1] in _WORD_BREAK
