"""A fish shell aware scanner.

fish differs from POSIX shells in one way that matters most for injection:
command substitution is bare parentheses ``(command)`` (and ``$(command)`` since
fish 3.4), not ``$(...)``. So an unquoted ``(`` opens executable code. fish has
no backtick substitution and no ``$((...))`` or ``${...}`` expansions.
"""

from __future__ import annotations

from ..scan import CMDSUB, DOUBLE, SINGLE, BaseScanner

_WORD_BREAK = set(" \t\n;&|(")


class FishScanner(BaseScanner):
    """Incremental fish scanner, fed in one or more chunks."""

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

            # Single quotes: only \' and \\ are escapes; everything else literal.
            if top == SINGLE:
                if c == "\\" and i + 1 < n and s[i + 1] in ("'", "\\"):
                    i += 2
                    continue
                if c == "'":
                    st.stack.pop()
                i += 1
                continue

            # Backslash escape outside single quotes.
            if c == "\\":
                i += 2
                continue

            if top == DOUBLE:
                if c == '"':
                    st.stack.pop()
                    i += 1
                    continue
                if c == "$" and i + 1 < n and s[i + 1] == "(":
                    self._record_sub(i + offset, record)
                    self._push(CMDSUB)
                    i += 2
                    continue
                i += 1
                continue

            # Unquoted, or inside a command substitution.
            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(":
                self._record_sub(i + offset, record)
                self._push(CMDSUB)
                i += 2
                continue
            if c == "(":  # bare command substitution
                self._record_sub(i + offset, record)
                self._push(CMDSUB)
                i += 1
                continue
            if top == CMDSUB and c == ")":
                st.stack.pop()
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
