"""A GraphQL aware scanner.

Tracks GraphQL string arguments (``"..."`` with backslash escapes and
``\"\"\"...\"\"\"`` block strings) and the selection and argument structure
(``{}`` and ``()``). It records the tokens that signal injection: a field
selection ``{``, an argument list ``(``, a directive ``@``, and an introspection
identifier (``__schema``, ``__type``, ``__typename``).
"""

from __future__ import annotations

from ..scan import DOUBLE, BaseScanner

BLOCK = '"""'
BRACE = "{"
PAREN = "("

_INTROSPECTION = {"__schema", "__type", "__typename"}


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class GraphqlScanner(BaseScanner):
    """Incremental GraphQL scanner, fed in one or more chunks."""

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]
            top = st.top

            if top == BLOCK:
                if s.startswith('"""', i):
                    st.stack.pop()
                    i += 3
                    continue
                i += 1
                continue

            if top == DOUBLE:
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    st.stack.pop()
                i += 1
                continue

            if s.startswith('"""', i):
                self._push(BLOCK)
                i += 3
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if c == "{":
                self._push(BRACE)
                self._record_separator(i + offset, "{", record)
                i += 1
                continue
            if c == "(":
                self._push(PAREN)
                self._record_separator(i + offset, "(", record)
                i += 1
                continue
            if c == "}":
                if top == BRACE:
                    st.stack.pop()
                self._record_separator(i + offset, "}", record)
                i += 1
                continue
            if c == ")":
                if top == PAREN:
                    st.stack.pop()
                self._record_separator(i + offset, ")", record)
                i += 1
                continue
            if c == "@":
                self._record_separator(i + offset, "@", record)
                i += 1
                continue
            if c == "_" and self._word_boundary(s, i, offset):
                j = i
                while j < n and _is_word(s[j]):
                    j += 1
                if s[i:j] in _INTROSPECTION:
                    self._record_separator(i + offset, "introspection", record)
                i = j
                continue

            i += 1

        self._touch_min()
        return st

    @staticmethod
    def _word_boundary(s: str, i: int, offset: int) -> bool:
        if i == 0:
            return offset == 0
        return not _is_word(s[i - 1])
