"""An XPath aware scanner.

Tracks string literals (``'...'`` and ``"..."``; XPath has no in-string escape,
a quote simply ends the string), parenthesis and predicate balance, and the
logic tokens that signal an injection at the top level: the ``or`` and ``and``
operators, the predicate close ``]``, the union ``|``, and ``=``.
"""

from __future__ import annotations

from ..scan import DOUBLE, SINGLE, BaseScanner

# Tokens that, at the top level after the injection point, indicate the payload
# is altering the XPath expression rather than supplying data.
_LOGIC_TOKENS = {"or", "and", "]", "|", "="}


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch in "_-"


class XPathScanner(BaseScanner):
    """Incremental XPath scanner, fed in one or more chunks."""

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

            if top == SINGLE:
                if c == "'":
                    st.stack.pop()
                i += 1
                continue
            if top == DOUBLE:
                if c == '"':
                    st.stack.pop()
                i += 1
                continue

            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue

            if c in "()[]":
                self._bracket(c)
                if c == "]":
                    self._record_separator(i + offset, "]", record)
                i += 1
                continue
            if c == "|":
                self._record_separator(i + offset, "|", record)
                i += 1
                continue
            if c == "=":
                self._record_separator(i + offset, "=", record)
                i += 1
                continue

            if (c.isalpha() or c == "_") and self._word_boundary(s, i, offset):
                j = i
                while j < n and _is_word(s[j]):
                    j += 1
                word = s[i:j].lower()
                if word in ("or", "and"):
                    self._record_separator(i + offset, word, record)
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


def is_logic_token(token: str) -> bool:
    return token in _LOGIC_TOKENS
