"""A SQL aware scanner.

Tracks string literals (``'...'`` with ``''`` doubling), quoted identifiers
(``"..."`` and MySQL ```...```), comments (``--`` and ``#`` to end of
line, and ``/* ... */`` blocks), parenthesis balance, stacked query separators
(``;``), and SQL keyword tokens at the top level.

Like the shell scanners it is lexical, not a full SQL parser: the goal is to
reason about whether a payload escapes a string literal and injects SQL code.
"""

from __future__ import annotations

from ..models import SqlDialect
from ..scan import BACKTICK, DOUBLE, SINGLE, BaseScanner, CommentEvent

# SQL keywords whose appearance at the top level, after the injection point,
# signals that the payload is being interpreted as code rather than data.
KEYWORDS = {
    "OR",
    "AND",
    "UNION",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "EXEC",
    "EXECUTE",
    "SLEEP",
    "BENCHMARK",
    "WAITFOR",
    "HAVING",
    "ORDER",
    "PROCEDURE",
    "CASE",
    "WHEN",
    "INTO",
    "LOAD_FILE",
    "OUTFILE",
    "DUMPFILE",
    "XP_CMDSHELL",
}

# Dialects where a backslash escapes the next character inside a string.
_BACKSLASH_DIALECTS = {SqlDialect.MYSQL}


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class SqlScanner(BaseScanner):
    """Incremental SQL scanner, fed in one or more chunks."""

    def __init__(self, dialect: SqlDialect = SqlDialect.MYSQL) -> None:
        super().__init__()
        self.dialect = dialect
        self._backslash = dialect in _BACKSLASH_DIALECTS
        self.in_block = False

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]

            if self.in_block:
                if c == "*" and i + 1 < n and s[i + 1] == "/":
                    self.in_block = False
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

            if top == SINGLE:
                if c == "\\" and self._backslash:
                    i += 2
                    continue
                if c == "'":
                    if i + 1 < n and s[i + 1] == "'":  # doubled '' escape
                        i += 2
                        continue
                    st.stack.pop()
                i += 1
                continue

            if top == DOUBLE:
                if c == "\\" and self._backslash:
                    i += 2
                    continue
                if c == '"':
                    if i + 1 < n and s[i + 1] == '"':
                        i += 2
                        continue
                    st.stack.pop()
                i += 1
                continue

            if top == BACKTICK:
                if c == "`":
                    if i + 1 < n and s[i + 1] == "`":
                        i += 2
                        continue
                    st.stack.pop()
                i += 1
                continue

            # Outside quotes.
            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if c == "`":
                self._push(BACKTICK)
                i += 1
                continue

            # Comments.
            if c == "-" and i + 1 < n and s[i + 1] == "-":
                self._record_comment(i + offset, record)
                i += 2
                continue
            if c == "#":
                self._record_comment(i + offset, record)
                i += 1
                continue
            if c == "/" and i + 1 < n and s[i + 1] == "*":
                if record and st.comment is None:
                    st.comment = CommentEvent(i + offset, st.depth)
                self.in_block = True
                i += 2
                continue

            if c in "()":
                self._bracket(c)
                i += 1
                continue

            if c == ";":
                self._record_separator(i + offset, ";", record)
                i += 1
                continue

            # SQL keyword at a word boundary.
            if (c.isalpha() or c == "_") and self._word_boundary(s, i, offset):
                j = i
                while j < n and _is_word(s[j]):
                    j += 1
                word = s[i:j]
                if word.upper() in KEYWORDS:
                    self._record_separator(i + offset, word.upper(), record)
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
