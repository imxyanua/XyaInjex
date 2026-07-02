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
from ..scan import BACKTICK, DOUBLE, SINGLE, BaseScanner, CommentEvent, Frame

# Extra frame kinds for dialect-specific quoting.
BRACKET = "[]"  # MSSQL bracket-quoted identifier [col]
DOLLAR = "$$"  # PostgreSQL dollar-quoted string $tag$...$tag$
QQUOTE = "q'"  # Oracle alternative quoting q'[...]'

_ORACLE_QQUOTE_CLOSE = {"[": "]", "(": ")", "{": "}", "<": ">"}

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


def _dollar_quote(s: str, i: int, n: int) -> str | None:
    """Return the ``$tag$`` opener at ``i``, or None (e.g. a ``$1`` param)."""
    j = i + 1
    if j < n and s[j].isdigit():
        return None
    while j < n and (s[j].isalnum() or s[j] == "_"):
        j += 1
    if j < n and s[j] == "$":
        return s[i : j + 1]
    return None


class SqlScanner(BaseScanner):
    """Incremental SQL scanner, fed in one or more chunks."""

    def __init__(self, dialect: SqlDialect = SqlDialect.MYSQL) -> None:
        super().__init__()
        self.dialect = dialect
        self._backslash = dialect in _BACKSLASH_DIALECTS
        self._hash_comment = dialect == SqlDialect.MYSQL
        self._brackets = dialect == SqlDialect.MSSQL
        self._dollar = dialect == SqlDialect.POSTGRES
        self._qquote = dialect == SqlDialect.ORACLE
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

            if top == BRACKET:  # MSSQL [identifier]
                if c == "]":
                    if i + 1 < n and s[i + 1] == "]":  # ]] escape
                        i += 2
                        continue
                    st.stack.pop()
                i += 1
                continue

            if top in (DOLLAR, QQUOTE):  # tagged string, closes on its marker
                marker = st.stack[-1].label
                if s.startswith(marker, i):
                    st.stack.pop()
                    i += len(marker)
                    continue
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
            if self._brackets and c == "[":
                self._push(BRACKET)
                i += 1
                continue
            if self._dollar and c == "$":
                opener = _dollar_quote(s, i, n)
                if opener is not None:
                    st.stack.append(Frame(DOLLAR, label=opener))
                    i += len(opener)
                    continue
            if (
                self._qquote
                and c in "qQ"
                and i + 1 < n
                and s[i + 1] == "'"
                and i + 2 < n
                and self._word_boundary(s, i, offset)
            ):
                delim = s[i + 2]
                close = _ORACLE_QQUOTE_CLOSE.get(delim, delim)
                st.stack.append(Frame(QQUOTE, label=close + "'"))
                i += 3
                continue

            # Comments.
            if c == "-" and i + 1 < n and s[i + 1] == "-":
                self._record_comment(i + offset, record)
                i += 2
                continue
            if c == "#" and self._hash_comment:
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
