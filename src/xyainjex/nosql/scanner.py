"""A NoSQL (MongoDB / JSON query) aware scanner.

Models an input embedded in a JSON query document, for example
``{"user": "{INPUT}", "pass": "x"}``. It tracks JSON strings (with ``\\"``
escapes) and object and array nesting, and records the tokens that signal
injection: MongoDB query operators (``$ne``, ``$gt``, ``$where``, ``$regex``,
``$or`` and friends), the key separator ``:``, and the object open ``{``.
"""

from __future__ import annotations

from ..scan import DOUBLE, BaseScanner

OBJ = "{"  # frame kind for an open object
ARR = "["  # frame kind for an open array

# MongoDB query operators whose appearance signals the payload is injecting
# query logic rather than a plain value.
OPERATORS = {
    "$ne",
    "$eq",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$in",
    "$nin",
    "$or",
    "$and",
    "$nor",
    "$not",
    "$exists",
    "$regex",
    "$options",
    "$where",
    "$expr",
    "$elemMatch",
    "$all",
    "$size",
    "$type",
    "$mod",
    "$text",
    "$jsonSchema",
}


class NoSqlScanner(BaseScanner):
    """Incremental JSON/MongoDB scanner, fed in one or more chunks."""

    def __init__(self) -> None:
        super().__init__()
        self._str_start_i = 0
        self._str_start_index = 0

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

            if top == DOUBLE:
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    st.stack.pop()
                    # A JSON key like "$ne" is an operator even though it is
                    # quoted; surface it as an injected token.
                    content = s[self._str_start_i + 1 : i]
                    if content in OPERATORS:
                        self._record_separator(self._str_start_index, content, record)
                i += 1
                continue

            if c == '"':
                self._str_start_i = i
                self._str_start_index = i + offset
                self._push(DOUBLE)
                i += 1
                continue
            if c == "{":
                self._push(OBJ)
                self._record_separator(i + offset, "{", record)
                i += 1
                continue
            if c == "[":
                self._push(ARR)
                i += 1
                continue
            if c == "}":
                if top == OBJ:
                    st.stack.pop()
                i += 1
                continue
            if c == "]":
                if top == ARR:
                    st.stack.pop()
                i += 1
                continue
            if c == "$":
                j = i + 1
                while j < n and (s[j].isalnum() or s[j] == "_"):
                    j += 1
                op = s[i:j]
                if op in OPERATORS:
                    self._record_separator(i + offset, op, record)
                i = j
                continue
            if c == ":":
                self._record_separator(i + offset, ":", record)
                i += 1
                continue

            i += 1

        self._touch_min()
        return st
