"""A YAML aware scanner (bounded).

Tracks single-quoted (``'...'`` with ``''`` doubling) and double-quoted
(``"..."`` with backslash escapes) scalars, and, at the plain (unquoted) scalar
level, records the tokens that signal injection: a newline that starts a new
line, a ``:`` key separator, and a ``!`` / ``!!`` tag (the deserialization
vector, e.g. ``!!python/object/apply``).

Full block-indentation parsing is out of scope; this captures the common
breakouts where a payload closes a quoted scalar or injects a new key or a tag.
"""

from __future__ import annotations

from ..scan import DOUBLE, SINGLE, BaseScanner


class YamlScanner(BaseScanner):
    """Incremental YAML scanner, fed in one or more chunks."""

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
                    if i + 1 < n and s[i + 1] == "'":  # '' escape
                        i += 2
                        continue
                    st.stack.pop()
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

            # Plain (unquoted) scalar level.
            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if c == "\n":
                self._record_separator(i + offset, "newline", record)
                i += 1
                continue
            if c == "!" and self._tag_position(s, i, offset):
                self._record_separator(i + offset, "tag", record)
                i += 1
                continue
            if c == ":" and (i + 1 >= n or s[i + 1] in " \t\n"):
                self._record_separator(i + offset, "key", record)
                i += 1
                continue

            i += 1

        self._touch_min()
        return st

    @staticmethod
    def _tag_position(s: str, i: int, offset: int) -> bool:
        # A tag begins a value: at the start, or after whitespace, a newline, or
        # a key separator.
        if i == 0:
            return offset == 0
        return s[i - 1] in " \t\n:"
