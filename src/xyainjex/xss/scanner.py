"""An HTML aware scanner for XSS analysis.

Tracks the lexical regions of an HTML document that matter for cross-site
scripting: element text, the inside of a tag and its quoted attribute values,
``<script>`` element bodies, and ``<!-- -->`` comments. It records the markup a
payload introduces: a new element, a ``<script`` open, a tag close ``>``, an
``on*`` event-handler attribute, and a ``</script>`` break-out.
"""

from __future__ import annotations

from ..scan import BaseScanner

TAG = "<"
ATTR_D = 'a"'
ATTR_S = "a'"
COMMENT = "comment"
SCRIPT = "script"


def _name(s: str, i: int, n: int) -> str:
    j = i
    while j < n and (s[j].isalnum() or s[j] in "-_"):
        j += 1
    return s[i:j]


class XssScanner(BaseScanner):
    """Incremental HTML scanner, fed in one or more chunks."""

    def __init__(self) -> None:
        super().__init__()
        self._pending_script = False

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

            if top == COMMENT:
                if s.startswith("-->", i):
                    st.stack.pop()
                    self._record_separator(i + offset, "-->", record)
                    i += 3
                    continue
                i += 1
                continue

            if top == SCRIPT:
                if s[i : i + 8].lower() == "</script":
                    st.stack.pop()
                    self._record_separator(i + offset, "script-close", record)
                    i += 8
                    continue
                i += 1
                continue

            if top == ATTR_D:
                if c == '"':
                    st.stack.pop()
                i += 1
                continue
            if top == ATTR_S:
                if c == "'":
                    st.stack.pop()
                i += 1
                continue

            if top == TAG:
                if c == '"':
                    self._push(ATTR_D)
                    i += 1
                    continue
                if c == "'":
                    self._push(ATTR_S)
                    i += 1
                    continue
                if c == ">":
                    st.stack.pop()
                    if self._pending_script:
                        self._push(SCRIPT)
                        self._pending_script = False
                    self._record_separator(i + offset, ">", record)
                    i += 1
                    continue
                if (c.isalpha()) and (i == 0 or not s[i - 1].isalnum()):
                    word = _name(s, i, n)
                    if word[:2].lower() == "on" and len(word) > 2:
                        self._record_separator(i + offset, "event-handler", record)
                    i += len(word)
                    continue
                i += 1
                continue

            # Element text (top level).
            if s.startswith("<!--", i):
                self._push(COMMENT)
                i += 4
                continue
            if c == "<" and i + 1 < n and (s[i + 1].isalpha() or s[i + 1] == "/"):
                start = i + (2 if s[i + 1] == "/" else 1)
                name = _name(s, start, n)
                if name.lower() == "script" and s[i + 1] != "/":
                    self._pending_script = True
                    self._record_separator(i + offset, "script", record)
                self._record_separator(i + offset, "element", record)
                self._push(TAG)
                i = start + len(name)
                continue

            i += 1

        self._touch_min()
        return st
