"""An XML aware scanner.

Tracks the lexical regions of an XML document: element text, the inside of a tag
(``<... >``) and its quoted attribute values, ``<![CDATA[ ... ]]>`` sections,
and ``<!-- ... -->`` comments. It records markup the payload introduces: a new
element open, a tag close ``>``, a CDATA or comment close, and an entity
reference.
"""

from __future__ import annotations

from ..scan import BaseScanner

TAG = "<"  # inside a start/end tag, parsing attributes
ATTR_D = 'a"'  # double-quoted attribute value
ATTR_S = "a'"  # single-quoted attribute value
CDATA = "cdata"
COMMENT = "comment"


class XmlScanner(BaseScanner):
    """Incremental XML scanner, fed in one or more chunks."""

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

            if top == CDATA:
                if s.startswith("]]>", i):
                    st.stack.pop()
                    self._record_separator(i + offset, "]]>", record)
                    i += 3
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
                    self._record_separator(i + offset, ">", record)
                    i += 1
                    continue
                i += 1
                continue

            # Element text (top level).
            if s.startswith("<!--", i):
                self._push(COMMENT)
                self._record_separator(i + offset, "element", record)
                i += 4
                continue
            if s.startswith("<![CDATA[", i):
                self._push(CDATA)
                i += 9
                continue
            if c == "<" and i + 1 < n and (s[i + 1].isalpha() or s[i + 1] in "/!?"):
                self._push(TAG)
                self._record_separator(i + offset, "element", record)
                i += 1
                continue
            if c == "&":
                j = i + 1
                while j < n and j - i < 32 and s[j] not in ";<&":
                    j += 1
                if j < n and s[j] == ";":
                    self._record_separator(i + offset, "entity", record)
                    i = j + 1
                    continue
            i += 1

        self._touch_min()
        return st
