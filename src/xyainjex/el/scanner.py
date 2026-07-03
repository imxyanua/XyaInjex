"""An expression-language aware scanner.

Recognizes the interpolation delimiters used by Java expression languages and
lookups: ``${...}`` (JSP EL, Log4j, Freemarker), ``#{...}`` (Spring SpEL), and
``%{...}`` (Struts OGNL). It tracks nested braces and string literals inside an
expression, and records where each expression opens and closes so a payload can
be told whether it opened an evaluated expression from literal text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..scan import DOUBLE, SINGLE, BaseScanner

EXPR = "${"  # frame kind for an open expression region

_OPENERS = ("${", "#{", "%{")


@dataclass
class ElRegion:
    opener: str
    start: int
    end: int | None = None


class ElScanner(BaseScanner):
    """Incremental expression-language scanner, fed in one or more chunks."""

    def __init__(self) -> None:
        super().__init__()
        self.regions: list[ElRegion] = []
        self._open_regions: list[ElRegion] = []

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
                if c == "\\":
                    i += 2
                    continue
                if c == "'":
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

            opener = next((o for o in _OPENERS if s.startswith(o, i)), None)
            if opener is not None:
                region = ElRegion(opener=opener, start=i + offset)
                if record:
                    self.regions.append(region)
                self._open_regions.append(region)
                self._push(EXPR)
                i += 2
                continue

            if top == EXPR:
                if c == "'":
                    self._push(SINGLE)
                    i += 1
                    continue
                if c == '"':
                    self._push(DOUBLE)
                    i += 1
                    continue
                if c == "{":
                    st.stack[-1].depth += 1
                    i += 1
                    continue
                if c == "}":
                    if st.stack[-1].depth > 0:
                        st.stack[-1].depth -= 1
                    else:
                        st.stack.pop()
                        if self._open_regions:
                            self._open_regions.pop().end = i + offset + 1
                    i += 1
                    continue

            i += 1

        self._touch_min()
        return st
