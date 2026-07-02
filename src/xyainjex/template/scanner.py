"""A region based scanner for template engines.

Unlike the shell and SQL scanners, template lexing is about multi-character
delimiters that switch between literal text and executable regions
(expressions, statements, comments). The scanner walks the text once and
records where executable regions begin and end, and tracks string literals
inside expressions so a payload can be told to escape a quoted value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .engines import COMMENT, TemplateSpec


@dataclass
class Region:
    kind: str  # expr | stmt | comment
    open: str
    start: int  # absolute index of the opening delimiter
    end: int | None = None  # absolute index just past the closing delimiter


@dataclass
class TemplateState:
    kind: str = "text"  # text | expr | stmt | comment
    open_token: str = ""
    close_token: str = ""
    in_string: str | None = None
    regions: list[Region] = field(default_factory=list)
    string_closed: bool = False
    _current: Region | None = None


class TemplateScanner:
    """Incremental template scanner, fed in one or more chunks."""

    def __init__(self, spec: TemplateSpec) -> None:
        self.spec = spec
        self.state = TemplateState()
        self._opens = spec.opens_longest_first()

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        while i < n:
            if st.kind == "text":
                match = self._match_open(s, i, n)
                if match is not None:
                    region = Region(kind=match.kind, open=match.open, start=i + offset)
                    if record:
                        st.regions.append(region)
                    st._current = region
                    st.kind = match.kind
                    st.open_token = match.open
                    st.close_token = match.close
                    i += len(match.open)
                    continue
                i += 1
                continue

            if st.kind == COMMENT:
                if s.startswith(st.close_token, i):
                    self._close_region(i + offset + len(st.close_token))
                    i += len(st.close_token)
                    continue
                i += 1
                continue

            # Inside an expression or statement region.
            if st.in_string is not None:
                if s[i] == "\\":
                    i += 2
                    continue
                if s[i] == st.in_string:
                    st.in_string = None
                    st.string_closed = True
                i += 1
                continue

            if s[i] in ("'", '"'):
                st.in_string = s[i]
                i += 1
                continue

            if s.startswith(st.close_token, i):
                self._close_region(i + offset + len(st.close_token))
                i += len(st.close_token)
                continue

            i += 1

        return st

    def _match_open(self, s: str, i: int, n: int):
        for region_def in self._opens:
            if s.startswith(region_def.open, i):
                return region_def
        return None

    def _close_region(self, end: int) -> None:
        st = self.state
        if st._current is not None:
            st._current.end = end
        st.kind = "text"
        st.open_token = ""
        st.close_token = ""
        st.in_string = None
        st._current = None
