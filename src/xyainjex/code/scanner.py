"""A code (eval sink) aware scanner for Python, JavaScript, and PHP.

Models an input embedded in source that reaches an eval-style sink. It tracks
string literals (``'...'`` and ``"..."`` with backslash escapes), the JavaScript
template literal ```...``` and its ``${...}`` substitutions, statement
separators (``;``) at the top level, and dangerous sink identifiers such as
``eval``, ``exec``, and ``system`` that appear in code position.
"""

from __future__ import annotations

from ..models import CodeLang
from ..scan import BACKTICK, CMDSUB, DOUBLE, SINGLE, BaseScanner

# Identifiers that reach code or command execution when they appear in code
# position (not inside a string, where they are data).
SINKS = {
    "eval",
    "exec",
    "execSync",
    "system",
    "popen",
    "proc_open",
    "shell_exec",
    "passthru",
    "spawn",
    "spawnSync",
    "assert",
    "require",
    "subprocess",
    "os",
    "child_process",
    "pcntl_exec",
    "Function",
    "setTimeout",
    "setInterval",
}


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class CodeScanner(BaseScanner):
    """Incremental code scanner, fed in one or more chunks."""

    def __init__(self, lang: CodeLang = CodeLang.PYTHON) -> None:
        super().__init__()
        self.lang = lang
        self._template = lang == CodeLang.JAVASCRIPT
        self._hash_comment = lang in (CodeLang.PYTHON, CodeLang.PHP)
        self._slash_comment = lang in (CodeLang.JAVASCRIPT, CodeLang.PHP)

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]

            if st.in_comment:
                if c == "\n":
                    st.in_comment = False
                i += 1
                continue

            top = st.top

            if top in (SINGLE, DOUBLE):
                if c == "\\":
                    i += 2
                    continue
                if (c == "'" and top == SINGLE) or (c == '"' and top == DOUBLE):
                    st.stack.pop()
                i += 1
                continue

            if top == BACKTICK:  # JavaScript template literal
                if c == "\\":
                    i += 2
                    continue
                if c == "`":
                    st.stack.pop()
                    i += 1
                    continue
                if c == "$" and i + 1 < n and s[i + 1] == "{":
                    self._record_sub(i + offset, record)
                    self._push(CMDSUB)
                    i += 2
                    continue
                i += 1
                continue

            if top == CMDSUB:  # inside ${ ... }
                if c == "}":
                    st.stack.pop()
                    i += 1
                    continue

            # Code position (top level or inside a substitution).
            if c == "'":
                self._push(SINGLE)
                i += 1
                continue
            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue
            if self._template and c == "`":
                self._push(BACKTICK)
                i += 1
                continue
            if st.depth == 0 and (
                (self._hash_comment and c == "#")
                or (self._slash_comment and c == "/" and i + 1 < n and s[i + 1] == "/")
            ):
                self._record_comment(i + offset, record)
                i += 1
                continue
            if c == ";" and st.depth == 0:
                self._record_separator(i + offset, ";", record)
                i += 1
                continue

            if (c.isalpha() or c == "_") and self._word_boundary(s, i, offset):
                j = i
                while j < n and _is_word(s[j]):
                    j += 1
                word = s[i:j]
                if word in SINKS:
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
