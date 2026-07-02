"""A cmd.exe (Windows batch) aware scanner.

cmd.exe has a very different lexer from POSIX shells:

- Only double quotes exist. There is no single quote and no backtick.
- ``^`` is the escape character outside quotes; it escapes the next character.
- Command separators are ``&``, ``&&``, ``||``, ``|`` and newlines. There is no
  ``;`` separator and no inline comment token, so trailing content cannot be
  commented out the way ``#`` does in POSIX.
- ``(`` and ``)`` group commands.

Command injection in cmd.exe therefore works by closing a double quote (when
present) and appending a ``&`` style separator.
"""

from __future__ import annotations

from ..scan import DOUBLE, BaseScanner


class CmdScanner(BaseScanner):
    """Incremental cmd.exe scanner, fed in one or more chunks."""

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
                if c == DOUBLE:
                    st.stack.pop()
                i += 1
                continue

            # Caret escapes the next character outside quotes.
            if c == "^":
                i += 2
                continue

            if c == '"':
                self._push(DOUBLE)
                i += 1
                continue

            if st.depth == 0 and c in "()":
                self._bracket(c)
                i += 1
                continue

            if c == "\n":
                self._record_separator(i + offset, "\n", record)
                i += 1
                continue
            if c == "|":
                token = "||" if i + 1 < n and s[i + 1] == "|" else "|"
                self._record_separator(i + offset, token, record)
                i += len(token)
                continue
            if c == "&":
                token = "&&" if i + 1 < n and s[i + 1] == "&" else "&"
                self._record_separator(i + offset, token, record)
                i += len(token)
                continue

            i += 1

        self._touch_min()
        return st
