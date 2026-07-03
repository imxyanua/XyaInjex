"""An LDAP search filter aware scanner.

LDAP filters use prefix notation, ``(&(attr=value)(attr2=value2))``, and have no
string quoting; values are delimited by the surrounding parentheses. The
metacharacters that matter for injection are ``(`` and ``)`` (assertion
grouping), ``*`` (wildcard), and the ``&``, ``|``, ``!`` logical operators.
Special characters in a value are escaped as ``\\28`` style sequences, so a
backslash escape makes the following character literal.
"""

from __future__ import annotations

from ..scan import BaseScanner

PAREN = "("  # frame kind for an open assertion or group

# Metacharacters recorded as tokens; presence in the payload signals the input
# is altering the filter structure rather than supplying a value.
_METATOKENS = {"(", ")", "*", "&", "|", "!"}


class LdapScanner(BaseScanner):
    """Incremental LDAP filter scanner, fed in one or more chunks."""

    def feed(self, text: str, *, offset: int = 0, record: bool = True):
        s = text
        i = 0
        n = len(s)
        st = self.state
        self._touch_min()
        while i < n:
            self._touch_min()
            c = s[i]

            # Backslash escapes the next character (e.g. \28 for a literal '(').
            if c == "\\":
                i += 2
                continue

            if c == "(":
                self._push(PAREN)
                self._record_separator(i + offset, "(", record)
                i += 1
                continue
            if c == ")":
                if st.top == PAREN:
                    st.stack.pop()
                self._record_separator(i + offset, ")", record)
                i += 1
                continue
            if c in "*&|!":
                self._record_separator(i + offset, c, record)
                i += 1
                continue

            i += 1

        self._touch_min()
        return st


def is_metatoken(token: str) -> bool:
    return token in _METATOKENS
