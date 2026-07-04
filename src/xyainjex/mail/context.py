"""Classify where the injection point sits within an email / SMTP message."""

from __future__ import annotations

import re

from ..models import Context
from ..shell.context import split_template

# An SMTP command verb at the start of a line.
_SMTP_VERB = re.compile(
    r"^(MAIL\s+FROM|RCPT\s+TO|DATA|HELO|EHLO|VRFY|EXPN|RSET|QUIT|AUTH|STARTTLS)\b",
    re.IGNORECASE,
)
# An email header line: "Name: value".
_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]*\s*:")


def analyze_mail_context(template: str) -> Context:
    """Return the mail context surrounding the injection point.

    - ``SMTP_COMMAND`` the input is an argument of a raw SMTP command line.
    - ``MAIL_HEADER``  the input is an email header value (``To:``, ``Subject:``).
    - ``MAIL_BODY``    the input is in the message body.
    """
    prefix = split_template(template).prefix
    last_line = re.split(r"\r\n|\r|\n", prefix)[-1]

    if _SMTP_VERB.match(last_line.strip()):
        return Context.SMTP_COMMAND
    if _HEADER.match(last_line):
        return Context.MAIL_HEADER
    return Context.MAIL_BODY
