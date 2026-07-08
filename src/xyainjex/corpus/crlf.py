"""CRLF / response-splitting parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

CRLF_DIALECTS = ["header", "log"]

CRLF_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="location-crlf-smuggle",
        template="Location: {INPUT}",
        payload="x\r\nSet-Cookie: y",
        note="CRLF response splitting in a Location header.",
        divergent=False,
    ),
    CorpusCase(
        id="location-lf-smuggle",
        template="Location: {INPUT}",
        payload="x\nSet-Cookie: y",
        note="LF-only smuggling in a Location header.",
        divergent=False,
    ),
    CorpusCase(
        id="header-crlf-smuggle",
        template="Header: {INPUT}",
        payload="value\r\nInjected: yes",
        note="Inject a second header line via CRLF.",
        divergent=False,
    ),
    CorpusCase(
        id="header-lf-smuggle",
        template="Header: {INPUT}",
        payload="value\nInjected: yes",
        note="Inject a second header line via bare LF.",
        divergent=False,
    ),
    CorpusCase(
        id="log-crlf-smuggle",
        template="Log: {INPUT}",
        payload="line\r\nFAKE",
        note="Forge a new log record with CRLF.",
        divergent=False,
    ),
    CorpusCase(
        id="log-lf-smuggle",
        template="Log: {INPUT}",
        payload="line\nFAKE",
        note="Forge a new log record with LF.",
        divergent=False,
    ),
    CorpusCase(
        id="cookie-crlf-smuggle",
        template="Set-Cookie: session={INPUT}",
        payload="abc\r\nSet-Cookie: admin=1",
        note="Smuggle an extra Set-Cookie header.",
        divergent=False,
    ),
    CorpusCase(
        id="double-crlf-body",
        template="Header: {INPUT}",
        payload="x\r\n\r\nbody",
        note="Terminate headers early and start a response body.",
        divergent=False,
    ),
    CorpusCase(
        id="header-normal",
        template="Header: {INPUT}",
        payload="normal",
        note="Benign header value with no line breaks.",
        divergent=False,
    ),
    CorpusCase(
        id="log-normal",
        template="Log: {INPUT}",
        payload="user login ok",
        note="Benign log line with no smuggling.",
        divergent=False,
    ),
)
