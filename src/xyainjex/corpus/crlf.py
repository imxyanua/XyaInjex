"""CRLF / response-splitting parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

CRLF_DIALECTS = ["header", "log"]

CRLF_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="location-crlf-smuggle",
        template="Location: {INPUT}",
        payload="x\r\nSet-Cookie: y",
        note="CRLF smuggling is CRITICAL in headers but only HIGH in logs.",
        divergent=True,
        metric="risk",
    ),
    CorpusCase(
        id="location-lf-smuggle",
        template="Location: {INPUT}",
        payload="x\nSet-Cookie: y",
        note="LF-only smuggling injects uniformly; risk stays HIGH in both kinds.",
        divergent=False,
        metric="risk",
    ),
    CorpusCase(
        id="header-crlf-smuggle",
        template="Header: {INPUT}",
        payload="value\r\nInjected: yes",
        note="Inject a second header line via CRLF.",
        divergent=True,
        metric="risk",
    ),
    CorpusCase(
        id="header-lf-smuggle",
        template="Header: {INPUT}",
        payload="value\nInjected: yes",
        note="LF-only header smuggling; both kinds rate it HIGH.",
        divergent=False,
        metric="risk",
    ),
    CorpusCase(
        id="log-crlf-smuggle",
        template="Log: {INPUT}",
        payload="line\r\nFAKE",
        note="Forge a new log record with CRLF.",
        divergent=True,
        metric="risk",
    ),
    CorpusCase(
        id="log-lf-smuggle",
        template="Log: {INPUT}",
        payload="line\nFAKE",
        note="LF-only log forging; uniform HIGH risk.",
        divergent=False,
        metric="risk",
    ),
    CorpusCase(
        id="cookie-crlf-smuggle",
        template="Set-Cookie: session={INPUT}",
        payload="abc\r\nSet-Cookie: admin=1",
        note="Smuggle an extra Set-Cookie header.",
        divergent=True,
        metric="risk",
    ),
    CorpusCase(
        id="double-crlf-body",
        template="Header: {INPUT}",
        payload="x\r\n\r\nbody",
        note="Terminate headers early and start a response body.",
        divergent=True,
        metric="risk",
    ),
    CorpusCase(
        id="header-normal",
        template="Header: {INPUT}",
        payload="normal",
        note="Benign header value with no line breaks.",
        divergent=False,
        metric="risk",
    ),
    CorpusCase(
        id="log-normal",
        template="Log: {INPUT}",
        payload="user login ok",
        note="Benign log line with no smuggling.",
        divergent=False,
        metric="risk",
    ),
)
