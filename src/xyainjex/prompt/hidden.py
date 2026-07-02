"""Detect hidden or obfuscated content used to smuggle prompt instructions."""

from __future__ import annotations

import base64
import re

from ..models import Risk
from .threats import PromptFinding, PromptThreat

# Invisible or zero-width characters commonly used to hide text.
_ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "­": "SOFT HYPHEN",
}

# Bidirectional control characters that can reorder displayed text.
_BIDI = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

# Common Cyrillic/Greek homoglyphs of ASCII Latin letters.
_HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ο": "O",
}

_TAG_START = 0xE0000
_TAG_END = 0xE007F

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_SUSPICIOUS = re.compile(
    r"ignore|disregard|system|instruction|prompt|password|secret|exfiltrat",
    re.IGNORECASE,
)

# Hidden HTML: comments, and elements styled to be invisible.
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_HIDDEN_RE = re.compile(
    r"""(display\s*:\s*none|visibility\s*:\s*hidden
        |font-size\s*:\s*0|color\s*:\s*#?fff(fff)?\b
        |opacity\s*:\s*0|\bhidden\b)""",
    re.IGNORECASE | re.VERBOSE,
)


def _decode_tag_chars(text: str) -> str:
    out = []
    for ch in text:
        cp = ord(ch)
        if _TAG_START <= cp <= _TAG_END:
            out.append(chr(cp - _TAG_START))
    return "".join(out)


def detect_hidden(text: str) -> list[PromptFinding]:
    """Return findings for hidden or obfuscated content in ``text``."""
    findings: list[PromptFinding] = []

    # Zero-width / invisible characters.
    zw = [(i, ch) for i, ch in enumerate(text) if ch in _ZERO_WIDTH]
    if zw:
        names = ", ".join(sorted({_ZERO_WIDTH[ch] for _, ch in zw}))
        findings.append(
            PromptFinding(
                threat=PromptThreat.HIDDEN_ZERO_WIDTH,
                severity=Risk.MEDIUM,
                title="Zero-width or invisible characters",
                evidence=f"{len(zw)} character(s): {names}",
                start=zw[0][0],
                end=zw[-1][0] + 1,
            )
        )

    # Unicode Tags block (invisible, decodes to ASCII).
    tag_positions = [
        i for i, ch in enumerate(text) if _TAG_START <= ord(ch) <= _TAG_END
    ]
    if tag_positions:
        decoded = _decode_tag_chars(text)
        findings.append(
            PromptFinding(
                threat=PromptThreat.HIDDEN_UNICODE_TAGS,
                severity=Risk.HIGH,
                title="Hidden text in Unicode Tags block",
                evidence=f"decodes to: {decoded!r}",
                start=tag_positions[0],
                end=tag_positions[-1] + 1,
            )
        )

    # Bidirectional overrides.
    bidi = [(i, ch) for i, ch in enumerate(text) if ch in _BIDI]
    if bidi:
        names = ", ".join(sorted({_BIDI[ch] for _, ch in bidi}))
        findings.append(
            PromptFinding(
                threat=PromptThreat.BIDI_OVERRIDE,
                severity=Risk.MEDIUM,
                title="Bidirectional control characters",
                evidence=f"{len(bidi)} character(s): {names}",
                start=bidi[0][0],
                end=bidi[-1][0] + 1,
            )
        )

    # Homoglyphs.
    homo = [(i, ch) for i, ch in enumerate(text) if ch in _HOMOGLYPHS]
    if homo:
        sample = ", ".join(sorted({f"{ch!r}->{_HOMOGLYPHS[ch]}" for _, ch in homo}))
        findings.append(
            PromptFinding(
                threat=PromptThreat.HOMOGLYPH,
                severity=Risk.LOW,
                title="Homoglyph characters mimicking ASCII letters",
                evidence=f"{len(homo)} character(s): {sample}",
                start=homo[0][0],
                end=homo[-1][0] + 1,
            )
        )

    # Base64 blobs that decode to readable text.
    for match in _BASE64_RE.finditer(text):
        decoded = _try_base64(match.group())
        if decoded is None:
            continue
        severity = Risk.HIGH if _SUSPICIOUS.search(decoded) else Risk.MEDIUM
        findings.append(
            PromptFinding(
                threat=PromptThreat.ENCODED_PAYLOAD,
                severity=severity,
                title="Base64 encoded text",
                evidence=f"decodes to: {decoded[:80]!r}",
                start=match.start(),
                end=match.end(),
            )
        )

    # Hidden HTML.
    html_hit = _HTML_COMMENT_RE.search(text) or _HTML_HIDDEN_RE.search(text)
    if html_hit:
        findings.append(
            PromptFinding(
                threat=PromptThreat.HIDDEN_HTML,
                severity=Risk.MEDIUM,
                title="Hidden HTML content",
                evidence=html_hit.group()[:80],
                start=html_hit.start(),
                end=html_hit.end(),
            )
        )

    return findings


def _try_base64(token: str) -> str | None:
    if len(token) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(token, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Require mostly printable text with at least one space or letter run,
    # so random hashes are not reported as hidden messages.
    printable = sum(c.isprintable() for c in decoded)
    if not decoded or printable / len(decoded) < 0.9:
        return None
    if not re.search(r"[A-Za-z]{3,}", decoded):
        return None
    return decoded
