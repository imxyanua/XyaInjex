"""Detect XXE (XML external entity) breakout in an injected XML payload."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_xxe_context

_DOCTYPE = re.compile(r"<!DOCTYPE\b", re.IGNORECASE)
# <!DOCTYPE root SYSTEM "http://..."> — an external DTD subset.
_DOCTYPE_EXTERNAL = re.compile(
    r"<!DOCTYPE\s+\S+\s+(?:SYSTEM|PUBLIC)\b[^>]*?[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
# <!ENTITY [%] name SYSTEM|PUBLIC ... "uri">  (external general / parameter)
_ENTITY_EXTERNAL = re.compile(
    r"<!ENTITY\s+(%\s*)?\w+\s+(?:SYSTEM|PUBLIC)\b[^>]*?[\"']([^\"']+)[\"']",
    re.IGNORECASE | re.DOTALL,
)
# <!ENTITY [%] name "value">  (internal)
_ENTITY_INTERNAL = re.compile(
    r"<!ENTITY\s+(%\s*)?\w+\s+[\"'](.*?)[\"']\s*>",
    re.IGNORECASE | re.DOTALL,
)
_ENTITY_REF = re.compile(r"[&%]\w+;")
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")

_WRAPPER_SCHEMES = {"php", "expect", "data", "jar", "netdoc"}
_REMOTE_SCHEMES = {"http", "https", "ftp", "ftps", "gopher"}


def _classify_uri(uri: str) -> str:
    """Return the risk kind for an entity/DTD URI."""
    m = _SCHEME.match(uri.strip())
    scheme = m.group(1).lower() if m else ""
    if scheme in _WRAPPER_SCHEMES:
        return "wrapper"
    if scheme in _REMOTE_SCHEMES:
        return "ssrf"
    # file:// or a bare path.
    return "file-read"


def detect_xxe_breakout(template: str, payload: str) -> Breakout:
    """Analyze the XXE breakout produced by injecting ``payload``.

    ``command_injected`` means the payload defines a DOCTYPE with an external (or
    parameter) entity in a position where the parser will process it.
    """
    context = analyze_xxe_context(template)
    prefix = split_template(template).prefix

    tokens: set[str] = set()

    has_doctype = bool(_DOCTYPE.search(payload))
    if has_doctype:
        tokens.add("doctype")

    external = list(_ENTITY_EXTERNAL.finditer(payload))
    parameter = any(m.group(1) for m in external)
    for m in external:
        tokens.add("external-entity")
        if m.group(1):
            tokens.add("parameter-entity")
        tokens.add(_classify_uri(m.group(2)))

    dtd_ext = _DOCTYPE_EXTERNAL.search(payload)
    if dtd_ext:
        tokens.add("external-dtd")
        tokens.add(_classify_uri(dtd_ext.group(1)))

    # A parameter entity that pulls an external DTD is the OOB exfiltration path.
    if parameter and ("ssrf" in tokens or "external-dtd" in tokens):
        tokens.add("oob")

    internal = list(_ENTITY_INTERNAL.finditer(payload))
    if internal:
        tokens.add("internal-entity")
    # Billion laughs: an internal entity whose value fans out into many refs.
    for m in internal:
        if len(_ENTITY_REF.findall(m.group(2))) >= 3:
            tokens.add("expansion")
            break

    if _ENTITY_REF.search(payload):
        tokens.add("entity-ref")

    external_present = bool(external) or bool(dtd_ext)
    if context == Context.XXE_DOCUMENT:
        command_injected = has_doctype and (external_present or "expansion" in tokens)
    else:
        # A DOCTYPE injected mid-document does not parse; only a reference to a
        # pre-declared entity could apply, which needs an existing DTD.
        command_injected = False

    index = len(prefix) + _DOCTYPE.search(payload).start() if has_doctype else None

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=len(external),
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "oob",
    "wrapper",
    "parameter-entity",
    "external-dtd",
    "ssrf",
    "file-read",
    "expansion",
    "external-entity",
    "internal-entity",
    "doctype",
    "entity-ref",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_xxe_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map an XXE breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        # Constructs are present but not in a position the parser will process.
        if seps & {"doctype", "external-entity", "external-dtd", "entity-ref"}:
            return Risk.MEDIUM
        return Risk.LOW
    if seps & {"oob", "wrapper", "parameter-entity"}:
        # Out-of-band exfiltration or a dangerous wrapper.
        return Risk.CRITICAL
    if seps & {"ssrf", "file-read", "expansion"}:
        # Arbitrary file read, internal request, or entity-expansion DoS.
        return Risk.HIGH
    return Risk.MEDIUM
