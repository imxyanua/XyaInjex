"""Detect an insecure-deserialization payload across common runtimes."""

from __future__ import annotations

import base64
import binascii
import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template

# --- byte-level format markers ---
_JAVA_MAGIC = b"\xac\xed\x00\x05"
_DOTNET_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
_PICKLE_PROTO = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")

# --- text markers (present without decoding) ---
_JAVA_B64 = re.compile(r"rO0AB[A-Za-z0-9+/]")
_DOTNET_B64 = re.compile(r"AAEAAAD/////")
_RUBY_B64 = re.compile(r"^\s*BAg[A-Za-z0-9+/]")
_PHP_OBJECT = re.compile(r'O:\d+:"[^"]+":\d+:\{')
_PHP_DATA = re.compile(r'(?:^|;)\s*(?:a:\d+:\{|s:\d+:")')
_PICKLE_TEXT = re.compile(r"c(?:os|posix|nt|__builtin__|builtins|subprocess)\b")

# --- gadget / RCE markers ---
_GADGET = re.compile(
    r"CommonsCollections|InvokerTransformer|TemplatesImpl|ObjectDataProvider|"
    r"TypeConfuseDelegate|__destruct|__wakeup|__reduce__|"
    r"\b(?:system|exec|passthru|popen|subprocess|Runtime|Process)\b",
    re.IGNORECASE,
)


def _decoded_forms(payload: str) -> list[bytes]:
    """Return candidate byte forms: raw, plus base64 / hex decodings."""
    forms = [payload.encode("utf-8", "ignore")]
    stripped = payload.strip()
    if len(stripped) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped):
        try:
            forms.append(base64.b64decode(stripped, validate=False))
        except (binascii.Error, ValueError):
            pass
    if len(stripped) >= 8 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", stripped):
        hexs = stripped[2:] if stripped.startswith("0x") else stripped
        if len(hexs) % 2 == 0:
            try:
                forms.append(bytes.fromhex(hexs))
            except ValueError:
                pass
    return forms


def detect_deserialize_breakout(template: str, payload: str) -> Breakout:
    """Analyze the deserialization payload in ``payload``.

    ``command_injected`` means the payload is a serialized *object* that the
    target runtime would instantiate (Java / PHP object / Python pickle / .NET /
    Ruby), as opposed to plain serialized scalar data.
    """
    prefix = split_template(template).prefix
    forms = _decoded_forms(payload)

    tokens: set[str] = set()
    encoded = False

    # Byte markers over the decoded forms (index 0 is the raw payload bytes).
    for i, data in enumerate(forms):
        matched = False
        if data.startswith(_JAVA_MAGIC):
            tokens.add("java")
            matched = True
        if data.startswith(_DOTNET_MAGIC):
            tokens.add("dotnet")
            matched = True
        # A pickle both opens with a protocol opcode and ends with STOP ('.').
        if data[:2] in _PICKLE_PROTO and data.rstrip(b"\n ").endswith(b"."):
            tokens.add("python-pickle")
            matched = True
        if matched and i > 0:
            encoded = True

    # Text markers on the raw payload.
    if _JAVA_B64.search(payload):
        tokens.add("java")
        encoded = True
    if _DOTNET_B64.search(payload):
        tokens.add("dotnet")
        encoded = True
    if _RUBY_B64.search(payload):
        tokens.add("ruby")
        encoded = True
    if _PHP_OBJECT.search(payload):
        tokens.add("php-object")
    elif _PHP_DATA.search(payload):
        tokens.add("php-data")
    # Protocol-0 pickle is ASCII: a c<module> global plus a REDUCE / STOP.
    pickle_end = "R" in payload or payload.rstrip().endswith(".")
    if _PICKLE_TEXT.search(payload) and pickle_end:
        tokens.add("python-pickle")

    gadget = bool(_GADGET.search(payload))
    if not gadget:
        for data in forms[1:]:
            if _GADGET.search(data.decode("latin-1", "ignore")):
                gadget = True
                break
    if gadget and tokens:
        tokens.add("gadget")
    if encoded:
        tokens.add("encoded")

    object_formats = tokens & {"java", "php-object", "python-pickle", "dotnet", "ruby"}
    command_injected = bool(object_formats)

    context = Context.DESERIALIZE_ENCODED if encoded else Context.DESERIALIZE_RAW
    index = len(prefix) if command_injected or "php-data" in tokens else None

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=len(object_formats),
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "gadget",
    "java",
    "python-pickle",
    "php-object",
    "dotnet",
    "ruby",
    "php-data",
    "encoded",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_deserialize_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map a deserialization breakout to a risk rating."""
    seps = set(breakout.separators)
    if "gadget" in seps:
        # A serialized object carrying a known RCE gadget.
        return Risk.CRITICAL
    if breakout.command_injected:
        # Untrusted object deserialization is dangerous even without a known
        # gadget (the runtime instantiates attacker-chosen types).
        return Risk.HIGH
    if "php-data" in seps:
        # Serialized scalar / array data, but no object instantiation.
        return Risk.MEDIUM
    return Risk.LOW
