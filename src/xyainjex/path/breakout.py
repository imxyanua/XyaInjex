"""Detect how a payload escapes an intended filesystem path (traversal / LFI)."""

from __future__ import annotations

import re
from urllib.parse import unquote

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_path_context

# PHP / stream wrappers that turn a file read into source disclosure or RCE.
_RCE_WRAPPERS = ("php://input", "data:", "expect://", "phar://", "zip://")
_READ_WRAPPERS = ("php://filter", "file://", "netdoc://")
# Remote schemes: remote file inclusion / content fetch.
_REMOTE_SCHEMES = ("http", "https", "ftp", "ftps")

_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:[\\/]")

# Sensitive targets that confirm the intent of a traversal / LFI payload.
_SENSITIVE = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "win.ini",
    "boot.ini",
    "web.config",
    "wp-config.php",
    "id_rsa",
    "/.env",
)


def _decode_variants(payload: str) -> list[str]:
    """Return the raw payload plus URL-decoded forms (single and double)."""
    variants = [payload]
    once = unquote(payload)
    if once != payload:
        variants.append(once)
    twice = unquote(once)
    if twice != once:
        variants.append(twice)
    return variants


def _has_traversal(text: str) -> bool:
    norm = text.replace("\\", "/")
    if "../" in norm or norm.startswith("../") or norm.endswith("/.."):
        return True
    # A bare ".." segment between separators, or a trailing "/..".
    return bool(re.search(r"(^|/)\.\.(/|$)", norm))


def _is_absolute(text: str) -> bool:
    return (
        text.startswith("/")
        or text.startswith("\\")
        or bool(_WINDOWS_DRIVE.match(text))
    )


def detect_path_breakout(template: str, payload: str) -> Breakout:
    """Analyze the path-traversal breakout produced by injecting ``payload``.

    ``command_injected`` means the payload escapes the intended file or
    directory: a ``../`` traversal, an absolute path, or a wrapper / remote
    scheme.
    """
    context = analyze_path_context(template)
    prefix = split_template(template).prefix
    variants = _decode_variants(payload)
    low_variants = [v.lower() for v in variants]

    tokens: set[str] = set()

    traversal = any(_has_traversal(v) for v in variants)
    if traversal:
        tokens.add("traversal")
    # Percent-encoded traversal (evades a naive string filter).
    if re.search(r"%(25)?2e|%(25)?2f|%(25)?5c|%c0%af", payload, re.IGNORECASE):
        tokens.add("encoded")

    absolute = any(_is_absolute(v) for v in variants)
    if absolute:
        tokens.add("absolute")

    if "\x00" in payload or "%00" in payload or any("\x00" in v for v in variants):
        tokens.add("null-byte")

    # Scheme / wrapper detection over the decoded variants.
    scheme = ""
    for v in variants:
        m = _SCHEME.match(v.strip())
        if m:
            scheme = m.group(1).lower()
            break
    remote = scheme in _REMOTE_SCHEMES
    rce_wrapper = any(w in lv for lv in low_variants for w in _RCE_WRAPPERS)
    read_wrapper = any(w in lv for lv in low_variants for w in _READ_WRAPPERS)
    if remote:
        tokens.add("remote-scheme")
    if rce_wrapper:
        tokens.add("rce-wrapper")
    if read_wrapper:
        tokens.add("read-wrapper")

    if any(s in lv for lv in low_variants for s in _SENSITIVE):
        tokens.add("sensitive-file")

    # A null byte only matters as an extension bypass when a suffix follows.
    if "null-byte" in tokens and context == Context.PATH_EXT:
        tokens.add("extension-bypass")

    scheme_break = remote or rce_wrapper or read_wrapper

    if context == Context.PATH_FULL:
        # The input is the whole path: absolute, traversal, or a scheme all
        # reach an arbitrary or remote target. A plain relative name does not.
        command_injected = bool(absolute or traversal or scheme_break)
    else:  # PATH_BASE, PATH_EXT
        command_injected = bool(traversal or absolute or scheme_break)

    ordered = _order_tokens(tokens)
    index = len(prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed=absolute or traversal,
        command_injected=command_injected,
        comment_terminated="null-byte" in tokens,
        separators=ordered,
        commands_created=1 if command_injected else 0,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "rce-wrapper",
    "remote-scheme",
    "read-wrapper",
    "traversal",
    "absolute",
    "sensitive-file",
    "extension-bypass",
    "null-byte",
    "encoded",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_path_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a path-traversal breakout to a risk rating."""
    seps = set(breakout.separators)
    if seps & {"rce-wrapper", "remote-scheme"}:
        # Remote file inclusion or an RCE wrapper (php://input, expect://, ...).
        return Risk.CRITICAL
    if not breakout.command_injected:
        return Risk.LOW
    if seps & {"traversal", "absolute", "read-wrapper", "sensitive-file"}:
        # Arbitrary local file read (optionally past an extension check).
        return Risk.HIGH
    return Risk.MEDIUM
