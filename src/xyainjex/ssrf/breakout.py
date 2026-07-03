"""Detect how a payload redirects a server-side request (SSRF)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ..models import Breakout, Context, Risk
from ..shell.breakout import render
from ..shell.context import split_template
from .context import analyze_ssrf_context

# Schemes that smuggle other protocols (Redis, memcached, ...) -> often RCE.
_RCE_SCHEMES = {"gopher", "dict"}
# Schemes that read local files.
_FILE_SCHEMES = {"file", "netdoc"}
# Other schemes a fetcher should never follow.
_OTHER_SCHEMES = {"ftp", "ldap", "ldaps", "tftp", "jar", "phar", "expect", "data"}
_DANGEROUS_SCHEMES = _RCE_SCHEMES | _FILE_SCHEMES | _OTHER_SCHEMES

# Cloud metadata endpoints (AWS/GCP/Azure link-local, Alibaba, GCP hostname).
_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
}
_METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


def _resolve_ip(host: str) -> tuple[ipaddress._BaseAddress | None, bool]:
    """Return (ip, obfuscated) for ``host`` or (None, False) if not an IP.

    Handles the dotted quad, bracketed IPv6, and the obfuscated decimal / hex /
    octal encodings SSRF payloads use to slip an internal address past a filter.
    """
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h), False
    except ValueError:
        pass

    # A single integer: decimal (2130706433), hex (0x7f000001), or octal.
    n: int | None = None
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
        n = int(h, 16)
    elif re.fullmatch(r"0[0-7]+", h):
        n = int(h, 8)
    elif re.fullmatch(r"\d+", h):
        n = int(h)
    if n is not None and 0 <= n <= 0xFFFFFFFF:
        return ipaddress.ip_address(n), True

    # Dotted quad whose parts may be hex or octal (0x7f.0.0.1, 0177.0.0.1).
    parts = h.split(".")
    if len(parts) == 4 and all(parts):
        vals: list[int] = []
        obf = False
        for p in parts:
            try:
                if re.fullmatch(r"0[xX][0-9a-fA-F]+", p):
                    v = int(p, 16)
                    obf = True
                elif re.fullmatch(r"0[0-7]+", p):
                    v = int(p, 8)
                    obf = True
                elif re.fullmatch(r"\d+", p):
                    v = int(p)
                else:
                    return None, False
            except ValueError:
                return None, False
            vals.append(v)
        if all(0 <= v <= 255 for v in vals):
            packed = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]
            return ipaddress.ip_address(packed), obf
    return None, False


def _classify_host(host: str) -> set[str]:
    """Return risk tokens describing where ``host`` points."""
    tokens: set[str] = set()
    if not host:
        return tokens
    low = host.lower().strip("[]")

    if low in _METADATA_HOSTS or low in _METADATA_IPS:
        tokens.add("metadata")
    if low == "localhost":
        tokens.add("loopback")

    ip, obfuscated = _resolve_ip(host)
    if ip is not None:
        if obfuscated:
            tokens.add("obfuscated-ip")
        if str(ip) in _METADATA_IPS:
            tokens.add("metadata")
        elif ip.is_loopback:
            tokens.add("loopback")
        elif ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            tokens.add("private-ip")
    return tokens


def detect_ssrf_breakout(template: str, payload: str) -> Breakout:
    """Analyze the SSRF breakout produced by injecting ``payload``.

    ``command_injected`` means the payload steers the server's request to a
    target it did not intend: an internal or metadata host, a dangerous scheme,
    an ``@`` authority override, or a protocol-relative / absolute URL.
    """
    context = analyze_ssrf_context(template)
    prefix = split_template(template).prefix

    if context in (Context.SSRF_URL, Context.SSRF_QUERY):
        target = payload.strip()
    else:  # SSRF_HOST, SSRF_PATH
        target = render(template, payload)

    sp = urlsplit(target)
    scheme = sp.scheme.lower()
    host = sp.hostname or ""
    netloc = sp.netloc

    tokens: set[str] = set()

    protocol_relative = target.startswith("//")
    absolute = bool(scheme and host)

    if scheme in _DANGEROUS_SCHEMES:
        tokens.add(scheme)
        tokens.add("scheme-change")
    elif absolute and scheme not in ("http", "https"):
        tokens.add("scheme-change")

    if "@" in netloc:
        tokens.add("userinfo-override")
        if re.search(r"[^@/]:[^@/]*@", netloc):
            tokens.add("credentials")

    if sp.port is not None and sp.port not in (80, 443):
        tokens.add("port")

    tokens |= _classify_host(host)

    # Decide whether the request target was redirected.
    reached_internal = bool(tokens & {"metadata", "loopback", "private-ip"})
    dangerous_scheme = bool(tokens & {"scheme-change"}) or scheme in _DANGEROUS_SCHEMES

    if context in (Context.SSRF_URL, Context.SSRF_QUERY):
        # The payload itself is fetched: an absolute or protocol-relative URL
        # points the request at an attacker-chosen host.
        if absolute:
            tokens.add("absolute-url")
        if protocol_relative:
            tokens.add("protocol-relative")
        command_injected = bool(
            absolute or protocol_relative or dangerous_scheme or reached_internal
        )
    else:  # SSRF_HOST, SSRF_PATH
        if context == Context.SSRF_HOST:
            tokens.add("host-controlled")
        command_injected = bool(
            host
            and (
                context == Context.SSRF_HOST
                or reached_internal
                or dangerous_scheme
                or "userinfo-override" in tokens
            )
        )

    ordered = _order_tokens(tokens)
    index = len(prefix) if command_injected else None

    return Breakout(
        context=context,
        quote_closed="userinfo-override" in tokens or protocol_relative,
        command_injected=command_injected,
        comment_terminated=False,
        separators=ordered,
        commands_created=1 if command_injected else 0,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "metadata",
    "gopher",
    "dict",
    "file",
    "netdoc",
    "scheme-change",
    "loopback",
    "private-ip",
    "userinfo-override",
    "credentials",
    "protocol-relative",
    "obfuscated-ip",
    "absolute-url",
    "host-controlled",
    "port",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_ssrf_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map an SSRF breakout to a risk rating."""
    seps = set(breakout.separators)
    if "metadata" in seps:
        # Cloud metadata: credential theft, full account takeover.
        return Risk.CRITICAL
    if seps & _RCE_SCHEMES:
        # gopher:// / dict:// smuggle a second protocol (Redis, ...) -> RCE.
        return Risk.CRITICAL
    if seps & (_FILE_SCHEMES | {"loopback", "private-ip", "userinfo-override"}):
        # Local file read, an internal host, or an allowlist bypass.
        return Risk.HIGH
    if not breakout.command_injected:
        return Risk.LOW
    if seps & (_OTHER_SCHEMES | {"scheme-change", "absolute-url", "protocol-relative"}):
        return Risk.MEDIUM
    if seps & {"host-controlled", "port", "obfuscated-ip"}:
        return Risk.MEDIUM
    return Risk.LOW
