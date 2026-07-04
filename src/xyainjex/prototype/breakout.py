"""Detect prototype-pollution breakout in an injected payload."""

from __future__ import annotations

import re

from ..models import Breakout, Risk
from ..shell.context import split_template
from .context import analyze_prototype_context

_KEYS = r"__proto__|constructor|prototype"

# A dangerous key as a JSON key:  "__proto__":
_JSON_KEY = re.compile(r'"(' + _KEYS + r')"\s*:', re.IGNORECASE)
# ... with an object value, which actually adds inherited properties.
_JSON_NESTED = re.compile(r'"(?:' + _KEYS + r')"\s*:\s*\{', re.IGNORECASE)

# A dangerous key as a path segment:  [__proto__]  or  .__proto__  or leading.
_PATH_KEY = re.compile(
    r'\[\s*["\']?(' + _KEYS + r')["\']?\s*\]'
    r"|(?:^|\.)(" + _KEYS + r")(?=$|[.\[=])",
    re.IGNORECASE,
)
# ... followed by a further accessor (so a property is set under it). A bracket
# key needs a following [ or . (a trailing = would only replace the proto ref);
# a bare leading key needs a following [ or . then a real segment character.
_PATH_NESTED = re.compile(
    r'\[\s*["\']?(?:' + _KEYS + r')["\']?\s*\]\s*(?:\[|\.)'
    r"|(?:^|\.)(?:" + _KEYS + r")\s*(?:\[|\.)[^=\s]",
    re.IGNORECASE,
)

# Property names commonly abused as RCE gadgets once the prototype is polluted.
_GADGET = re.compile(
    r"\b(NODE_OPTIONS|execArgv|argv0|sourceURL|contextExtensions|shell)\b",
    re.IGNORECASE,
)


def detect_prototype_breakout(template: str, payload: str) -> Breakout:
    """Analyze the prototype-pollution breakout produced by injecting ``payload``.

    ``command_injected`` means the payload sets a property on ``Object.prototype``
    (a dangerous key with a nested property), not merely names the key.
    """
    context = analyze_prototype_context(template)
    prefix = split_template(template).prefix

    tokens: set[str] = set()

    json_keys = {m.group(1).lower() for m in _JSON_KEY.finditer(payload)}
    path_keys = {
        (m.group(1) or m.group(2)).lower() for m in _PATH_KEY.finditer(payload)
    }
    all_keys = json_keys | path_keys
    for key in all_keys:
        tokens.add(
            {
                "__proto__": "proto-key",
                "constructor": "constructor-key",
                "prototype": "prototype-key",
            }[key]
        )
    if json_keys:
        tokens.add("json-vector")
    if path_keys:
        tokens.add("path-vector")

    json_pollution = bool(_JSON_NESTED.search(payload))
    path_pollution = bool(_PATH_NESTED.search(payload))
    pollution = json_pollution or path_pollution
    if pollution:
        tokens.add("pollution")

    gadget = pollution and bool(_GADGET.search(payload))
    if gadget:
        tokens.add("gadget")

    first = _JSON_KEY.search(payload) or _PATH_KEY.search(payload)
    index = len(prefix) + first.start() if first else None

    return Breakout(
        context=context,
        quote_closed=pollution,
        command_injected=pollution,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=1 if pollution else 0,
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "gadget",
    "pollution",
    "proto-key",
    "constructor-key",
    "prototype-key",
    "json-vector",
    "path-vector",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_prototype_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map a prototype-pollution breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        # A dangerous key is named but no property is set under it.
        if seps & {"proto-key", "constructor-key", "prototype-key"}:
            return Risk.MEDIUM
        return Risk.LOW
    if "gadget" in seps:
        # Pollutes a known RCE gadget property.
        return Risk.CRITICAL
    return Risk.HIGH
