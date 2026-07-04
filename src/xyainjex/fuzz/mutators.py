"""Deterministic payload obfuscation mutators.

Each mutator takes a base payload and returns zero or more variants tagged with
the strategy name. Mutators are deterministic so fuzzing runs are reproducible.
The set is chosen so that some transformations preserve the injection under a
lexical analyzer (case, whitespace, inline comments) while others typically do
not (percent encoding), which makes the differential between them informative.
"""

from __future__ import annotations

from urllib.parse import quote

Variant = tuple[str, str]  # (payload, strategy)


def _alternating(payload: str) -> str:
    out = []
    upper = True
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def case_variants(payload: str) -> list[Variant]:
    """Case transformations, effective against case-insensitive keywords."""
    variants = {
        payload.upper(): "case-upper",
        payload.lower(): "case-lower",
        _alternating(payload): "case-alternating",
    }
    return [(p, s) for p, s in variants.items() if p != payload]


def whitespace_variants(payload: str) -> list[Variant]:
    """Swap ASCII spaces for other separators."""
    if " " not in payload:
        return []
    out: list[Variant] = [(payload.replace(" ", "\t"), "whitespace-tab")]
    return out


def sql_whitespace_variants(payload: str) -> list[Variant]:
    """SQL inline comments used as whitespace between tokens."""
    if " " not in payload:
        return []
    return [(payload.replace(" ", "/**/"), "sql-inline-comment")]


def encoding_variants(payload: str) -> list[Variant]:
    """Percent encoding variants (usually inert against a shell/SQL lexer)."""
    once = quote(payload, safe="")
    twice = quote(once, safe="")
    out: list[Variant] = []
    if once != payload:
        out.append((once, "url-encode"))
    if twice != once:
        out.append((twice, "url-encode-double"))
    return out


_MUTATORS = {
    "shell": [case_variants, whitespace_variants, encoding_variants],
    "sql": [
        case_variants,
        whitespace_variants,
        sql_whitespace_variants,
        encoding_variants,
    ],
    "template": [case_variants, whitespace_variants, encoding_variants],
    "code": [case_variants, whitespace_variants, encoding_variants],
    # HTML tags and attributes are case-insensitive, so case survives.
    "xss": [case_variants],
    # URL schemes and hosts are case-insensitive.
    "ssrf": [case_variants],
    # The path analyzer decodes percent-encoding, so encoded traversal survives.
    "path": [encoding_variants],
    # SQL-style keyword contexts (XPath / LDAP / EL) accept case folding.
    "xpath": [case_variants],
    "ldap": [case_variants],
    "el": [case_variants],
}


def expand(payload: str, lang: str) -> list[Variant]:
    """Return the seed plus all mutator variants for ``lang``."""
    out: list[Variant] = [(payload, "seed")]
    seen = {payload}
    for mutator in _MUTATORS.get(lang, []):
        for variant, strategy in mutator(payload):
            if variant not in seen:
                seen.add(variant)
                out.append((variant, strategy))
    return out
