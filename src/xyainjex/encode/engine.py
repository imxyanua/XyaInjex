"""Payload encoder: emit filter / WAF evasion variants of a working payload.

The transforms come from the fuzzing mutators (case folding, whitespace swaps,
percent encoding, SQL inline comments). When a template is supplied, each variant
is validated by the analyzer, so the result shows which encodings still break out
of the real context rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..dispatch import BREAKOUT_LANGS, analyze_lang
from ..fuzz.mutators import (
    case_variants,
    encoding_variants,
    sql_whitespace_variants,
    whitespace_variants,
)


@dataclass
class EncodeVariant:
    payload: str
    strategy: str
    validated: bool | None  # None when no template was given to validate against
    risk: str | None

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "strategy": self.strategy,
            "validated": self.validated,
            "risk": self.risk,
        }


@dataclass
class EncodeResult:
    payload: str
    lang: str
    dialect: str | None
    template: str | None
    total: int
    surviving: int
    variants: list[EncodeVariant] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "lang": self.lang,
            "dialect": self.dialect,
            "template": self.template,
            "total": self.total,
            "surviving": self.surviving,
            "variants": [v.to_dict() for v in self.variants],
        }


def _build_variants(payload: str, lang: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = [(payload, "original")]
    seen = {payload}
    funcs = [case_variants, whitespace_variants, encoding_variants]
    if lang == "sql":
        funcs.insert(2, sql_whitespace_variants)
    for func in funcs:
        for variant, strategy in func(payload):
            if variant not in seen:
                seen.add(variant)
                out.append((variant, strategy))
    return out


def encode(
    payload: str,
    lang: str = "shell",
    template: str | None = None,
    dialect: str | None = None,
) -> EncodeResult:
    """Return filter-evasion encodings of ``payload``.

    When ``template`` is given, each variant is analyzed and marked with whether
    it still breaks out (``validated``) and its risk.
    """
    lang = lang.strip().lower()
    if lang not in BREAKOUT_LANGS:
        raise ValueError(
            "encode supports: " + ", ".join(BREAKOUT_LANGS) + f", not {lang!r}"
        )

    raw = _build_variants(payload, lang)
    variants: list[EncodeVariant] = []
    surviving = 0
    for variant, strategy in raw:
        if template is not None:
            result = analyze_lang(template, variant, lang, dialect)
            b = result.breakout
            injects = b.command_injected or b.substitution_injected
            if injects:
                surviving += 1
            variants.append(
                EncodeVariant(variant, strategy, injects, result.risk.value)
            )
        else:
            variants.append(EncodeVariant(variant, strategy, None, None))

    if template is None:
        surviving = len(variants)

    return EncodeResult(
        payload=payload,
        lang=lang,
        dialect=dialect,
        template=template,
        total=len(variants),
        surviving=surviving,
        variants=variants,
    )
