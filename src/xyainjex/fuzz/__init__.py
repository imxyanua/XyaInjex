"""Differential fuzzing and automated exploit-path discovery.

Builds on the deterministic analyzers: it expands seed payloads with obfuscation
mutators, runs every variant through the analyzer, and reports which ones still
achieve a breakout. The analyzer is the source of truth, so results reflect what
the lexical model actually accepts rather than a guess.
"""

from .engine import (
    _DIALECT_LANGS,
    _FUZZ_LANGS,
    DifferentialResult,
    ExploitPath,
    FuzzResult,
    differential,
    fuzz,
)

# Public tuples of the languages each engine feature supports.
FUZZ_LANGS = _FUZZ_LANGS
DIFFERENTIAL_LANGS = _DIALECT_LANGS

__all__ = [
    "fuzz",
    "differential",
    "FuzzResult",
    "ExploitPath",
    "DifferentialResult",
    "FUZZ_LANGS",
    "DIFFERENTIAL_LANGS",
]
