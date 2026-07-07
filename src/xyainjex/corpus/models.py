"""Shared types for parser-divergence benchmark corpora."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorpusCase:
    id: str
    template: str
    payload: str
    note: str
    divergent: bool
