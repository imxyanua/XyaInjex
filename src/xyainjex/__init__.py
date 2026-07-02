"""XyaInjex: real-time injection context and breakout analyzer."""

from __future__ import annotations

from .analyzer import analyze
from .dialects import parse_dialect
from .models import (
    AnalysisResult,
    Balance,
    Breakout,
    Context,
    Dialect,
    Risk,
)
from .mutation import mutate
from .shell.breakout import render

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "mutate",
    "render",
    "parse_dialect",
    "AnalysisResult",
    "Balance",
    "Breakout",
    "Context",
    "Dialect",
    "Risk",
    "__version__",
]
