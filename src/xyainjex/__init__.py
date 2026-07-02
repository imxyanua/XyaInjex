"""XyaInjex: real-time injection context and breakout analyzer."""

from __future__ import annotations

from .analyzer import analyze
from .dialects import parse_dialect, parse_sql_dialect
from .models import (
    AnalysisResult,
    Balance,
    Breakout,
    Context,
    Dialect,
    Risk,
    SqlDialect,
)
from .mutation import mutate
from .shell.breakout import render
from .sql import analyze_sql, mutate_sql

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "analyze_sql",
    "mutate",
    "mutate_sql",
    "render",
    "parse_dialect",
    "parse_sql_dialect",
    "AnalysisResult",
    "Balance",
    "Breakout",
    "Context",
    "Dialect",
    "SqlDialect",
    "Risk",
    "__version__",
]
