"""XyaInjex: real-time injection context and breakout analyzer."""

from __future__ import annotations

from .analyzer import analyze
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .models import (
    AnalysisResult,
    Balance,
    Breakout,
    Context,
    Dialect,
    Risk,
    SqlDialect,
    TemplateEngine,
)
from .mutation import mutate
from .shell.breakout import render
from .sql import analyze_sql, mutate_sql
from .template import analyze_template, mutate_template

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "analyze_sql",
    "analyze_template",
    "mutate",
    "mutate_sql",
    "mutate_template",
    "render",
    "parse_dialect",
    "parse_sql_dialect",
    "parse_template_engine",
    "AnalysisResult",
    "Balance",
    "Breakout",
    "Context",
    "Dialect",
    "SqlDialect",
    "TemplateEngine",
    "Risk",
    "__version__",
]
