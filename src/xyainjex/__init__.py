"""XyaInjex: real-time injection context and breakout analyzer."""

from __future__ import annotations

from .agent import (
    AgentAnalysis,
    AgentFinding,
    AgentSource,
    AgentThreat,
    analyze_agent,
    analyze_flow,
    parse_source,
)
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
from .prompt import (
    PromptAnalysis,
    PromptFinding,
    PromptThreat,
    analyze_prompt,
    detect_hidden,
)
from .shell.breakout import render
from .sql import analyze_sql, mutate_sql
from .template import analyze_template, mutate_template

__version__ = "0.1.0"

__all__ = [
    "analyze",
    "analyze_sql",
    "analyze_template",
    "analyze_prompt",
    "analyze_agent",
    "analyze_flow",
    "detect_hidden",
    "parse_source",
    "AgentSource",
    "AgentThreat",
    "AgentAnalysis",
    "AgentFinding",
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
    "PromptAnalysis",
    "PromptFinding",
    "PromptThreat",
    "Risk",
    "__version__",
]
