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
from .code import analyze_code, mutate_code, parse_code_lang
from .crlf import analyze_crlf, mutate_crlf, parse_crlf_kind
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .fuzz import DifferentialResult, ExploitPath, FuzzResult, differential, fuzz
from .graphql import analyze_graphql, mutate_graphql
from .ldap import analyze_ldap, mutate_ldap
from .llm import (
    LLMProvider,
    MockProvider,
    SuggestResult,
    explain,
    get_provider,
    suggest_payloads,
)
from .models import (
    AnalysisResult,
    Balance,
    Breakout,
    CodeLang,
    Context,
    CrlfKind,
    Dialect,
    Risk,
    SqlDialect,
    TemplateEngine,
)
from .mutation import mutate
from .nosql import analyze_nosql, mutate_nosql
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
from .xml import analyze_xml, mutate_xml
from .xpath import analyze_xpath, mutate_xpath
from .yaml import analyze_yaml, mutate_yaml

__version__ = "0.4.0"

__all__ = [
    "analyze",
    "analyze_sql",
    "analyze_template",
    "analyze_xpath",
    "analyze_ldap",
    "analyze_nosql",
    "analyze_code",
    "analyze_crlf",
    "analyze_xml",
    "analyze_yaml",
    "analyze_graphql",
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
    "mutate_xpath",
    "mutate_ldap",
    "mutate_nosql",
    "mutate_code",
    "mutate_crlf",
    "mutate_xml",
    "mutate_yaml",
    "mutate_graphql",
    "parse_code_lang",
    "parse_crlf_kind",
    "CodeLang",
    "CrlfKind",
    "fuzz",
    "differential",
    "FuzzResult",
    "ExploitPath",
    "DifferentialResult",
    "suggest_payloads",
    "explain",
    "get_provider",
    "LLMProvider",
    "MockProvider",
    "SuggestResult",
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
