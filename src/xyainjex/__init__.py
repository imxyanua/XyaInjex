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
from .mcp import McpAnalysis, McpFinding, analyze_mcp
from .analyzer import analyze
from .argument import analyze_argument, mutate_argument
from .build import BUILD_LANGS, BuildResult, build
from .code import analyze_code, mutate_code, parse_code_lang
from .crlf import analyze_crlf, mutate_crlf, parse_crlf_kind
from .csv import analyze_csv, mutate_csv
from .deserialize import analyze_deserialize, mutate_deserialize
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .el import analyze_el, mutate_el
from .corpus import BenchmarkResult, benchmark
from .encode import EncodeResult, encode
from .fuzz import DifferentialResult, ExploitPath, FuzzResult, differential, fuzz
from .graphql import analyze_graphql, mutate_graphql
from .host import analyze_host, mutate_host
from .ldap import analyze_ldap, mutate_ldap
from .llm import (
    LLMProvider,
    MockProvider,
    SuggestResult,
    explain,
    get_provider,
    suggest_payloads,
)
from .mail import analyze_mail, mutate_mail
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
from .orm import analyze_orm, mutate_orm
from .path import analyze_path, mutate_path
from .prompt import (
    PromptAnalysis,
    PromptFinding,
    PromptThreat,
    analyze_prompt,
    detect_hidden,
)
from .prototype import analyze_prototype, mutate_prototype
from .redis import analyze_redis, mutate_redis
from .shell.breakout import render
from .sql import analyze_sql, mutate_sql
from .ssi import analyze_ssi, mutate_ssi
from .ssrf import analyze_ssrf, mutate_ssrf
from .template import analyze_template, mutate_template
from .xml import analyze_xml, mutate_xml
from .xpath import analyze_xpath, mutate_xpath
from .xss import analyze_xss, mutate_xss
from .xxe import analyze_xxe, mutate_xxe
from .yaml import analyze_yaml, mutate_yaml

__version__ = "0.11.0"

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
    "analyze_el",
    "analyze_csv",
    "analyze_ssi",
    "analyze_ssrf",
    "analyze_path",
    "analyze_mail",
    "analyze_xss",
    "analyze_xxe",
    "analyze_prototype",
    "analyze_argument",
    "analyze_deserialize",
    "analyze_orm",
    "analyze_host",
    "analyze_redis",
    "analyze_prompt",
    "analyze_agent",
    "analyze_flow",
    "analyze_mcp",
    "detect_hidden",
    "parse_source",
    "AgentSource",
    "AgentThreat",
    "AgentAnalysis",
    "AgentFinding",
    "McpAnalysis",
    "McpFinding",
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
    "mutate_el",
    "mutate_csv",
    "mutate_ssi",
    "mutate_ssrf",
    "mutate_path",
    "mutate_mail",
    "mutate_xss",
    "mutate_xxe",
    "mutate_prototype",
    "mutate_argument",
    "mutate_deserialize",
    "mutate_orm",
    "mutate_host",
    "mutate_redis",
    "parse_code_lang",
    "parse_crlf_kind",
    "CodeLang",
    "CrlfKind",
    "fuzz",
    "differential",
    "benchmark",
    "BenchmarkResult",
    "build",
    "BuildResult",
    "BUILD_LANGS",
    "encode",
    "EncodeResult",
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
