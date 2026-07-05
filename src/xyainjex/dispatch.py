"""Shared per-language analyze / seed dispatch.

Both the fuzzing engine and the LLM-assisted suggester need to run "analyze this
payload under this language" and "seed payloads from this language's mutation
engine" for any breakout analyzer. This module is the single source of truth for
that dispatch and for the lists of supported languages.
"""

from __future__ import annotations

from .analyzer import analyze
from .argument import analyze_argument, mutate_argument
from .code import analyze_code, mutate_code, parse_code_lang
from .crlf import analyze_crlf, mutate_crlf, parse_crlf_kind
from .csv import analyze_csv, mutate_csv
from .deserialize import analyze_deserialize, mutate_deserialize
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .el import analyze_el, mutate_el
from .graphql import analyze_graphql, mutate_graphql
from .host import analyze_host, mutate_host
from .ldap import analyze_ldap, mutate_ldap
from .mail import analyze_mail, mutate_mail
from .models import AnalysisResult
from .mutation import mutate
from .nosql import analyze_nosql, mutate_nosql
from .orm import analyze_orm, mutate_orm
from .path import analyze_path, mutate_path
from .prototype import analyze_prototype, mutate_prototype
from .sql import analyze_sql, mutate_sql
from .ssi import analyze_ssi, mutate_ssi
from .ssrf import analyze_ssrf, mutate_ssrf
from .template import analyze_template, mutate_template
from .xml import analyze_xml, mutate_xml
from .xpath import analyze_xpath, mutate_xpath
from .xss import analyze_xss, mutate_xss
from .xxe import analyze_xxe, mutate_xxe
from .yaml import analyze_yaml, mutate_yaml

# No-dialect analyzers: (analyze(template, payload), mutate(template)).
_SIMPLE = {
    "xpath": (analyze_xpath, mutate_xpath),
    "ldap": (analyze_ldap, mutate_ldap),
    "nosql": (analyze_nosql, mutate_nosql),
    "xml": (analyze_xml, mutate_xml),
    "yaml": (analyze_yaml, mutate_yaml),
    "graphql": (analyze_graphql, mutate_graphql),
    "el": (analyze_el, mutate_el),
    "csv": (analyze_csv, mutate_csv),
    "ssi": (analyze_ssi, mutate_ssi),
    "xss": (analyze_xss, mutate_xss),
    "ssrf": (analyze_ssrf, mutate_ssrf),
    "path": (analyze_path, mutate_path),
    "mail": (analyze_mail, mutate_mail),
    "xxe": (analyze_xxe, mutate_xxe),
    "prototype": (analyze_prototype, mutate_prototype),
    "argument": (analyze_argument, mutate_argument),
    "deserialize": (analyze_deserialize, mutate_deserialize),
    "orm": (analyze_orm, mutate_orm),
    "host": (analyze_host, mutate_host),
}

# Languages whose analyzer selects a dialect / kind (so they can be compared).
DIALECT_LANGS = ("shell", "sql", "template", "code", "crlf")

# Every language whose analyzer is breakout based and has a mutation engine.
BREAKOUT_LANGS = DIALECT_LANGS + tuple(_SIMPLE)


def analyze_lang(
    template: str, payload: str, lang: str, dialect: str | None
) -> AnalysisResult:
    """Analyze ``payload`` in ``template`` under ``lang`` and ``dialect``."""
    if lang == "sql":
        return analyze_sql(template, payload, parse_sql_dialect(dialect or "mysql"))
    if lang == "template":
        return analyze_template(
            template, payload, parse_template_engine(dialect or "jinja2")
        )
    if lang == "code":
        return analyze_code(template, payload, parse_code_lang(dialect or "python"))
    if lang == "crlf":
        return analyze_crlf(template, payload, parse_crlf_kind(dialect or "header"))
    if lang in _SIMPLE:
        return _SIMPLE[lang][0](template, payload)
    return analyze(template, payload, parse_dialect(dialect or "posix"))


def seed_payloads(
    template: str, lang: str, dialect: str | None = None, command: str = "id"
) -> list[str]:
    """Return seed payloads from ``lang``'s context-aware mutation engine."""
    if lang == "sql":
        result = mutate_sql(template, parse_sql_dialect(dialect or "mysql"))
    elif lang == "template":
        result = mutate_template(template, parse_template_engine(dialect or "jinja2"))
    elif lang == "code":
        result = mutate_code(template, parse_code_lang(dialect or "python"))
    elif lang == "crlf":
        result = mutate_crlf(template, parse_crlf_kind(dialect or "header"))
    elif lang in _SIMPLE:
        result = _SIMPLE[lang][1](template)
    else:
        result = mutate(
            template, command=command, dialect=parse_dialect(dialect or "posix")
        )
    return [c.payload for c in result.candidates]
