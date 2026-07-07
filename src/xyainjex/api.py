"""Optional HTTP API exposing the analyzer.

Requires the ``api`` extra: ``pip install -e ".[api]"``.
Run with ``uvicorn xyainjex.api:app --reload``.
"""

from __future__ import annotations

import json
import os

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        'The HTTP API requires FastAPI. Install with: pip install -e ".[api]"'
    ) from exc

from .agent import analyze_agent, parse_source
from .agent.flow import analyze_flow
from .mcp import analyze_mcp
from .analyzer import analyze
from .argument import analyze_argument, mutate_argument
from .build import build
from .code import analyze_code, mutate_code, parse_code_lang
from .crlf import analyze_crlf, mutate_crlf, parse_crlf_kind
from .csv import analyze_csv, mutate_csv
from .deserialize import analyze_deserialize, mutate_deserialize
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .dispatch import BREAKOUT_LANGS, analyze_lang
from .el import analyze_el, mutate_el
from .encode import encode
from .fuzz import differential, fuzz
from .graphql import analyze_graphql, mutate_graphql
from .host import analyze_host, mutate_host
from .ldap import analyze_ldap, mutate_ldap
from .llm import explain, get_provider, suggest_payloads
from .mail import analyze_mail, mutate_mail
from .mutation import mutate
from .nosql import analyze_nosql, mutate_nosql
from .orm import analyze_orm, mutate_orm
from .path import analyze_path, mutate_path
from .prompt import analyze_prompt
from .prototype import analyze_prototype, mutate_prototype
from .redis import analyze_redis, mutate_redis
from .sql import analyze_sql, mutate_sql
from .ssi import analyze_ssi, mutate_ssi
from .ssrf import analyze_ssrf, mutate_ssrf
from .template import analyze_template, mutate_template
from .xml import analyze_xml, mutate_xml
from .xpath import analyze_xpath, mutate_xpath
from .xss import analyze_xss, mutate_xss
from .xxe import analyze_xxe, mutate_xxe
from .yaml import analyze_yaml, mutate_yaml

app = FastAPI(title="XyaInjex", version="0.10.0")

# Allow the web frontend to call the API from the browser. Origins are taken
# from XYAINJEX_CORS_ORIGINS (comma separated) and default to the local Vite
# dev server ports.
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
_cors_origins = [
    origin.strip()
    for origin in os.environ.get("XYAINJEX_CORS_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    template: str
    payload: str = ""
    lang: str = "shell"
    dialect: str | None = None
    source: str = "tool_output"


class MutateRequest(BaseModel):
    template: str
    command: str = "id"
    lang: str = "shell"
    dialect: str | None = None


class FuzzRequest(BaseModel):
    template: str
    lang: str = "shell"
    dialect: str | None = None
    command: str = "id"


class BuildRequest(BaseModel):
    template: str
    lang: str = "shell"
    dialect: str | None = None
    goal: str | None = None


class EncodeRequest(BaseModel):
    payload: str
    lang: str = "shell"
    dialect: str | None = None
    template: str | None = None


class DifferentialRequest(BaseModel):
    template: str
    payload: str
    lang: str = "shell"
    dialects: list[str]


class SuggestRequest(BaseModel):
    template: str
    lang: str = "shell"
    dialect: str | None = None
    provider: str = "mock"
    n: int = 12


class ExplainRequest(BaseModel):
    template: str
    payload: str
    lang: str = "shell"
    dialect: str | None = None
    provider: str = "mock"


class FlowStep(BaseModel):
    source: str
    content: str


class FlowRequest(BaseModel):
    steps: list[FlowStep]


class McpRequest(BaseModel):
    content: str
    tools: str | list | None = None


def _require_lang(lang: str) -> str:
    key = lang.strip().lower()
    valid = (
        "shell",
        "sql",
        "template",
        "xpath",
        "ldap",
        "nosql",
        "xml",
        "yaml",
        "graphql",
        "el",
        "csv",
        "ssi",
        "xss",
        "ssrf",
        "path",
        "mail",
        "xxe",
        "prototype",
        "argument",
        "deserialize",
        "orm",
        "host",
        "redis",
        "code",
        "crlf",
        "prompt",
        "agent",
    )
    if key not in valid:
        raise ValueError("lang must be one of: " + ", ".join(valid))
    return key


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    try:
        lang = _require_lang(req.lang)
        if lang == "agent":
            # The content is the untrusted blob; templates are not used here.
            return analyze_agent(req.template, parse_source(req.source)).to_dict()
        if lang == "xpath":
            return analyze_xpath(req.template, req.payload).to_dict()
        if lang == "ldap":
            return analyze_ldap(req.template, req.payload).to_dict()
        if lang == "nosql":
            return analyze_nosql(req.template, req.payload).to_dict()
        if lang == "xml":
            return analyze_xml(req.template, req.payload).to_dict()
        if lang == "yaml":
            return analyze_yaml(req.template, req.payload).to_dict()
        if lang == "graphql":
            return analyze_graphql(req.template, req.payload).to_dict()
        if lang == "el":
            return analyze_el(req.template, req.payload).to_dict()
        if lang == "csv":
            return analyze_csv(req.template, req.payload).to_dict()
        if lang == "ssi":
            return analyze_ssi(req.template, req.payload).to_dict()
        if lang == "xss":
            return analyze_xss(req.template, req.payload).to_dict()
        if lang == "ssrf":
            return analyze_ssrf(req.template, req.payload).to_dict()
        if lang == "path":
            return analyze_path(req.template, req.payload).to_dict()
        if lang == "mail":
            return analyze_mail(req.template, req.payload).to_dict()
        if lang == "xxe":
            return analyze_xxe(req.template, req.payload).to_dict()
        if lang == "prototype":
            return analyze_prototype(req.template, req.payload).to_dict()
        if lang == "argument":
            return analyze_argument(req.template, req.payload).to_dict()
        if lang == "deserialize":
            return analyze_deserialize(req.template, req.payload).to_dict()
        if lang == "orm":
            return analyze_orm(req.template, req.payload).to_dict()
        if lang == "host":
            return analyze_host(req.template, req.payload).to_dict()
        if lang == "redis":
            return analyze_redis(req.template, req.payload).to_dict()
        if lang == "code":
            code_lang = parse_code_lang(req.dialect or "python")
            return analyze_code(req.template, req.payload, code_lang).to_dict()
        if lang == "crlf":
            kind = parse_crlf_kind(req.dialect or "header")
            return analyze_crlf(req.template, req.payload, kind).to_dict()
        if lang == "prompt":
            return analyze_prompt(req.template, req.payload).to_dict()
        if lang == "sql":
            dialect = parse_sql_dialect(req.dialect or "mysql")
            return analyze_sql(req.template, req.payload, dialect).to_dict()
        if lang == "template":
            engine = parse_template_engine(req.dialect or "jinja2")
            return analyze_template(req.template, req.payload, engine).to_dict()
        dialect = parse_dialect(req.dialect or "posix")
        return analyze(req.template, req.payload, dialect).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/mutate")
def mutate_endpoint(req: MutateRequest) -> dict:
    try:
        lang = _require_lang(req.lang)
        if lang in ("prompt", "agent"):
            raise ValueError(f"mutate is not supported for lang {lang!r}")
        if lang == "xpath":
            return mutate_xpath(req.template).to_dict()
        if lang == "ldap":
            return mutate_ldap(req.template).to_dict()
        if lang == "nosql":
            return mutate_nosql(req.template).to_dict()
        if lang == "xml":
            return mutate_xml(req.template).to_dict()
        if lang == "yaml":
            return mutate_yaml(req.template).to_dict()
        if lang == "graphql":
            return mutate_graphql(req.template).to_dict()
        if lang == "el":
            return mutate_el(req.template).to_dict()
        if lang == "csv":
            return mutate_csv(req.template).to_dict()
        if lang == "ssi":
            return mutate_ssi(req.template).to_dict()
        if lang == "xss":
            return mutate_xss(req.template).to_dict()
        if lang == "ssrf":
            return mutate_ssrf(req.template).to_dict()
        if lang == "path":
            return mutate_path(req.template).to_dict()
        if lang == "mail":
            return mutate_mail(req.template).to_dict()
        if lang == "xxe":
            return mutate_xxe(req.template).to_dict()
        if lang == "prototype":
            return mutate_prototype(req.template).to_dict()
        if lang == "argument":
            return mutate_argument(req.template).to_dict()
        if lang == "deserialize":
            return mutate_deserialize(req.template).to_dict()
        if lang == "orm":
            return mutate_orm(req.template).to_dict()
        if lang == "host":
            return mutate_host(req.template).to_dict()
        if lang == "redis":
            return mutate_redis(req.template).to_dict()
        if lang == "code":
            return mutate_code(
                req.template, parse_code_lang(req.dialect or "python")
            ).to_dict()
        if lang == "crlf":
            return mutate_crlf(
                req.template, parse_crlf_kind(req.dialect or "header")
            ).to_dict()
        if lang == "sql":
            dialect = parse_sql_dialect(req.dialect or "mysql")
            return mutate_sql(req.template, dialect=dialect).to_dict()
        if lang == "template":
            engine = parse_template_engine(req.dialect or "jinja2")
            return mutate_template(req.template, engine).to_dict()
        dialect = parse_dialect(req.dialect or "posix")
        return mutate(req.template, command=req.command, dialect=dialect).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/build")
def build_endpoint(req: BuildRequest) -> dict:
    try:
        return build(
            req.template,
            lang=req.lang.strip().lower(),
            goal=req.goal,
            dialect=req.dialect,
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/encode")
def encode_endpoint(req: EncodeRequest) -> dict:
    try:
        return encode(
            req.payload,
            lang=req.lang.strip().lower(),
            template=req.template,
            dialect=req.dialect,
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/fuzz")
def fuzz_endpoint(req: FuzzRequest) -> dict:
    try:
        return fuzz(
            req.template,
            lang=req.lang.strip().lower(),
            dialect=req.dialect,
            command=req.command,
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/differential")
def differential_endpoint(req: DifferentialRequest) -> dict:
    try:
        return differential(
            req.template, req.payload, req.lang.strip().lower(), req.dialects
        ).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/suggest")
def suggest_endpoint(req: SuggestRequest) -> dict:
    """Ask an LLM provider for payloads and return the ones the engine validates.

    The provider is chosen by name (mock, openai, claude, ollama); the engine
    remains the source of truth, so only payloads that actually break out are
    returned.
    """
    n = max(1, min(req.n, 50))
    try:
        provider = get_provider(req.provider)
        return suggest_payloads(
            req.template,
            provider,
            lang=req.lang.strip().lower(),
            dialect=req.dialect,
            n=n,
        ).to_dict()
    except (ValueError, ImportError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # provider/runtime failure (e.g. LLM unreachable)
        raise HTTPException(status_code=502, detail=f"provider error: {exc}") from exc


@app.post("/explain")
def explain_endpoint(req: ExplainRequest) -> dict:
    """Analyze a payload, then ask an LLM provider to explain the breakout."""
    lang = req.lang.strip().lower()
    if lang not in BREAKOUT_LANGS:
        raise HTTPException(
            status_code=400,
            detail="explain supports: " + ", ".join(BREAKOUT_LANGS),
        )
    try:
        provider = get_provider(req.provider)
        result = analyze_lang(req.template, req.payload, lang, req.dialect)
        return {"explanation": explain(result, provider)}
    except (ValueError, ImportError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # provider/runtime failure (e.g. LLM unreachable)
        raise HTTPException(status_code=502, detail=f"provider error: {exc}") from exc


@app.post("/flow")
def flow_endpoint(req: FlowRequest) -> dict:
    """Analyze a multi-agent message flow and return a trust graph."""
    if not req.steps:
        raise HTTPException(status_code=400, detail="at least one flow step is required")
    try:
        steps = [(parse_source(s.source), s.content) for s in req.steps]
        return analyze_flow(steps).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/mcp")
def mcp_endpoint(req: McpRequest) -> dict:
    """Analyze untrusted content and an optional MCP tool catalog."""
    try:
        return analyze_mcp(req.content, tools=req.tools).to_dict()
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
