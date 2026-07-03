"""Optional HTTP API exposing the analyzer.

Requires the ``api`` extra: ``pip install -e ".[api]"``.
Run with ``uvicorn xyainjex.api:app --reload``.
"""

from __future__ import annotations

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
from .analyzer import analyze
from .code import analyze_code, mutate_code, parse_code_lang
from .crlf import analyze_crlf, mutate_crlf, parse_crlf_kind
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .el import analyze_el, mutate_el
from .fuzz import differential, fuzz
from .graphql import analyze_graphql, mutate_graphql
from .ldap import analyze_ldap, mutate_ldap
from .mutation import mutate
from .nosql import analyze_nosql, mutate_nosql
from .prompt import analyze_prompt
from .sql import analyze_sql, mutate_sql
from .template import analyze_template, mutate_template
from .xml import analyze_xml, mutate_xml
from .xpath import analyze_xpath, mutate_xpath
from .yaml import analyze_yaml, mutate_yaml

app = FastAPI(title="XyaInjex", version="0.4.0")

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


class DifferentialRequest(BaseModel):
    template: str
    payload: str
    lang: str = "shell"
    dialects: list[str]


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
