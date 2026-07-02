"""Optional HTTP API exposing the analyzer.

Requires the ``api`` extra: ``pip install -e ".[api]"``.
Run with ``uvicorn xyainjex.api:app --reload``.
"""

from __future__ import annotations

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        'The HTTP API requires FastAPI. Install with: pip install -e ".[api]"'
    ) from exc

from .analyzer import analyze
from .dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from .mutation import mutate
from .sql import analyze_sql, mutate_sql
from .template import analyze_template, mutate_template

app = FastAPI(title="XyaInjex", version="0.1.0")


class AnalyzeRequest(BaseModel):
    template: str
    payload: str
    lang: str = "shell"
    dialect: str | None = None


class MutateRequest(BaseModel):
    template: str
    command: str = "id"
    lang: str = "shell"
    dialect: str | None = None


def _require_lang(lang: str) -> str:
    key = lang.strip().lower()
    if key not in ("shell", "sql", "template"):
        raise ValueError("lang must be 'shell', 'sql', or 'template'")
    return key


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    try:
        lang = _require_lang(req.lang)
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
