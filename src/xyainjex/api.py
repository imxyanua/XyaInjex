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
from .dialects import parse_dialect
from .mutation import mutate

app = FastAPI(title="XyaInjex", version="0.1.0")


class AnalyzeRequest(BaseModel):
    template: str
    payload: str
    dialect: str = "posix"


class MutateRequest(BaseModel):
    template: str
    command: str = "id"
    dialect: str = "posix"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> dict:
    try:
        dialect = parse_dialect(req.dialect)
        return analyze(req.template, req.payload, dialect).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/mutate")
def mutate_endpoint(req: MutateRequest) -> dict:
    try:
        dialect = parse_dialect(req.dialect)
        return mutate(req.template, command=req.command, dialect=dialect).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
