"""LLM-assisted payload suggestion and explanation.

The LLM proposes; the deterministic engine disposes. Suggested payloads are
always validated by the analyzer, so a suggestion is only returned when it
actually achieves a breakout.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analyzer import analyze
from ..dialects import parse_dialect, parse_sql_dialect, parse_template_engine
from ..models import AnalysisResult, Risk
from ..sql import analyze_sql
from ..template import analyze_template
from .providers import LLMProvider

_LANGS = ("shell", "sql", "template")

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}

_SYSTEM = (
    "You are an application security assistant helping with authorized injection "
    "testing. Given a command or query template with a {INPUT} marker, propose "
    "candidate breakout payloads. Reply with one payload per line and nothing "
    "else: no numbering, no commentary, no code fences."
)


def _analyze(
    template: str, payload: str, lang: str, dialect: str | None
) -> AnalysisResult:
    if lang == "sql":
        return analyze_sql(template, payload, parse_sql_dialect(dialect or "mysql"))
    if lang == "template":
        return analyze_template(
            template, payload, parse_template_engine(dialect or "jinja2")
        )
    return analyze(template, payload, parse_dialect(dialect or "posix"))


def _injects(result: AnalysisResult) -> bool:
    b = result.breakout
    return b.command_injected or b.substitution_injected


def _parse_payloads(text: str, limit: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        # Drop obvious list markers and code fences.
        if line.startswith("```") or not line:
            continue
        line = line.lstrip("-*0123456789. ").strip("`")
        if line and line not in seen:
            seen.add(line)
            out.append(line)
        if len(out) >= limit:
            break
    return out


@dataclass
class Suggestion:
    payload: str
    risk: Risk
    context: str
    command_injected: bool
    substitution_injected: bool

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "risk": self.risk.value,
            "context": self.context,
            "command_injected": self.command_injected,
            "substitution_injected": self.substitution_injected,
        }


@dataclass
class SuggestResult:
    template: str
    lang: str
    dialect: str | None
    proposed: int
    validated: list[Suggestion] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "lang": self.lang,
            "dialect": self.dialect,
            "proposed": self.proposed,
            "valid": len(self.validated),
            "validated": [s.to_dict() for s in self.validated],
        }


def suggest_payloads(
    template: str,
    provider: LLMProvider,
    lang: str = "shell",
    dialect: str | None = None,
    n: int = 12,
) -> SuggestResult:
    """Ask ``provider`` for payloads and return the ones the engine validates."""
    if lang not in _LANGS:
        raise ValueError(f"suggestion supports {_LANGS}, not {lang!r}")

    prompt = (
        f"Language: {lang}\n"
        f"Dialect: {dialect or 'default'}\n"
        f"Template: {template}\n"
        f"Give up to {n} breakout payloads for the {{INPUT}} marker."
    )
    reply = provider.complete(prompt, system=_SYSTEM)
    proposed = _parse_payloads(reply, n)

    validated: list[Suggestion] = []
    for payload in proposed:
        result = _analyze(template, payload, lang, dialect)
        if _injects(result):
            b = result.breakout
            validated.append(
                Suggestion(
                    payload=payload,
                    risk=result.risk,
                    context=result.context.value,
                    command_injected=b.command_injected,
                    substitution_injected=b.substitution_injected,
                )
            )

    validated.sort(key=lambda s: _RISK_ORDER[s.risk], reverse=True)
    return SuggestResult(
        template=template,
        lang=lang,
        dialect=dialect,
        proposed=len(proposed),
        validated=validated,
    )


def explain(result: AnalysisResult, provider: LLMProvider) -> str:
    """Ask ``provider`` to explain an analysis result in natural language."""
    b = result.breakout
    prompt = (
        "Explain this injection analysis for a security report in a short "
        "paragraph.\n"
        f"Template: {result.template}\n"
        f"Payload: {result.payload}\n"
        f"Rendered: {result.rendered}\n"
        f"Context: {result.context.value}\n"
        f"Quote closed: {b.quote_closed}\n"
        f"Command injected: {b.command_injected}\n"
        f"Substitution injected: {b.substitution_injected}\n"
        f"Comment terminated: {b.comment_terminated}\n"
        f"Risk: {result.risk.value}"
    )
    system = (
        "You are a security assistant. Explain injection breakouts factually and "
        "concisely for an authorized testing report."
    )
    return provider.complete(prompt, system=system)
