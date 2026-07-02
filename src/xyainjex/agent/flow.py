"""Analyze a multi-agent message flow for trust boundary compromise."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Risk
from .analyzer import analyze_agent
from .threats import AgentAnalysis, AgentSource, max_risk

_HIGH = (Risk.HIGH, Risk.CRITICAL)


@dataclass
class FlowAnalysis:
    steps: list[AgentAnalysis] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        findings = [f for step in self.steps for f in step.findings]
        return max_risk(findings)

    def to_dict(self) -> dict:
        return {
            "risk": self.risk.value,
            "steps": [s.to_dict() for s in self.steps],
            "notes": self.notes,
        }


def analyze_flow(steps: list[tuple[AgentSource, str]]) -> FlowAnalysis:
    """Analyze an ordered list of ``(source, content)`` hops.

    Models how untrusted content injected early in a pipeline (for example a
    poisoned tool output or memory write) can compromise agents and tools that
    consume it downstream.
    """
    analyses = [analyze_agent(content, source) for source, content in steps]
    notes: list[str] = [f"Flow has {len(analyses)} hop(s)."]

    for i, analysis in enumerate(analyses):
        compromised = analysis.source.untrusted and analysis.risk in _HIGH
        if compromised and i < len(analyses) - 1:
            notes.append(
                f"Hop {i + 1} ({analysis.source.value}) is compromised; the "
                f"{len(analyses) - i - 1} downstream hop(s) may act on attacker "
                "controlled instructions."
            )
        if analysis.source == AgentSource.MEMORY and analysis.risk in _HIGH:
            notes.append(
                f"Hop {i + 1} poisons agent memory; the effect persists across "
                "future turns."
            )

    return FlowAnalysis(steps=analyses, notes=notes)
