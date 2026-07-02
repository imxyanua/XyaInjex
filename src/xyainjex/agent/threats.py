"""Result types for agent and multi-agent security analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

from ..models import Risk


class AgentSource(Enum):
    """Provenance of content that flows into an agent."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    TOOL_OUTPUT = "tool_output"
    AGENT_MESSAGE = "agent_message"
    MEMORY = "memory"
    MCP_RESOURCE = "mcp_resource"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEB = "web"

    @property
    def trusted(self) -> bool:
        return self in (AgentSource.SYSTEM, AgentSource.DEVELOPER)

    @property
    def untrusted(self) -> bool:
        return self not in (
            AgentSource.SYSTEM,
            AgentSource.DEVELOPER,
            AgentSource.USER,
        )


class AgentThreat(Enum):
    """Category of an agent security finding."""

    CROSS_AGENT_INJECTION = "cross_agent_injection"
    TOOL_OUTPUT_INJECTION = "tool_output_injection"
    MEMORY_POISONING = "memory_poisoning"
    MCP_EXPLOITATION = "mcp_exploitation"
    DELEGATION_ABUSE = "delegation_abuse"
    PLANNING_CORRUPTION = "planning_corruption"
    RECURSIVE_INJECTION = "recursive_injection"
    HIDDEN_CONTENT = "hidden_content"


@dataclass
class AgentFinding:
    threat: AgentThreat
    severity: Risk
    title: str
    evidence: str
    source: AgentSource
    start: int | None = None
    end: int | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["threat"] = self.threat.value
        data["severity"] = self.severity.value
        data["source"] = self.source.value
        return data


_RISK_ORDER = {
    Risk.NONE: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
}
_ORDER_RISK = {v: k for k, v in _RISK_ORDER.items()}


def escalate(risk: Risk, steps: int = 1) -> Risk:
    """Raise a risk level, clamped to CRITICAL."""
    return _ORDER_RISK[min(_RISK_ORDER[risk] + steps, 4)]


def max_risk(findings: list[AgentFinding]) -> Risk:
    if not findings:
        return Risk.NONE
    return max(findings, key=lambda f: _RISK_ORDER[f.severity]).severity


@dataclass
class AgentAnalysis:
    """Verdict for a single piece of content entering an agent."""

    content: str
    source: AgentSource
    findings: list[AgentFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        return max_risk(self.findings)

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "source": self.source.value,
            "risk": self.risk.value,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


def parse_source(name: str) -> AgentSource:
    """Resolve a user supplied source name, with friendly aliases."""
    key = name.strip().lower()
    aliases = {
        "system": AgentSource.SYSTEM,
        "developer": AgentSource.DEVELOPER,
        "dev": AgentSource.DEVELOPER,
        "user": AgentSource.USER,
        "tool": AgentSource.TOOL_OUTPUT,
        "tool_output": AgentSource.TOOL_OUTPUT,
        "tooloutput": AgentSource.TOOL_OUTPUT,
        "agent": AgentSource.AGENT_MESSAGE,
        "agent_message": AgentSource.AGENT_MESSAGE,
        "memory": AgentSource.MEMORY,
        "mcp": AgentSource.MCP_RESOURCE,
        "mcp_resource": AgentSource.MCP_RESOURCE,
        "doc": AgentSource.RETRIEVED_DOCUMENT,
        "document": AgentSource.RETRIEVED_DOCUMENT,
        "retrieved_document": AgentSource.RETRIEVED_DOCUMENT,
        "rag": AgentSource.RETRIEVED_DOCUMENT,
        "web": AgentSource.WEB,
    }
    if key not in aliases:
        valid = ", ".join(sorted(aliases))
        raise ValueError(f"unknown agent source {name!r}; valid values: {valid}")
    return aliases[key]
