"""Trust graph for multi-agent message flows."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Risk
from .threats import AgentSource

_SOURCE_KIND = {
    AgentSource.SYSTEM: "system",
    AgentSource.DEVELOPER: "system",
    AgentSource.USER: "user",
    AgentSource.TOOL_OUTPUT: "tool",
    AgentSource.AGENT_MESSAGE: "agent",
    AgentSource.MEMORY: "memory",
    AgentSource.MCP_RESOURCE: "mcp",
    AgentSource.RETRIEVED_DOCUMENT: "document",
    AgentSource.WEB: "web",
}

_SOURCE_LABEL = {
    AgentSource.SYSTEM: "System",
    AgentSource.DEVELOPER: "Developer",
    AgentSource.USER: "User",
    AgentSource.TOOL_OUTPUT: "Tool output",
    AgentSource.AGENT_MESSAGE: "Agent message",
    AgentSource.MEMORY: "Memory",
    AgentSource.MCP_RESOURCE: "MCP resource",
    AgentSource.RETRIEVED_DOCUMENT: "Document",
    AgentSource.WEB: "Web",
}

_HIGH = (Risk.HIGH, Risk.CRITICAL)

_RISK_ORDER = {
    Risk.NONE: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
}


@dataclass
class TrustNode:
    id: str
    label: str
    kind: str
    source: str
    risk: str
    compromised: bool
    hop: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "source": self.source,
            "risk": self.risk,
            "compromised": self.compromised,
            "hop": self.hop,
        }


@dataclass
class TrustEdge:
    from_id: str
    to_id: str
    label: str
    risk: str
    compromised: bool

    def to_dict(self) -> dict:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "label": self.label,
            "risk": self.risk,
            "compromised": self.compromised,
        }


@dataclass
class TrustGraph:
    nodes: list[TrustNode] = field(default_factory=list)
    edges: list[TrustEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


def build_trust_graph(
    steps: list[tuple[AgentSource, str]],
    risks: list[Risk],
) -> TrustGraph:
    """Build a trust graph from ordered flow hops and their analyzed risks."""
    nodes: list[TrustNode] = []
    edges: list[TrustEdge] = []

    hop_ids: list[str] = []
    for i, (source, _content) in enumerate(steps):
        risk = risks[i]
        compromised = source.untrusted and risk in _HIGH
        node_id = f"hop_{i + 1}"
        hop_ids.append(node_id)
        nodes.append(
            TrustNode(
                id=node_id,
                label=f"Hop {i + 1}: {_SOURCE_LABEL[source]}",
                kind=_SOURCE_KIND[source],
                source=source.value,
                risk=risk.value,
                compromised=compromised,
                hop=i + 1,
            )
        )

    agent_compromised = any(
        source.untrusted and risks[i] in _HIGH for i, (source, _) in enumerate(steps)
    )
    worst = max(risks, key=lambda r: _RISK_ORDER[r]) if risks else Risk.NONE
    nodes.append(
        TrustNode(
            id="agent",
            label="Consuming agent",
            kind="agent",
            source="agent",
            risk=worst.value,
            compromised=agent_compromised,
            hop=0,
        )
    )

    chain = hop_ids + ["agent"]
    for i in range(len(chain) - 1):
        src_id = chain[i]
        dst_id = chain[i + 1]
        src_node = next(n for n in nodes if n.id == src_id)
        edges.append(
            TrustEdge(
                from_id=src_id,
                to_id=dst_id,
                label="feeds",
                risk=src_node.risk,
                compromised=src_node.compromised,
            )
        )

    return TrustGraph(nodes=nodes, edges=edges)
