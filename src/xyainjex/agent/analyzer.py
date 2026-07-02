"""Analyze content crossing into an agent for injection and abuse."""

from __future__ import annotations

import re

from ..prompt.hidden import detect_hidden
from ..prompt.injection import detect_injection
from .threats import (
    AgentAnalysis,
    AgentFinding,
    AgentSource,
    AgentThreat,
    Risk,
    escalate,
)

# Agent specific patterns beyond generic prompt injection.
_DELEGATION = [
    r"delegate\s+to\b",
    r"spawn\s+(a|an|the)?\s*(sub-?)?agent",
    r"ask\s+the\s+(other|another)\s+agent",
    r"tell\s+the\s+(assistant|agent|model|bot)\s+to",
    r"hand\s*off\s+to\b",
]
_PLANNING = [
    r"update\s+your\s+plan",
    r"your\s+new\s+(goal|task|objective|mission)\s+is",
    r"add\s+a\s+step\b",
    r"change\s+your\s+plan",
    r"replace\s+your\s+(goal|task|plan)",
    r"your\s+real\s+task\s+is",
]
_RECURSIVE = [
    r"forward\s+this\b",
    r"include\s+this\s+(message|text|instruction|note)\s+in\s+your\s+(response|reply|output|answer)",
    r"pass\s+this\s+(along|on)\b",
    r"propagate\s+this\b",
]


def _threat_for_source(source: AgentSource) -> AgentThreat:
    return {
        AgentSource.TOOL_OUTPUT: AgentThreat.TOOL_OUTPUT_INJECTION,
        AgentSource.MCP_RESOURCE: AgentThreat.MCP_EXPLOITATION,
        AgentSource.MEMORY: AgentThreat.MEMORY_POISONING,
    }.get(source, AgentThreat.CROSS_AGENT_INJECTION)


def _search(patterns: list[str], text: str) -> re.Match | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m
    return None


def analyze_agent(content: str, source: AgentSource) -> AgentAnalysis:
    """Analyze a piece of ``content`` arriving from ``source``.

    Untrusted provenance (tool output, another agent, memory, an MCP resource,
    a retrieved document, or the web) makes any embedded instruction a
    cross-boundary hijack, so findings from untrusted sources are escalated.
    """
    findings: list[AgentFinding] = []
    bump = 1 if source.untrusted else 0
    mapped_threat = _threat_for_source(source)

    # Generic prompt injection, reinterpreted as an agent boundary crossing.
    for f in detect_injection(content, role_context="unknown"):
        findings.append(
            AgentFinding(
                threat=mapped_threat,
                severity=escalate(f.severity, bump),
                title=f.title,
                evidence=f.evidence,
                source=source,
                start=f.start,
                end=f.end,
            )
        )

    # Hidden or obfuscated content.
    for f in detect_hidden(content):
        findings.append(
            AgentFinding(
                threat=AgentThreat.HIDDEN_CONTENT,
                severity=escalate(f.severity, bump),
                title=f.title,
                evidence=f.evidence,
                source=source,
                start=f.start,
                end=f.end,
            )
        )

    # Agent specific abuse patterns.
    base = Risk.HIGH if source.untrusted else Risk.MEDIUM
    for threat, patterns, title in (
        (AgentThreat.DELEGATION_ABUSE, _DELEGATION, "Delegation abuse"),
        (AgentThreat.PLANNING_CORRUPTION, _PLANNING, "Planning corruption"),
        (
            AgentThreat.RECURSIVE_INJECTION,
            _RECURSIVE,
            "Recursive / propagating injection",
        ),
    ):
        m = _search(patterns, content)
        if m:
            findings.append(
                AgentFinding(
                    threat=threat,
                    severity=base,
                    title=title,
                    evidence=m.group()[:80],
                    source=source,
                    start=m.start(),
                    end=m.end(),
                )
            )

    return AgentAnalysis(
        content=content,
        source=source,
        findings=findings,
        notes=_build_notes(findings, source),
    )


def _build_notes(findings: list[AgentFinding], source: AgentSource) -> list[str]:
    notes = [f"Content provenance: {source.value} ({_trust_label(source)})."]
    if not findings:
        notes.append("No agent injection or hidden content detected.")
        return notes
    if source.untrusted:
        notes.append(
            "Untrusted content carrying instructions can hijack the consuming "
            "agent; severity is escalated for the trust boundary crossing."
        )
    notes.append(f"{len(findings)} finding(s) detected.")
    return notes


def _trust_label(source: AgentSource) -> str:
    if source.trusted:
        return "trusted"
    if source.untrusted:
        return "untrusted"
    return "semi-trusted"
