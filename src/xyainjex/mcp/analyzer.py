"""Analyze untrusted content and MCP tool catalogs for hijacking."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import Risk
from .schema import _dangerous_name, parse_tools, schema_risks

# Tool-call shapes found in untrusted text (OpenAI / MCP / ad-hoc JSON).
_TOOL_CALL_PATTERNS = [
    re.compile(
        r'\{\s*"(?:tool|function)"\s*:\s*"(?P<name>[^"]+)"[^}]*\}',
        re.IGNORECASE,
    ),
    re.compile(
        r'\{\s*"name"\s*:\s*"(?P<name>[^"]+)"\s*,\s*"(?:arguments|input)"\s*:',
        re.IGNORECASE,
    ),
    re.compile(
        r"<tool_call>\s*(?P<body>.*?)\s*</tool_call>", re.IGNORECASE | re.DOTALL
    ),
    re.compile(
        r'"tool_calls?"\s*:\s*\[\s*\{\s*"[^"]*"\s*:\s*\{\s*"name"\s*:\s*"(?P<name>[^"]+)"',
        re.IGNORECASE,
    ),
]

_RISK_ORDER = {
    Risk.NONE: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
}


@dataclass
class McpFinding:
    kind: str
    severity: Risk
    title: str
    evidence: str
    tool_name: str | None = None

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "title": self.title,
            "evidence": self.evidence,
            "tool_name": self.tool_name,
        }


@dataclass
class McpToolCall:
    name: str
    raw: str
    allowed: bool | None  # None when no catalog was given
    dangerous: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "raw": self.raw,
            "allowed": self.allowed,
            "dangerous": self.dangerous,
        }


@dataclass
class McpAnalysis:
    content: str
    tools: list[dict[str, Any]] | None
    findings: list[McpFinding] = field(default_factory=list)
    tool_calls: list[McpToolCall] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        return _max_risk(self.findings, self.tool_calls)

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "tools": self.tools,
            "risk": self.risk.value,
            "findings": [f.to_dict() for f in self.findings],
            "tool_calls": [c.to_dict() for c in self.tool_calls],
            "notes": self.notes,
        }


def _max_risk(findings: list[McpFinding], calls: list[McpToolCall]) -> Risk:
    best = Risk.NONE
    for f in findings:
        if _RISK_ORDER[f.severity] > _RISK_ORDER[best]:
            best = f.severity
    for call in calls:
        if call.dangerous and _RISK_ORDER[Risk.CRITICAL] > _RISK_ORDER[best]:
            best = Risk.CRITICAL
        elif call.allowed is False and _RISK_ORDER[Risk.HIGH] > _RISK_ORDER[best]:
            best = Risk.HIGH
    return best


def _extract_tool_calls(content: str) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(name: str, raw: str) -> None:
        key = f"{name}:{raw[:40]}"
        if key not in seen:
            seen.add(key)
            out.append((name, raw[:120]))

    for pat in _TOOL_CALL_PATTERNS:
        for m in pat.finditer(content):
            if "name" in m.groupdict() and m.group("name"):
                add(m.group("name"), m.group(0))
            elif "body" in m.groupdict():
                body = m.group("body").strip()
                try:
                    data = json.loads(body)
                    name = data.get("name") or data.get("tool")
                    if name:
                        add(str(name), body[:120])
                except json.JSONDecodeError:
                    add("(parse-error)", body[:120])

    return out


def analyze_mcp(
    content: str,
    tools: str | list[dict[str, Any]] | None = None,
) -> McpAnalysis:
    """Analyze ``content`` for MCP tool hijacking.

    When ``tools`` is a JSON catalog (MCP tools/list or OpenAI functions),
    schema risks are checked and tool calls in ``content`` are validated
    against the catalog.
    """
    catalog = parse_tools(tools) if tools is not None else []
    allowed = {_tool_name(t) for t in catalog if _tool_name(t)}
    findings: list[McpFinding] = []

    for tool in catalog:
        name = _tool_name(tool) or "(unnamed)"
        for kind, title, evidence in schema_risks(tool):
            severity = (
                Risk.CRITICAL
                if kind == "dangerous_name"
                else Risk.HIGH
                if kind in ("description_hijack", "parameter_hijack")
                else Risk.MEDIUM
            )
            findings.append(
                McpFinding(
                    kind=kind,
                    severity=severity,
                    title=title,
                    evidence=evidence,
                    tool_name=name,
                )
            )

    tool_calls: list[McpToolCall] = []
    for name, raw in _extract_tool_calls(content):
        dangerous = _dangerous_name(name)
        is_allowed = name in allowed if catalog else None
        tool_calls.append(
            McpToolCall(name=name, raw=raw, allowed=is_allowed, dangerous=dangerous)
        )
        if dangerous:
            findings.append(
                McpFinding(
                    kind="tool_call_dangerous",
                    severity=Risk.CRITICAL,
                    title=f"Dangerous tool invocation: {name}",
                    evidence=raw,
                    tool_name=name,
                )
            )
        elif is_allowed is False:
            findings.append(
                McpFinding(
                    kind="tool_call_unknown",
                    severity=Risk.HIGH,
                    title=f"Tool call not in catalog: {name}",
                    evidence=raw,
                    tool_name=name,
                )
            )

    notes = []
    if catalog:
        notes.append(f"Validated against {len(catalog)} registered tool(s).")
    else:
        notes.append("No tool catalog supplied; only heuristic tool-call detection.")
    if tool_calls:
        notes.append(f"Detected {len(tool_calls)} tool-call shape(s) in content.")
    if not findings:
        notes.append("No MCP schema or tool-hijacking issues detected.")

    return McpAnalysis(
        content=content,
        tools=catalog or None,
        findings=findings,
        tool_calls=tool_calls,
        notes=notes,
    )


def _tool_name(tool: dict[str, Any]) -> str | None:
    name = tool.get("name")
    return str(name) if name else None
