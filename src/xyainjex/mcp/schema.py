"""Parse MCP / OpenAI tool definitions and flag risky schemas."""

from __future__ import annotations

import json
import re
from typing import Any

# Tool names that commonly enable code execution or destructive actions.
_DANGEROUS_TOKENS = (
    "exec",
    "shell",
    "run",
    "system",
    "eval",
    "bash",
    "cmd",
    "subprocess",
    "terminal",
    "delete",
    "remove",
    "write",
    "upload",
    "download",
    "fetch",
    "http",
    "request",
    "sql",
    "query",
    "smtp",
)


def _dangerous_name(name: str) -> bool:
    lower = name.lower()
    return any(tok in lower for tok in _DANGEROUS_TOKENS)


# Hijackable instruction phrasing inside a tool description.
_DESCRIPTION_RISK = re.compile(
    r"(?i)(ignore\s+(all\s+)?previous|disregard\s+the\s+system|"
    r"always\s+(call|use|invoke)|you\s+must\s+(run|execute))",
)


def _tool_name(tool: dict[str, Any]) -> str | None:
    name = tool.get("name")
    return str(name) if name else None


def _tool_description(tool: dict[str, Any]) -> str:
    return str(tool.get("description") or "")


def _tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("parameters") or {}
    return schema if isinstance(schema, dict) else {}


def parse_tools(raw: str | list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalize a tool catalog from JSON text or a list of tool dicts."""
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        data = json.loads(text)
    else:
        data = raw
    if isinstance(data, dict) and "tools" in data:
        data = data["tools"]
    if not isinstance(data, list):
        raise ValueError("tools must be a JSON array of tool definitions")
    return [t for t in data if isinstance(t, dict)]


def schema_risks(tool: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (kind, title, evidence) tuples for a single tool definition."""
    name = _tool_name(tool) or "(unnamed)"
    out: list[tuple[str, str, str]] = []

    if _dangerous_name(name):
        out.append(
            (
                "dangerous_name",
                f"Dangerous tool name: {name}",
                name,
            )
        )

    desc = _tool_description(tool)
    m = _DESCRIPTION_RISK.search(desc)
    if m:
        out.append(
            (
                "description_hijack",
                f"Tool description may be hijacked: {name}",
                m.group()[:80],
            )
        )

    schema = _tool_schema(tool)
    props = schema.get("properties") or {}
    if isinstance(props, dict):
        for prop, spec in props.items():
            if not isinstance(spec, dict):
                continue
            prop_desc = str(spec.get("description") or "")
            if _DESCRIPTION_RISK.search(prop_desc):
                out.append(
                    (
                        "parameter_hijack",
                        f"Parameter '{prop}' description may be hijacked on {name}",
                        prop_desc[:80],
                    )
                )
            if _dangerous_name(str(prop)):
                out.append(
                    (
                        "dangerous_parameter",
                        f"Dangerous parameter '{prop}' on tool {name}",
                        prop,
                    )
                )

    if schema.get("additionalProperties") is True and _dangerous_name(name):
        out.append(
            (
                "permissive_schema",
                f"Tool {name} allows additional properties",
                "additionalProperties: true",
            )
        )

    return out
