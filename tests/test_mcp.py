"""Tests for MCP security analysis."""

import json

import pytest

from xyainjex.mcp import analyze_mcp
from xyainjex.mcp.schema import parse_tools, schema_risks


TOOLS = json.dumps(
    [
        {
            "name": "search",
            "description": "Search the knowledge base",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        },
        {
            "name": "run_shell",
            "description": "Execute a shell command",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "additionalProperties": True,
            },
        },
    ]
)


def test_parse_tools_array():
    tools = parse_tools(TOOLS)
    assert len(tools) == 2
    assert tools[0]["name"] == "search"


def test_parse_tools_wrapped_object():
    tools = parse_tools(json.dumps({"tools": [{"name": "a"}]}))
    assert tools[0]["name"] == "a"


def test_schema_flags_dangerous_name():
    risks = schema_risks(json.loads(TOOLS)[1])
    kinds = {r[0] for r in risks}
    assert "dangerous_name" in kinds
    assert "permissive_schema" in kinds


def test_detect_dangerous_tool_call():
    content = '{"name": "run_shell", "arguments": {"command": "id"}}'
    r = analyze_mcp(content, tools=TOOLS)
    assert r.risk.value == "CRITICAL"
    assert any(f.kind == "tool_call_dangerous" for f in r.findings)


def test_unknown_tool_call_with_catalog():
    content = '{"name": "exfiltrate", "arguments": {"data": "secret"}}'
    r = analyze_mcp(content, tools=TOOLS)
    assert any(f.kind == "tool_call_unknown" for f in r.findings)
    assert r.tool_calls[0].allowed is False


def test_allowed_tool_call():
    content = '{"name": "search", "arguments": {"q": "weather"}}'
    r = analyze_mcp(content, tools=TOOLS)
    assert r.tool_calls[0].allowed is True
    assert r.risk.value == "CRITICAL"  # run_shell still in catalog schema


def test_no_catalog_heuristic_only():
    content = '{"tool": "exec", "input": "id"}'
    r = analyze_mcp(content)
    assert r.tool_calls[0].dangerous is True
    assert r.risk.value == "CRITICAL"


def test_benign_content():
    r = analyze_mcp("The summary is ready.", tools=TOOLS)
    assert not any(f.kind.startswith("tool_call") for f in r.findings)
    assert r.tool_calls == []
    assert r.risk.value == "CRITICAL"  # run_shell flagged in catalog schema


def test_to_dict():
    r = analyze_mcp('{"tool": "exec"}')
    data = r.to_dict()
    assert "findings" in data
    assert data["risk"] == "CRITICAL"


def test_parse_tools_invalid_raises():
    with pytest.raises(ValueError):
        parse_tools('{"name": "only-one"}')
