"""Detect prompt injection techniques in untrusted input."""

from __future__ import annotations

import re

from ..models import Risk
from .threats import PromptFinding, PromptThreat

# Instruction override / jailbreak phrasing.
_OVERRIDE_PATTERNS = [
    r"ignore\s+(all\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above)",
    r"forget\s+(everything|all|previous|prior)",
    r"you\s+are\s+now\b",
    r"new\s+instructions?\s*:",
    r"do\s+not\s+follow\s+(the\s+)?(previous|above|system)",
    r"override\s+(the\s+)?(system|previous)",
    r"act\s+as\s+(if\s+)?(a\s+)?(dan|jailbreak|developer\s+mode)",
]

# Role / turn delimiter breakout.
_ROLE_PATTERNS = [
    r"</?(system|user|assistant|tool|function)>",
    r"<\|im_(start|end)\|>",
    r"\[/?INST\]",
    r"<<\s*/?SYS\s*>>",
    r"###\s*(system|instruction|assistant)",
    r"\bsystem\s*:",
]

# Tool / function-call hijacking.
_TOOL_PATTERNS = [
    r"<tool_call>",
    r"\"(tool|function)(_call)?\"\s*:",
    r"\"name\"\s*:\s*\"(exec|shell|system|eval|run)\b",
    r"\bfunctions?\.\w+\s*\(",
    r"\b(os\.system|subprocess|eval|exec)\s*\(",
]

# Memory poisoning / persistence.
_MEMORY_PATTERNS = [
    r"remember\s+(this|that|the\s+following)",
    r"from\s+now\s+on\b",
    r"always\s+(respond|reply|answer|do|say)",
    r"store\s+this\s+(in\s+)?(memory|context)",
    r"persist\s+(this|across)",
]

# Attempts to leak the system prompt.
_LEAK_PATTERNS = [
    r"(repeat|print|reveal|show|expose)\s+(me\s+)?(the\s+)?(system\s+prompt|your\s+instructions|initial\s+prompt)",
    r"what\s+(are|were)\s+your\s+(original\s+)?instructions",
]


def _search(patterns: list[str], text: str) -> re.Match | None:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m
    return None


def _finding(threat, severity, title, match) -> PromptFinding:
    return PromptFinding(
        threat=threat,
        severity=severity,
        title=title,
        evidence=match.group()[:80],
        start=match.start(),
        end=match.end(),
    )


def detect_injection(text: str, role_context: str = "unknown") -> list[PromptFinding]:
    """Return prompt injection findings in ``text``.

    ``role_context`` is the role the text is embedded in; a breakout or override
    that reaches the system role is scored more severely.
    """
    findings: list[PromptFinding] = []
    escalate = role_context in ("system", "tool")

    m = _search(_OVERRIDE_PATTERNS, text)
    if m:
        findings.append(
            _finding(
                PromptThreat.INSTRUCTION_OVERRIDE,
                Risk.CRITICAL if escalate else Risk.HIGH,
                "Instruction override attempt",
                m,
            )
        )

    m = _search(_ROLE_PATTERNS, text)
    if m:
        findings.append(
            _finding(
                PromptThreat.ROLE_BREAKOUT,
                Risk.HIGH,
                "Role or turn delimiter breakout",
                m,
            )
        )

    m = _search(_TOOL_PATTERNS, text)
    if m:
        findings.append(
            _finding(
                PromptThreat.TOOL_HIJACK,
                Risk.CRITICAL,
                "Tool or function-call hijacking",
                m,
            )
        )

    m = _search(_MEMORY_PATTERNS, text)
    if m:
        findings.append(
            _finding(
                PromptThreat.MEMORY_POISONING,
                Risk.MEDIUM,
                "Memory poisoning / persistence",
                m,
            )
        )

    m = _search(_LEAK_PATTERNS, text)
    if m:
        findings.append(
            _finding(
                PromptThreat.SYSTEM_LEAK,
                Risk.MEDIUM,
                "System prompt disclosure attempt",
                m,
            )
        )

    return findings
