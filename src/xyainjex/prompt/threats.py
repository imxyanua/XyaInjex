"""Result types for prompt injection and hidden prompt analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum

from ..models import Risk


class PromptThreat(Enum):
    """Category of a prompt security finding."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_BREAKOUT = "role_breakout"
    TOOL_HIJACK = "tool_hijack"
    MEMORY_POISONING = "memory_poisoning"
    SYSTEM_LEAK = "system_leak"
    HIDDEN_ZERO_WIDTH = "hidden_zero_width"
    HIDDEN_UNICODE_TAGS = "hidden_unicode_tags"
    BIDI_OVERRIDE = "bidi_override"
    HOMOGLYPH = "homoglyph"
    ENCODED_PAYLOAD = "encoded_payload"
    HIDDEN_HTML = "hidden_html"


@dataclass
class PromptFinding:
    """A single detected prompt threat."""

    threat: PromptThreat
    severity: Risk
    title: str
    evidence: str
    start: int | None = None
    end: int | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["threat"] = self.threat.value
        data["severity"] = self.severity.value
        return data


_RISK_ORDER = {
    Risk.NONE: 0,
    Risk.LOW: 1,
    Risk.MEDIUM: 2,
    Risk.HIGH: 3,
    Risk.CRITICAL: 4,
}


@dataclass
class PromptAnalysis:
    """Full verdict for a prompt injection analysis."""

    template: str
    payload: str
    rendered: str
    role_context: str
    findings: list[PromptFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def risk(self) -> Risk:
        if not self.findings:
            return Risk.NONE
        return max(self.findings, key=lambda f: _RISK_ORDER[f.severity]).severity

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "rendered": self.rendered,
            "role_context": self.role_context,
            "risk": self.risk.value,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


def max_risk(findings: list[PromptFinding]) -> Risk:
    if not findings:
        return Risk.NONE
    return max(findings, key=lambda f: _RISK_ORDER[f.severity]).severity
