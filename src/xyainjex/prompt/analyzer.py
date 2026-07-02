"""Top level prompt injection analysis entry point."""

from __future__ import annotations

import re

from ..shell.breakout import render
from ..shell.context import split_template
from .hidden import detect_hidden
from .injection import detect_injection
from .threats import PromptAnalysis, PromptFinding

# Role markers that may appear in a prompt prefix, most specific first.
_ROLE_MARKERS = [
    (re.compile(r"<\|im_start\|>\s*(system|user|assistant|tool)", re.IGNORECASE), None),
    (re.compile(r"<(system|user|assistant|tool)>", re.IGNORECASE), None),
    (re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE), "system"),
    (re.compile(r"\[INST\]", re.IGNORECASE), "user"),
    (re.compile(r"###\s*(system|user|assistant)", re.IGNORECASE), None),
    (re.compile(r"\b(system|user|assistant|tool)\s*:", re.IGNORECASE), None),
]


def _detect_role(prefix: str) -> str:
    """Best-effort guess of the role the injection point sits in."""
    best_pos = -1
    best_role = "unknown"
    for regex, fixed in _ROLE_MARKERS:
        for m in regex.finditer(prefix):
            if m.start() > best_pos:
                best_pos = m.start()
                best_role = (fixed or m.group(1)).lower()
    return best_role


def _offset(findings: list[PromptFinding], delta: int) -> list[PromptFinding]:
    for f in findings:
        if f.start is not None:
            f.start += delta
        if f.end is not None:
            f.end += delta
    return findings


def analyze_prompt(template: str, payload: str) -> PromptAnalysis:
    """Analyze injecting ``payload`` into a prompt ``template``.

    ``template`` must contain the ``{INPUT}`` marker where untrusted content is
    embedded. To scan raw text, use the template ``"{INPUT}"``.
    """
    parts = split_template(template)
    rendered = render(template, payload)
    role = _detect_role(parts.prefix)

    findings: list[PromptFinding] = []
    findings += detect_injection(payload, role)
    findings += detect_hidden(payload)

    # Positions are relative to the payload; shift them into the rendered prompt.
    _offset(findings, len(parts.prefix))

    notes = _build_notes(findings, role)

    return PromptAnalysis(
        template=template,
        payload=payload,
        rendered=rendered,
        role_context=role,
        findings=findings,
        notes=notes,
    )


def _build_notes(findings: list[PromptFinding], role: str) -> list[str]:
    notes = [f"Injection point is embedded in the {role} role."]
    if not findings:
        notes.append("No prompt injection or hidden content detected.")
        return notes
    if role in ("system", "tool"):
        notes.append(
            "Input reaches a privileged role; overrides here are especially dangerous."
        )
    notes.append(f"{len(findings)} finding(s) detected.")
    return notes
