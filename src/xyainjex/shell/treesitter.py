"""Optional tree-sitter bash parser for cross-checking the lexical shell model.

Install with the ``parser`` extra::

    pip install -e ".[parser]"

Tree-sitter only applies to POSIX-style shell commands. It is a research spike
to compare top-level command counts against the lexical analyzer, not a
replacement parser for cmd, powershell, or fish.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..dialects import Dialect
from ..shell.context import split_template
from .breakout import detect_breakout

try:
    import tree_sitter_bash as _tsbash
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - optional dependency
    _tsbash = None
    Language = None  # type: ignore[assignment,misc]
    Parser = None  # type: ignore[assignment,misc]

_PARSER: Parser | None = None


def available() -> bool:
    """Return True when tree-sitter and tree-sitter-bash are installed."""
    return _tsbash is not None


def _parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        if not available():
            raise RuntimeError(
                'tree-sitter is not installed; use: pip install -e ".[parser]"'
            )
        language = Language(_tsbash.language())
        _PARSER = Parser(language)
    return _PARSER


def top_level_command_count(source: str) -> int | None:
    """Count top-level ``command`` nodes in a bash program, or None if unavailable."""
    if not available():
        return None
    tree = _parser().parse(source.encode("utf-8"))
    root = tree.root_node
    return sum(
        1
        for i in range(root.named_child_count)
        if root.named_child(i).type == "command"
    )


def rendered_command(template: str, payload: str) -> str:
    """Render a template with a payload substituted at ``{INPUT}``."""
    parts = split_template(template)
    return parts.prefix + payload + parts.suffix


@dataclass
class TreesitterCompareResult:
    template: str
    payload: str
    rendered: str
    baseline_commands: int
    actual_commands: int
    lexical_injected: bool
    treesitter_injected: bool
    agrees: bool

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "payload": self.payload,
            "rendered": self.rendered,
            "baseline_commands": self.baseline_commands,
            "actual_commands": self.actual_commands,
            "lexical_injected": self.lexical_injected,
            "treesitter_injected": self.treesitter_injected,
            "agrees": self.agrees,
        }


def compare_posix(template: str, payload: str) -> TreesitterCompareResult | None:
    """Compare lexical posix breakout analysis with tree-sitter bash parsing."""
    if not available():
        return None
    rendered = rendered_command(template, payload)
    baseline = top_level_command_count(rendered_command(template, "xya_probe")) or 0
    actual = top_level_command_count(rendered) or 0
    lexical = detect_breakout(template, payload, Dialect.POSIX)
    treesitter_injected = actual > baseline
    return TreesitterCompareResult(
        template=template,
        payload=payload,
        rendered=rendered,
        baseline_commands=baseline,
        actual_commands=actual,
        lexical_injected=lexical.command_injected,
        treesitter_injected=treesitter_injected,
        agrees=lexical.command_injected == treesitter_injected,
    )
