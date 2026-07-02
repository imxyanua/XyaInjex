"""Core data models shared across the XyaInjex engine."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Context(Enum):
    """Lexical context that surrounds the injection point in a command."""

    UNQUOTED = "unquoted"
    SINGLE_QUOTE = "single_quote"
    DOUBLE_QUOTE = "double_quote"
    BACKTICK = "backtick"
    COMMAND_SUBSTITUTION = "command_substitution"
    ARITHMETIC = "arithmetic"

    @property
    def quote_char(self) -> str | None:
        """The character that closes this context, if any."""
        return {
            Context.SINGLE_QUOTE: "'",
            Context.DOUBLE_QUOTE: '"',
            Context.BACKTICK: "`",
        }.get(self)


class Risk(Enum):
    """Overall severity of an analyzed injection."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Balance:
    """Result of the syntax balance engine over a rendered command."""

    quotes_balanced: bool
    single_quote_open: bool
    double_quote_open: bool
    backtick_open: bool
    unbalanced_pairs: dict[str, int] = field(default_factory=dict)

    @property
    def syntax_valid(self) -> bool:
        return self.quotes_balanced and not self.unbalanced_pairs


@dataclass
class Breakout:
    """Description of how, and whether, the payload escaped its context."""

    context: Context
    quote_closed: bool
    command_injected: bool
    comment_terminated: bool
    separators: list[str] = field(default_factory=list)
    commands_created: int = 0
    breakout_index: int | None = None


@dataclass
class AnalysisResult:
    """Full verdict produced by :func:`xyainjex.analyze`."""

    template: str
    payload: str
    rendered: str
    context: Context
    breakout: Breakout
    balance: Balance
    risk: Risk
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["context"] = self.context.value
        data["risk"] = self.risk.value
        data["breakout"]["context"] = self.breakout.context.value
        data["syntax_valid"] = self.balance.syntax_valid
        return data
