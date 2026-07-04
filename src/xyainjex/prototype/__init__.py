"""Prototype-pollution context and breakout analysis."""

from .analyzer import analyze_prototype
from .balance import prototype_balance
from .breakout import detect_prototype_breakout, score_prototype_risk
from .context import analyze_prototype_context
from .mutation import mutate_prototype

__all__ = [
    "analyze_prototype",
    "mutate_prototype",
    "prototype_balance",
    "detect_prototype_breakout",
    "score_prototype_risk",
    "analyze_prototype_context",
]
