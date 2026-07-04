"""XXE (XML external entity) context and breakout analysis."""

from .analyzer import analyze_xxe
from .balance import xxe_balance
from .breakout import detect_xxe_breakout, score_xxe_risk
from .context import analyze_xxe_context
from .mutation import mutate_xxe

__all__ = [
    "analyze_xxe",
    "mutate_xxe",
    "xxe_balance",
    "detect_xxe_breakout",
    "score_xxe_risk",
    "analyze_xxe_context",
]
