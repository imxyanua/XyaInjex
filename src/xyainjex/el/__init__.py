"""Expression language (EL / OGNL / SpEL / JNDI) injection analysis."""

from .analyzer import analyze_el
from .balance import el_balance
from .breakout import detect_el_breakout, score_el_risk
from .context import analyze_el_context
from .mutation import mutate_el
from .scanner import ElScanner

__all__ = [
    "analyze_el",
    "mutate_el",
    "el_balance",
    "detect_el_breakout",
    "score_el_risk",
    "analyze_el_context",
    "ElScanner",
]
