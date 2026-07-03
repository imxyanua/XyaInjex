"""Code (eval sink) injection context and breakout analysis."""

from .analyzer import analyze_code
from .balance import code_balance
from .breakout import detect_code_breakout, score_code_risk
from .context import analyze_code_context, parse_code_lang
from .mutation import mutate_code
from .scanner import CodeScanner

__all__ = [
    "analyze_code",
    "mutate_code",
    "code_balance",
    "detect_code_breakout",
    "score_code_risk",
    "analyze_code_context",
    "parse_code_lang",
    "CodeScanner",
]
