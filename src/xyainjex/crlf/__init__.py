"""CRLF (HTTP header / log) injection context and breakout analysis."""

from .analyzer import analyze_crlf
from .balance import crlf_balance
from .breakout import detect_crlf_breakout, score_crlf_risk
from .context import analyze_crlf_context, parse_crlf_kind
from .mutation import mutate_crlf

__all__ = [
    "analyze_crlf",
    "mutate_crlf",
    "crlf_balance",
    "detect_crlf_breakout",
    "score_crlf_risk",
    "analyze_crlf_context",
    "parse_crlf_kind",
]
