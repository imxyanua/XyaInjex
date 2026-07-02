"""Server-side template injection (SSTI) context and breakout analysis."""

from .analyzer import analyze_template
from .balance import template_balance
from .breakout import detect_template_breakout, score_template_risk
from .context import analyze_template_context
from .engines import get_template_spec
from .mutation import mutate_template
from .scanner import TemplateScanner

__all__ = [
    "analyze_template",
    "mutate_template",
    "template_balance",
    "detect_template_breakout",
    "score_template_risk",
    "analyze_template_context",
    "get_template_spec",
    "TemplateScanner",
]
