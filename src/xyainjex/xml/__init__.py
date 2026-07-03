"""XML injection context and breakout analysis."""

from .analyzer import analyze_xml
from .balance import xml_balance
from .breakout import detect_xml_breakout, score_xml_risk
from .context import analyze_xml_context
from .mutation import mutate_xml
from .scanner import XmlScanner

__all__ = [
    "analyze_xml",
    "mutate_xml",
    "xml_balance",
    "detect_xml_breakout",
    "score_xml_risk",
    "analyze_xml_context",
    "XmlScanner",
]
