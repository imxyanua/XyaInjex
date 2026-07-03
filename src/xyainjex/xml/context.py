"""Classify the XML context surrounding the injection point."""

from __future__ import annotations

from ..models import Context
from ..shell.context import split_template
from .scanner import ATTR_D, ATTR_S, CDATA, COMMENT, TAG, XmlScanner

_TOP_TO_CONTEXT = {
    ATTR_D: Context.XML_ATTR,
    ATTR_S: Context.XML_ATTR,
    TAG: Context.XML_ATTR,
    CDATA: Context.XML_CDATA,
    COMMENT: Context.XML_COMMENT,
}


def analyze_xml_context(template: str) -> Context:
    """Return the XML context surrounding the injection point."""
    parts = split_template(template)
    scanner = XmlScanner()
    scanner.feed(parts.prefix, record=False)
    return _TOP_TO_CONTEXT.get(scanner.state.top, Context.XML_TEXT)
