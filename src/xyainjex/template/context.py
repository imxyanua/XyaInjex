"""Classify the template context surrounding the injection point."""

from __future__ import annotations

from ..models import Context, TemplateEngine
from ..shell.context import split_template
from .engines import COMMENT, EXPR, STMT, get_template_spec
from .scanner import TemplateScanner

_KIND_TO_CONTEXT = {
    "text": Context.TEMPLATE_TEXT,
    EXPR: Context.TEMPLATE_EXPRESSION,
    STMT: Context.TEMPLATE_STATEMENT,
    COMMENT: Context.TEMPLATE_COMMENT,
}


def analyze_template_context(
    template: str, engine: TemplateEngine = TemplateEngine.JINJA2
) -> Context:
    """Return the template context surrounding the injection point."""
    parts = split_template(template)
    scanner = TemplateScanner(get_template_spec(engine))
    scanner.feed(parts.prefix, record=False)
    st = scanner.state
    if st.kind in (EXPR, STMT) and st.in_string is not None:
        return Context.TEMPLATE_STRING
    return _KIND_TO_CONTEXT.get(st.kind, Context.TEMPLATE_TEXT)
