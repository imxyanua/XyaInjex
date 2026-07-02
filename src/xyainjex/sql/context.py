"""Classify the SQL context surrounding the injection point."""

from __future__ import annotations

from ..models import Context, SqlDialect
from ..scan import BACKTICK, DOUBLE, SINGLE
from ..shell.context import split_template
from .scanner import SqlScanner


def _frame_to_context(kind: str | None, dialect: SqlDialect) -> Context:
    if kind == SINGLE:
        return Context.SQL_STRING
    if kind == DOUBLE:
        # MySQL treats double quotes as string literals by default; other
        # dialects treat them as quoted identifiers.
        return (
            Context.SQL_STRING
            if dialect == SqlDialect.MYSQL
            else Context.SQL_IDENTIFIER
        )
    if kind == BACKTICK:
        return Context.SQL_IDENTIFIER
    # Outside any quote the input sits in a numeric or expression position.
    return Context.SQL_NUMERIC


def analyze_sql_context(
    template: str, dialect: SqlDialect = SqlDialect.MYSQL
) -> Context:
    """Return the SQL context surrounding the injection point."""
    parts = split_template(template)
    scanner = SqlScanner(dialect)
    scanner.feed(parts.prefix, record=False)
    return _frame_to_context(scanner.state.top, dialect)
