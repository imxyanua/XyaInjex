"""Detect how a payload breaks out of a SQL context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk, SqlDialect
from ..shell.context import split_template
from .context import analyze_sql_context
from .scanner import SqlScanner

_QUOTED = (Context.SQL_STRING, Context.SQL_IDENTIFIER)


def detect_sql_breakout(
    template: str, payload: str, dialect: SqlDialect = SqlDialect.MYSQL
) -> Breakout:
    """Analyze the SQL breakout produced by injecting ``payload``.

    The ``command_injected`` field means SQL code (a keyword, operator, stacked
    query, or comment) was introduced where the template expected data.
    """
    parts = split_template(template)
    context = analyze_sql_context(template, dialect)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    # Two phase scan to measure how far the payload pops below its context.
    escape_scanner = SqlScanner(dialect)
    escape_scanner.feed(prefix, record=False)
    start_depth = escape_scanner.state.depth
    escape_scanner.reset_min()
    escape_scanner.feed(payload, offset=payload_start, record=False)
    escaped = escape_scanner.state.min_depth < start_depth

    # Full scan of the rendered statement.
    rendered = prefix + payload + parts.suffix
    st = SqlScanner(dialect).feed(rendered, record=True)

    injected = [
        ev for ev in st.separators if ev.stack_depth == 0 and ev.index >= payload_start
    ]
    tokens = [ev.token for ev in injected]

    comment_terminated = (
        st.comment is not None
        and st.comment.index >= payload_start
        and st.comment.index < payload_end
        and len(parts.suffix) > 0
    )

    quote_closed = escaped if context in _QUOTED else False

    if context in _QUOTED:
        command_injected = quote_closed and (bool(injected) or comment_terminated)
    else:  # numeric or unquoted expression position
        command_injected = bool(injected)

    if injected:
        breakout_index = injected[0].index
    elif comment_terminated and st.comment is not None:
        breakout_index = st.comment.index
    else:
        breakout_index = None

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=comment_terminated,
        separators=tokens,
        commands_created=len(injected),
        breakout_index=breakout_index,
    )


def score_sql_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a SQL breakout and syntax validity to an overall risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH

    if breakout.quote_closed:
        # Escaped the string but introduced no SQL code yet.
        return Risk.MEDIUM

    return Risk.LOW
