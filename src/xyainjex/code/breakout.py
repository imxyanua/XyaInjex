"""Detect how a payload breaks out of a code context."""

from __future__ import annotations

from ..models import Breakout, CodeLang, Context, Risk
from ..shell.context import split_template
from .context import analyze_code_context
from .scanner import CodeScanner


def detect_code_breakout(
    template: str, payload: str, lang: CodeLang = CodeLang.PYTHON
) -> Breakout:
    """Analyze the code breakout produced by injecting ``payload``.

    ``command_injected`` means the payload reached code position and introduced a
    new statement (``;``) or a sink identifier (``eval``, ``system``, ...).
    ``substitution_injected`` means the payload opened a ``${...}`` template
    substitution that executes.
    """
    parts = split_template(template)
    context = analyze_code_context(template, lang)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = CodeScanner(lang)
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = CodeScanner(lang).feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]
    has_semicolon = ";" in tokens
    has_sink = any(t != ";" for t in tokens)
    substitution = any(payload_start <= idx < payload_end for idx in st.sub_opens)

    comment_terminated = (
        st.comment is not None
        and payload_start <= st.comment.index < payload_end
        and len(parts.suffix) > 0
    )

    if context == Context.CODE_STRING:
        quote_closed = escaped
        command_injected = quote_closed and (has_semicolon or has_sink)
    elif context == Context.CODE_TEMPLATE:
        quote_closed = escaped
        command_injected = substitution or (escaped and (has_semicolon or has_sink))
    else:  # expression position: already code
        quote_closed = False
        command_injected = has_semicolon or has_sink

    index = None
    if tokens:
        for ev in st.separators:
            if payload_start <= ev.index < payload_end:
                index = ev.index
                break
    elif substitution:
        index = next(i for i in st.sub_opens if payload_start <= i < payload_end)

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=comment_terminated,
        separators=tokens,
        commands_created=sum(1 for t in tokens if t == ";"),
        breakout_index=index,
        substitution_injected=substitution,
    )


def score_code_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a code breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if breakout.substitution_injected:
        return Risk.HIGH
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
