"""Detect how a payload breaks out of its shell context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from .context import split_template, analyze_context
from .scanner import ShellScanner


def render(template: str, payload: str) -> str:
    """Substitute ``payload`` into the template's ``{INPUT}`` marker."""
    parts = split_template(template)
    return parts.prefix + payload + parts.suffix


def detect_breakout(template: str, payload: str) -> Breakout:
    """Analyze the breakout produced by injecting ``payload`` into ``template``."""
    parts = split_template(template)
    context = analyze_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    # Two phase scan to measure how far the payload pops below its context.
    escape_scanner = ShellScanner()
    escape_scanner.feed(prefix, record=False)
    start_depth = escape_scanner.state.depth
    escape_scanner.reset_min()
    escape_scanner.feed(payload, offset=payload_start, record=False)
    payload_min = escape_scanner.state.min_depth
    escaped_context = payload_min < start_depth

    # Full scan of the rendered command for separators and comments.
    rendered = prefix + payload + parts.suffix
    scanner = ShellScanner()
    st = scanner.feed(rendered, record=True)

    # Separators that execute at the shell top level and originate at or after
    # the injection point are injected command boundaries.
    injected = [
        ev
        for ev in st.separators
        if ev.stack_depth == 0 and ev.index >= payload_start
    ]
    separators = [ev.token for ev in injected]
    command_injected = len(injected) > 0

    comment_terminated = (
        st.comment is not None
        and st.comment.stack_depth == 0
        and st.comment.index >= payload_start
        and st.comment.index < payload_end
        and len(parts.suffix) > 0
    )

    if context == Context.UNQUOTED:
        quote_closed = False
    else:
        quote_closed = escaped_context

    breakout_index = injected[0].index if injected else None

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=comment_terminated,
        separators=separators,
        commands_created=len(injected),
        breakout_index=breakout_index,
    )


def score_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a breakout and syntax validity to an overall risk rating."""
    if breakout.command_injected:
        if syntax_valid:
            return Risk.CRITICAL
        # A command boundary was created but the residual command is broken;
        # still commonly exploitable but less reliable.
        return Risk.HIGH

    if breakout.context == Context.UNQUOTED:
        # Unquoted input needs no quote closure; argument level control is
        # already dangerous even without an explicit separator.
        return Risk.MEDIUM

    if breakout.quote_closed:
        # The surrounding quote was escaped but no command separator landed at
        # the top level: argument injection rather than command injection.
        return Risk.MEDIUM

    return Risk.LOW
