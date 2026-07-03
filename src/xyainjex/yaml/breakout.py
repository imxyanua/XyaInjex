"""Detect how a payload breaks out of a YAML context."""

from __future__ import annotations

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_yaml_context
from .scanner import YamlScanner

_QUOTED = (Context.YAML_SINGLE, Context.YAML_DOUBLE)


def detect_yaml_breakout(template: str, payload: str) -> Breakout:
    """Analyze the YAML breakout produced by injecting ``payload``.

    ``command_injected`` means the payload injected new YAML structure: a
    deserialization tag (RCE), a new key, or a new line, after escaping any
    quoted scalar.
    """
    parts = split_template(template)
    context = analyze_yaml_context(template)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    escape = YamlScanner()
    escape.feed(prefix, record=False)
    start_depth = escape.state.depth
    escape.reset_min()
    escape.feed(payload, offset=payload_start, record=False)
    escaped = escape.state.min_depth < start_depth

    rendered = prefix + payload + parts.suffix
    st = YamlScanner().feed(rendered, record=True)
    tokens = [
        ev.token for ev in st.separators if payload_start <= ev.index < payload_end
    ]
    has_tag = "tag" in tokens
    structural = "newline" in tokens or "key" in tokens

    if context in _QUOTED:
        quote_closed = escaped
        command_injected = quote_closed and (has_tag or structural)
    else:  # plain scalar position
        quote_closed = False
        command_injected = has_tag or structural

    first_index = None
    for ev in st.separators:
        if payload_start <= ev.index < payload_end:
            first_index = ev.index
            break

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=False,
        separators=tokens,
        commands_created=tokens.count("key"),
        breakout_index=first_index,
    )


def score_yaml_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a YAML breakout and syntax validity to a risk rating."""
    if breakout.command_injected and "tag" in breakout.separators:
        # A deserialization tag reaches code execution under an unsafe loader.
        return Risk.CRITICAL
    if breakout.command_injected:
        # Structure or key injection: configuration tampering.
        return Risk.HIGH if syntax_valid else Risk.MEDIUM
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
