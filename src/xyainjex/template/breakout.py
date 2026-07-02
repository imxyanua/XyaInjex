"""Detect how a payload breaks out into template execution."""

from __future__ import annotations

from ..models import Breakout, Context, Risk, TemplateEngine
from ..shell.context import split_template
from .context import analyze_template_context
from .engines import EXPR, STMT, get_template_spec
from .scanner import TemplateScanner

_EXECUTABLE = (EXPR, STMT)
_ALREADY_CODE = (Context.TEMPLATE_EXPRESSION, Context.TEMPLATE_STATEMENT)


def detect_template_breakout(
    template: str, payload: str, engine: TemplateEngine = TemplateEngine.JINJA2
) -> Breakout:
    """Analyze the SSTI breakout produced by injecting ``payload``.

    ``command_injected`` means the payload lands in, or opens, an executable
    template region (an expression or statement), which is what makes SSTI
    reach server-side evaluation.
    """
    spec = get_template_spec(engine)
    parts = split_template(template)
    context = analyze_template_context(template, engine)

    prefix = parts.prefix
    payload_start = len(prefix)
    payload_end = payload_start + len(payload)

    # Escape detection for a string literal inside an expression.
    esc = TemplateScanner(spec)
    esc.feed(prefix, record=False)
    esc.state.string_closed = False
    esc.feed(payload, offset=payload_start, record=False)
    string_escaped = esc.state.string_closed

    # Full region scan of the rendered template.
    rendered = prefix + payload + parts.suffix
    st = TemplateScanner(spec).feed(rendered, record=True)
    opened_regions = [
        r
        for r in st.regions
        if r.kind in _EXECUTABLE and payload_start <= r.start < payload_end
    ]
    # Only a closed region actually evaluates; an unclosed one is a syntax error.
    injected_regions = [r for r in opened_regions if r.end is not None]

    quote_closed = False
    separators: list[str] = []

    if context in (Context.TEMPLATE_TEXT, Context.TEMPLATE_COMMENT):
        command_injected = bool(injected_regions)
        separators = list(dict.fromkeys(r.open for r in opened_regions))
    elif context in _ALREADY_CODE:
        # The injection point is already inside an evaluated region.
        command_injected = True
    elif context == Context.TEMPLATE_STRING:
        quote_closed = string_escaped
        command_injected = string_escaped
    else:
        command_injected = False

    if injected_regions:
        breakout_index = injected_regions[0].start
    elif command_injected:
        breakout_index = payload_start
    else:
        breakout_index = None

    return Breakout(
        context=context,
        quote_closed=quote_closed,
        command_injected=command_injected,
        comment_terminated=False,
        separators=separators,
        commands_created=len(injected_regions),
        breakout_index=breakout_index,
    )


def score_template_risk(breakout: Breakout, syntax_valid: bool) -> Risk:
    """Map a template breakout and syntax validity to a risk rating."""
    if breakout.command_injected:
        return Risk.CRITICAL if syntax_valid else Risk.HIGH
    if breakout.separators:
        # An executable region was opened but not completed by this payload.
        return Risk.MEDIUM
    if breakout.quote_closed:
        return Risk.MEDIUM
    return Risk.LOW
