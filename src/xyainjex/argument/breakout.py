"""Detect argument / option injection breakout in a subprocess argument."""

from __future__ import annotations

import re

from ..models import Breakout, Context, Risk
from ..shell.context import split_template
from .context import analyze_argument_context

# An option at the start of the payload, or after whitespace (a new argument).
_LEADING = re.compile(r"^\s*(-{1,2}[A-Za-z][\w-]*)")
_NEW = re.compile(r"\s(-{1,2}[A-Za-z][\w-]*)")
_END_OF_OPTIONS = re.compile(r"(^|\s)--(\s|$)")

# Flag names (dashes stripped) that reach command execution across common tools
# (git, tar, find, ...).
_RCE_FLAGS = {"upload-pack", "receive-pack", "checkpoint-action", "exec", "use"}
# Flag names that read or write an arbitrary file (curl, wget, ...).
_FILE_FLAGS = {
    "o",
    "output",
    "output-document",
    "k",
    "config",
    "remote-name",
    "remote-header-name",
    "trace",
    "dump-header",
}
# Option *values* that reach command execution (ssh -o ProxyCommand=..., ...).
_RCE_VALUE = re.compile(
    r"(ProxyCommand|use-askpass|LocalCommand|PermitLocalCommand)\s*=",
    re.IGNORECASE,
)


def _classify(option: str) -> str:
    name = option.lstrip("-").lower()
    if name in _RCE_FLAGS:
        return "rce-flag"
    if name in _FILE_FLAGS:
        return "file-flag"
    return "option"


def detect_argument_breakout(template: str, payload: str) -> Breakout:
    """Analyze the argument-injection breakout produced by injecting ``payload``.

    ``command_injected`` means the payload lands in its own argument slot and
    starts with a ``-``, so the program parses it as an option.
    """
    context = analyze_argument_context(template)
    prefix = split_template(template).prefix

    # A leading "--" is the end-of-options separator: everything after it is
    # positional, so it neutralizes rather than injects an option.
    if re.match(r"^\s*--(\s|$)", payload):
        return Breakout(
            context=context,
            quote_closed=False,
            command_injected=False,
            comment_terminated=False,
            separators=["end-of-options"],
            commands_created=0,
            breakout_index=None,
        )

    tokens: set[str] = set()

    leading = _LEADING.match(payload)
    options = list(_NEW.findall(payload))
    if leading:
        options.insert(0, leading.group(1))

    for opt in options:
        tokens.add(_classify(opt))
    if _RCE_VALUE.search(payload):
        tokens.add("rce-flag")

    if leading:
        tokens.add("option-injection")
    if _NEW.search(payload):
        tokens.add("new-option")
    if _END_OF_OPTIONS.search(payload):
        tokens.add("end-of-options")

    if context == Context.ARG_OPTION:
        command_injected = leading is not None
    else:
        # Glued to a preceding token: injection needs the value to be word-split.
        command_injected = False

    index = len(prefix) + (leading.start(1) if leading else 0) if leading else None

    return Breakout(
        context=context,
        quote_closed=command_injected,
        command_injected=command_injected,
        comment_terminated=False,
        separators=_order_tokens(tokens),
        commands_created=len(options),
        breakout_index=index,
    )


_TOKEN_ORDER = [
    "rce-flag",
    "file-flag",
    "option-injection",
    "new-option",
    "option",
    "end-of-options",
]


def _order_tokens(tokens: set[str]) -> list[str]:
    ordered = [t for t in _TOKEN_ORDER if t in tokens]
    ordered += sorted(t for t in tokens if t not in _TOKEN_ORDER)
    return ordered


def score_argument_risk(breakout: Breakout, syntax_valid: bool = True) -> Risk:
    """Map an argument-injection breakout to a risk rating."""
    seps = set(breakout.separators)
    if not breakout.command_injected:
        # An option pattern is present but glued to a token (needs word split).
        if seps & {"option-injection", "new-option"}:
            return Risk.MEDIUM
        return Risk.LOW
    if "rce-flag" in seps:
        # A flag that reaches command execution (--upload-pack, -exec, ...).
        return Risk.CRITICAL
    if "file-flag" in seps:
        # A flag that reads or writes an arbitrary file (-o, --config, ...).
        return Risk.HIGH
    return Risk.MEDIUM
