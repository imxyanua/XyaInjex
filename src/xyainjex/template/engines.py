"""Delimiter specifications for supported template engines."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import TemplateEngine

# Region kinds used internally by the scanner.
EXPR = "expr"
STMT = "stmt"
COMMENT = "comment"


@dataclass(frozen=True)
class RegionDef:
    kind: str  # EXPR | STMT | COMMENT
    open: str
    close: str


@dataclass(frozen=True)
class TemplateSpec:
    engine: TemplateEngine
    regions: tuple[RegionDef, ...]

    def opens_longest_first(self) -> list[RegionDef]:
        return sorted(self.regions, key=lambda r: len(r.open), reverse=True)


# Jinja2, Twig, Liquid, and Nunjucks share the same delimiters.
_CURLY = (
    RegionDef(EXPR, "{{", "}}"),
    RegionDef(STMT, "{%", "%}"),
    RegionDef(COMMENT, "{#", "#}"),
)

_SPECS: dict[TemplateEngine, TemplateSpec] = {
    TemplateEngine.JINJA2: TemplateSpec(TemplateEngine.JINJA2, _CURLY),
    TemplateEngine.TWIG: TemplateSpec(TemplateEngine.TWIG, _CURLY),
    TemplateEngine.LIQUID: TemplateSpec(TemplateEngine.LIQUID, _CURLY),
    TemplateEngine.NUNJUCKS: TemplateSpec(TemplateEngine.NUNJUCKS, _CURLY),
    TemplateEngine.FREEMARKER: TemplateSpec(
        TemplateEngine.FREEMARKER,
        (
            RegionDef(EXPR, "${", "}"),
            RegionDef(COMMENT, "<#--", "-->"),
        ),
    ),
    TemplateEngine.ERB: TemplateSpec(
        TemplateEngine.ERB,
        (
            RegionDef(COMMENT, "<%#", "%>"),
            RegionDef(EXPR, "<%=", "%>"),
            RegionDef(STMT, "<%", "%>"),
        ),
    ),
    TemplateEngine.HANDLEBARS: TemplateSpec(
        TemplateEngine.HANDLEBARS,
        (
            RegionDef(COMMENT, "{{!", "}}"),
            RegionDef(EXPR, "{{{", "}}}"),
            RegionDef(EXPR, "{{", "}}"),
        ),
    ),
    TemplateEngine.VELOCITY: TemplateSpec(
        TemplateEngine.VELOCITY,
        (RegionDef(EXPR, "${", "}"),),
    ),
}


def get_template_spec(engine: TemplateEngine) -> TemplateSpec:
    return _SPECS[engine]
