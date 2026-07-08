"""Template engine parser-divergence regression cases."""

from __future__ import annotations

from .models import CorpusCase

TEMPLATE_DIALECTS = [
    "jinja2",
    "twig",
    "liquid",
    "nunjucks",
    "freemarker",
    "erb",
    "handlebars",
    "velocity",
    "mako",
]

TEMPLATE_CASES: tuple[CorpusCase, ...] = (
    CorpusCase(
        id="jinja-mustache-hello",
        template="Hello {{ {INPUT} }}",
        payload="{{7*7}}",
        note="Mustache-style {{ }} SSTI; freemarker, erb, velocity, and mako disagree.",
        divergent=True,
    ),
    CorpusCase(
        id="jinja-config-access",
        template="Hello {{ {INPUT} }}",
        payload="{{ config }}",
        note="Config/object access via double-brace syntax.",
        divergent=True,
    ),
    CorpusCase(
        id="freemarker-dollar",
        template="{{ {INPUT} }}",
        payload="${7*7}",
        note="Dollar-brace math is native to freemarker/velocity/mako but not erb.",
        divergent=True,
    ),
    CorpusCase(
        id="hash-expression",
        template="{{ {INPUT} }}",
        payload="#{7*7}",
        note="Hash-curly expression syntax accepted unevenly across engines.",
        divergent=True,
    ),
    CorpusCase(
        id="set-tag-handlebars-only",
        template="{% set x = '{INPUT}' %}",
        payload="{{7*7}}",
        note="Only handlebars treats the follow-on mustache as top-level code here.",
        divergent=True,
    ),
    CorpusCase(
        id="single-quote-breakout",
        template="{{ '{INPUT}' }}",
        payload="'}{{7*7}}",
        note="Break out of a quoted mustache string.",
        divergent=True,
    ),
    CorpusCase(
        id="raw-block-breakout",
        template="{% raw %}{INPUT}{% endraw %}",
        payload="{{7*7}}",
        note="Escape a raw block and inject mustache code afterward.",
        divergent=True,
    ),
    CorpusCase(
        id="tag-logic-inject",
        template="{{ {INPUT} }}",
        payload="{% if 1 %}x{% endif %}",
        note="Inject template logic tags after a mustache sink.",
        divergent=True,
    ),
    CorpusCase(
        id="filter-safe-bypass",
        template="{{ {INPUT} | safe }}",
        payload="{{7*7}}",
        note="Expression inside a filtered mustache slot.",
        divergent=True,
    ),
    CorpusCase(
        id="freemarker-bracket-dollar",
        template="[[{INPUT}]]",
        payload="${7*7}",
        note="Freemarker bracket refs vs mustache engines on dollar syntax.",
        divergent=True,
    ),
    CorpusCase(
        id="plain-text-literal",
        template="Hello {INPUT}",
        payload="world",
        note="Plain text substitution with no template metacharacters.",
        divergent=False,
    ),
    CorpusCase(
        id="raw-block-contained",
        template="{% raw %}{INPUT}{% endraw %}",
        payload="hello",
        note="Payload stays inside a raw block on every engine.",
        divergent=False,
    ),
    CorpusCase(
        id="bracket-literal",
        template="[[{INPUT}]]",
        payload="value",
        note="Benign freemarker-style bracket reference text.",
        divergent=False,
    ),
)
