import json

import pytest

from xyainjex import (
    Context,
    TemplateEngine,
    analyze_template,
    mutate_template,
    parse_template_engine,
)
from xyainjex.cli import main
from xyainjex.template.balance import template_balance
from xyainjex.template.context import analyze_template_context

TEXT_TMPL = "Hello {INPUT}"
EXPR_TMPL = "{{ user.{INPUT} }}"
STMT_TMPL = "{% if {INPUT} %}"
STRING_TMPL = '{{ "{INPUT}" }}'
COMMENT_TMPL = "Hi {# {INPUT} #}"


# --- context ---


def test_text_context():
    assert analyze_template_context(TEXT_TMPL) == Context.TEMPLATE_TEXT


def test_expression_context():
    assert analyze_template_context(EXPR_TMPL) == Context.TEMPLATE_EXPRESSION


def test_statement_context():
    assert analyze_template_context(STMT_TMPL) == Context.TEMPLATE_STATEMENT


def test_string_context():
    assert analyze_template_context(STRING_TMPL) == Context.TEMPLATE_STRING


def test_comment_context():
    assert analyze_template_context(COMMENT_TMPL) == Context.TEMPLATE_COMMENT


def test_erb_text_context():
    assert (
        analyze_template_context("Hi {INPUT}", TemplateEngine.ERB)
        == Context.TEMPLATE_TEXT
    )


# --- balance ---


def test_balanced_template():
    assert template_balance("Hello {{ name }}").syntax_valid


def test_unclosed_expression_unbalanced():
    b = template_balance("Hello {{ name")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("{{ }}") == 1


def test_string_inside_expression_balances():
    assert template_balance('{{ "a }} b" }}').syntax_valid


# --- breakout ---


def test_text_ssti_breakout():
    r = analyze_template(TEXT_TMPL, "{{7*7}}")
    assert r.context == Context.TEMPLATE_TEXT
    assert r.breakout.command_injected
    assert "{{" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_text_plain_no_breakout():
    r = analyze_template(TEXT_TMPL, "just text")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_expression_context_is_injected():
    r = analyze_template(EXPR_TMPL, "name")
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_string_context_no_escape():
    r = analyze_template(STRING_TMPL, "safe")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_string_context_escape():
    r = analyze_template(STRING_TMPL, 'x" + config + "')
    assert r.breakout.quote_closed
    assert r.breakout.command_injected


def test_comment_escape_breakout():
    r = analyze_template(COMMENT_TMPL, "#}{{7*7}}")
    assert r.breakout.command_injected
    assert "{{" in r.breakout.separators


def test_unclosed_expression_is_medium():
    r = analyze_template(TEXT_TMPL, "{{7*7")
    assert not r.breakout.command_injected
    assert not r.balance.syntax_valid
    assert r.risk.value == "MEDIUM"


def test_freemarker_breakout():
    r = analyze_template("Hello {INPUT}", "${7*7}", TemplateEngine.FREEMARKER)
    assert r.breakout.command_injected
    assert "${" in r.breakout.separators


def test_erb_breakout():
    r = analyze_template("Hello {INPUT}", "<%= 7*7 %>", TemplateEngine.ERB)
    assert r.breakout.command_injected
    assert "<%=" in r.breakout.separators


@pytest.mark.parametrize(
    "engine,payload,opener",
    [
        (TemplateEngine.BLADE, "{{7*7}}", "{{"),
        (TemplateEngine.BLADE, "{!! 7*7 !!}", "{!!"),
        (TemplateEngine.MAKO, "${7*7}", "${"),
        (TemplateEngine.MAKO, "<% x=7 %>", "<%"),
        (TemplateEngine.RAZOR, "@(7*7)", "@("),
        (TemplateEngine.GOTEMPLATE, "{{7*7}}", "{{"),
        (TemplateEngine.EJS, "<%= 7*7 %>", "<%="),
        (TemplateEngine.EJS, "<%- 7*7 %>", "<%-"),
        (TemplateEngine.THYMELEAF, "[[${7*7}]]", "[["),
    ],
)
def test_additional_engine_breakouts(engine, payload, opener):
    r = analyze_template("Hello {INPUT}", payload, engine)
    assert r.breakout.command_injected
    assert opener in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_blade_comment_escape():
    r = analyze_template("Hi {{-- {INPUT} --}}", "--}}{{7*7}}", TemplateEngine.BLADE)
    assert r.context == Context.TEMPLATE_COMMENT
    assert r.breakout.command_injected


def test_razor_expression_context():
    from xyainjex.template.context import analyze_template_context

    assert (
        analyze_template_context("@( {INPUT} )", TemplateEngine.RAZOR)
        == Context.TEMPLATE_EXPRESSION
    )


def test_blade_plain_text_no_breakout():
    r = analyze_template("Hello {INPUT}", "plain", TemplateEngine.BLADE)
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_new_engine_aliases():
    assert parse_template_engine("laravel") == TemplateEngine.BLADE
    assert parse_template_engine("go") == TemplateEngine.GOTEMPLATE
    assert parse_template_engine("cshtml") == TemplateEngine.RAZOR


def test_string_close_inside_expression_not_a_delimiter():
    # A closing delimiter inside a string literal must not end the expression.
    r = analyze_template("Value {INPUT}", '{{ "}}" + config }}')
    assert r.breakout.command_injected
    assert r.balance.syntax_valid


# --- mutation ---


def test_mutate_text_context():
    result = mutate_template(TEXT_TMPL)
    assert result.context == Context.TEMPLATE_TEXT
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_dict_shape():
    data = mutate_template(TEXT_TMPL).to_dict()
    assert data["engine"] == "jinja2"
    assert isinstance(data["high_probability"], list)


# --- dialect parsing and CLI ---


def test_parse_template_engine_aliases():
    assert parse_template_engine("jinja") == TemplateEngine.JINJA2
    assert parse_template_engine("hbs") == TemplateEngine.HANDLEBARS
    assert parse_template_engine("ftl") == TemplateEngine.FREEMARKER


def test_result_dict_includes_engine():
    data = analyze_template(TEXT_TMPL, "{{7*7}}").to_dict()
    assert data["dialect"] == "jinja2"
    assert data["context"] == "template_text"


def test_cli_template_json(capsys):
    code = main(["--lang", "template", "--json", TEXT_TMPL, "{{7*7}}"])
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "jinja2"
    assert data["risk"] == "CRITICAL"
    assert code == 2


def test_cli_template_mutate(capsys):
    code = main(["-l", "template", "-d", "freemarker", "--mutate", "Hello {INPUT}"])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
