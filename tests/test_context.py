import pytest

from xyainjex import Context
from xyainjex.shell.context import analyze_context, split_template


def test_double_quote_context():
    assert analyze_context('curl "{INPUT}"') == Context.DOUBLE_QUOTE


def test_single_quote_context():
    assert analyze_context("grep '{INPUT}' file.txt") == Context.SINGLE_QUOTE


def test_unquoted_context():
    assert analyze_context("ping {INPUT}") == Context.UNQUOTED


def test_backtick_context():
    assert analyze_context("echo `{INPUT}`") == Context.BACKTICK


def test_command_substitution_context():
    assert analyze_context("echo $({INPUT})") == Context.COMMAND_SUBSTITUTION


def test_double_quote_inside_more_text():
    assert analyze_context('sh -c "echo {INPUT} done"') == Context.DOUBLE_QUOTE


def test_missing_marker_raises():
    with pytest.raises(ValueError):
        analyze_context("curl example.com")


def test_split_template_parts():
    parts = split_template('curl "{INPUT}"')
    assert parts.prefix == 'curl "'
    assert parts.suffix == '"'
