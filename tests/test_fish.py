from xyainjex import Context, Dialect, analyze, mutate, parse_dialect
from xyainjex.shell.context import analyze_context


def test_fish_command_substitution_context():
    assert (
        analyze_context("echo ({INPUT})", Dialect.FISH) == Context.COMMAND_SUBSTITUTION
    )


def test_fish_bare_substitution_breakout():
    r = analyze("echo {INPUT}", "(id)", Dialect.FISH)
    assert r.breakout.substitution_injected
    assert not r.breakout.command_injected
    assert r.risk.value == "HIGH"


def test_fish_dollar_substitution_breakout():
    r = analyze("echo {INPUT}", "$(id)", Dialect.FISH)
    assert r.breakout.substitution_injected


def test_fish_single_quote_blocks_substitution():
    r = analyze("echo '{INPUT}'", "(id)", Dialect.FISH)
    assert not r.breakout.substitution_injected
    assert r.risk.value == "LOW"


def test_fish_separator_breakout():
    r = analyze("echo {INPUT}", "; id", Dialect.FISH)
    assert r.breakout.command_injected
    assert ";" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_fish_supports_and_operator():
    r = analyze("echo {INPUT}", "&& whoami", Dialect.FISH)
    assert r.breakout.command_injected
    assert "&&" in r.breakout.separators


def test_fish_double_quote_breakout():
    r = analyze('echo "{INPUT}"', '"; id', Dialect.FISH)
    assert r.context == Context.DOUBLE_QUOTE
    assert r.breakout.command_injected


def test_fish_benign_unquoted():
    r = analyze("echo {INPUT}", "plainvalue", Dialect.FISH)
    assert not r.breakout.command_injected
    assert not r.breakout.substitution_injected


def test_fish_mutate():
    result = mutate("echo {INPUT}", command="id", dialect=Dialect.FISH)
    assert result.dialect == Dialect.FISH
    assert result.valid > 0


def test_fish_parenthesis_substitution_in_mutation():
    result = mutate("echo ({INPUT})", command="id", dialect=Dialect.FISH)
    # Inside a command substitution the input already executes.
    assert result.context == Context.COMMAND_SUBSTITUTION


def test_parse_fish_alias():
    assert parse_dialect("fish") == Dialect.FISH
