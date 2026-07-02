from xyainjex import analyze, Context, Risk
from xyainjex.shell.breakout import detect_breakout


def test_classic_double_quote_breakout():
    b = detect_breakout('curl "{INPUT}"', '"; id ; #')
    assert b.context == Context.DOUBLE_QUOTE
    assert b.quote_closed
    assert b.command_injected
    assert b.comment_terminated
    assert ";" in b.separators
    assert b.commands_created >= 1


def test_single_quote_breakout():
    b = detect_breakout("grep '{INPUT}' file.txt", "'; id ; #")
    assert b.context == Context.SINGLE_QUOTE
    assert b.quote_closed
    assert b.command_injected


def test_unquoted_separator():
    b = detect_breakout("ping {INPUT}", "; id")
    assert b.context == Context.UNQUOTED
    assert not b.quote_closed
    assert b.command_injected


def test_no_breakout_inside_double_quote():
    b = detect_breakout('curl "{INPUT}"', "http://example.com/path")
    assert not b.quote_closed
    assert not b.command_injected


def test_no_breakout_separator_stays_quoted():
    # The ; is inside the still-open quote, so it is not a top level separator.
    b = detect_breakout('curl "{INPUT}"', "a ; b")
    assert not b.command_injected


def test_command_substitution_payload():
    b = detect_breakout('curl "{INPUT}"', '"$(id)"')
    # Substitution runs even without a separator, but there is no top level
    # command separator, so command_injected stays false while quote is closed.
    assert b.quote_closed


def test_and_operator_breakout():
    b = detect_breakout('curl "{INPUT}"', '" && id #')
    assert b.command_injected
    assert "&&" in b.separators


def test_risk_critical_for_valid_injection():
    result = analyze('curl "{INPUT}"', '"; id ; #')
    assert result.risk == Risk.CRITICAL
    assert result.balance.syntax_valid


def test_risk_high_when_unbalanced():
    # Injection without balancing the trailing quote leaves broken syntax.
    result = analyze('curl "{INPUT}"', '"; id')
    assert result.breakout.command_injected
    assert not result.balance.syntax_valid
    assert result.risk == Risk.HIGH


def test_risk_low_when_contained():
    result = analyze('curl "{INPUT}"', "http://example.com")
    assert result.risk == Risk.LOW


def test_rendered_matches_plan_example():
    result = analyze('curl "{INPUT}"', '"; id ; #')
    assert result.rendered == 'curl ""; id ; #"'
