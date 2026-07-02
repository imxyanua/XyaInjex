from xyainjex import Context, Dialect, analyze
from xyainjex.shell.balance import balance
from xyainjex.shell.context import analyze_context


def test_arithmetic_context():
    assert analyze_context("echo $(( {INPUT} ))") == Context.ARITHMETIC


def test_parameter_expansion_context():
    assert analyze_context("echo ${{{INPUT}}}") == Context.PARAMETER_EXPANSION


def test_arithmetic_balances():
    assert balance("echo $((1+2))").syntax_valid


def test_open_arithmetic_is_unbalanced():
    b = balance("echo $((1+2")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("$(())") == 1


def test_parameter_expansion_balances():
    assert balance("echo ${HOME}").syntax_valid


def test_open_parameter_expansion_is_unbalanced():
    b = balance("echo ${HOME")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("${}") == 1


def test_command_substitution_still_works():
    assert analyze_context("echo $({INPUT})") == Context.COMMAND_SUBSTITUTION


def test_arithmetic_breakout():
    result = analyze("echo $(( {INPUT} ))", "1 )); id #", Dialect.POSIX)
    assert result.breakout.command_injected
    assert result.risk.value == "CRITICAL"


def test_dollar_paren_not_confused_with_arithmetic():
    # $( ... ) must be a command substitution, not arithmetic.
    assert analyze_context("echo $( {INPUT} )") == Context.COMMAND_SUBSTITUTION
