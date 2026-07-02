from xyainjex.shell.balance import balance


def test_balanced_double_quotes():
    b = balance('curl "http://example.com"')
    assert b.quotes_balanced
    assert b.syntax_valid


def test_unbalanced_double_quote():
    b = balance('curl "http://example.com')
    assert not b.quotes_balanced
    assert b.double_quote_open
    assert not b.syntax_valid


def test_comment_swallows_trailing_quote():
    # The '#' comment eats the trailing template quote, so the command is
    # balanced. This is why the classic payload keeps syntax valid.
    b = balance('curl ""; id ; #"')
    assert b.quotes_balanced
    assert b.syntax_valid


def test_breakout_without_comment_is_unbalanced():
    # No comment: the trailing template quote re-opens a double quote.
    b = balance('curl ""; id"')
    assert b.double_quote_open
    assert not b.syntax_valid


def test_single_quote_literal_double():
    # Double quote inside single quotes is literal, so quotes stay balanced.
    b = balance("echo 'a \" b'")
    assert b.quotes_balanced


def test_unbalanced_parens():
    b = balance("echo (a")
    assert b.unbalanced_pairs.get("()") == 1
    assert not b.syntax_valid


def test_command_substitution_balance():
    b = balance("echo $(id)")
    assert b.syntax_valid


def test_open_command_substitution():
    b = balance("echo $(id")
    assert b.unbalanced_pairs.get("$()") == 1
    assert not b.syntax_valid
