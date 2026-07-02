from xyainjex import Context, analyze
from xyainjex.shell.balance import balance
from xyainjex.shell.context import analyze_context

HEREDOC_TMPL = "cat <<EOF\n{INPUT}\nEOF"


# --- context ---


def test_heredoc_context():
    assert analyze_context(HEREDOC_TMPL) == Context.HEREDOC


def test_heredoc_dash_context():
    assert analyze_context("cat <<-END\n\t{INPUT}\nEND") == Context.HEREDOC


def test_heredoc_quoted_delimiter_context():
    assert analyze_context("cat <<'EOF'\n{INPUT}\nEOF") == Context.HEREDOC


def test_here_string_is_not_heredoc():
    # ``<<<`` is a here-string, not a here-document.
    assert analyze_context("cat <<<{INPUT}") == Context.UNQUOTED


def test_single_redirect_is_not_heredoc():
    assert analyze_context("cat < {INPUT}") == Context.UNQUOTED


# --- balance ---


def test_open_heredoc_is_unbalanced():
    b = balance("cat <<EOF\nbody")
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("<<") == 1


def test_closed_heredoc_balances():
    assert balance("cat <<EOF\nbody\nEOF").syntax_valid


def test_heredoc_body_content_is_literal():
    # Quotes and semicolons inside the body do not affect balance.
    assert balance("cat <<EOF\na ' \" ; b\nEOF").syntax_valid


# --- breakout ---


def test_benign_heredoc_body_no_breakout():
    r = analyze(HEREDOC_TMPL, "just some text")
    assert r.context == Context.HEREDOC
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_terminator_injection_breakout():
    # The payload closes the heredoc with its own EOF line, then injects id.
    r = analyze(HEREDOC_TMPL, "\nEOF\nid")
    assert r.context == Context.HEREDOC
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_dash_heredoc_terminator_with_tab():
    # ``<<-`` strips leading tabs from the terminator line.
    r = analyze("cat <<-EOF\n\t{INPUT}\n\tEOF", "\n\tEOF\n\tid")
    assert r.breakout.command_injected


def test_substitution_in_body_is_conservative():
    # Command substitution inside the body is not flagged (documented follow-up).
    r = analyze(HEREDOC_TMPL, "$(id)")
    assert not r.breakout.command_injected


def test_heredoc_does_not_break_normal_commands():
    r = analyze('curl "{INPUT}"', '"; id ; #')
    assert r.context == Context.DOUBLE_QUOTE
    assert r.risk.value == "CRITICAL"
