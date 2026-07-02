from xyainjex import Context, Dialect, analyze


def test_double_quote_command_substitution():
    r = analyze('echo "{INPUT}"', "$(id)")
    assert r.context == Context.DOUBLE_QUOTE
    assert not r.breakout.command_injected
    assert r.breakout.substitution_injected
    assert r.risk.value == "HIGH"


def test_backtick_substitution():
    r = analyze('echo "{INPUT}"', "`id`")
    assert r.breakout.substitution_injected
    assert r.risk.value == "HIGH"


def test_single_quote_blocks_substitution():
    r = analyze("echo '{INPUT}'", "$(id)")
    assert not r.breakout.substitution_injected
    assert r.risk.value == "LOW"


def test_unquoted_substitution():
    r = analyze("echo {INPUT}", "$(id)")
    assert r.breakout.substitution_injected


def test_arithmetic_is_not_substitution():
    # Arithmetic expansion does not run commands, so it is not flagged.
    r = analyze("echo {INPUT}", "$((1+1))")
    assert not r.breakout.substitution_injected


def test_parameter_expansion_is_not_substitution():
    r = analyze('echo "{INPUT}"', "${HOME}")
    assert not r.breakout.substitution_injected


def test_template_substitution_in_prefix_not_counted():
    # A substitution already in the template must not be attributed to the input.
    r = analyze('echo "$(whoami) {INPUT}"', "plain")
    assert not r.breakout.substitution_injected
    assert r.risk.value == "LOW"


def test_heredoc_substitution_breakout():
    # Unquoted heredoc: command substitution in the body executes.
    r = analyze("cat <<EOF\n{INPUT}\nEOF", "$(id)")
    assert r.context == Context.HEREDOC
    assert r.breakout.substitution_injected
    assert r.risk.value == "HIGH"


def test_quoted_heredoc_blocks_substitution():
    # Quoted delimiter makes the body fully literal.
    r = analyze("cat <<'EOF'\n{INPUT}\nEOF", "$(id)")
    assert not r.breakout.substitution_injected
    assert r.risk.value == "LOW"


def test_heredoc_terminator_injection_still_critical():
    r = analyze("cat <<EOF\n{INPUT}\nEOF", "\nEOF\nid")
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_powershell_subexpression_substitution():
    r = analyze('Get-Content "{INPUT}"', "$(whoami)", Dialect.POWERSHELL)
    assert r.breakout.substitution_injected
    assert r.risk.value == "HIGH"


def test_command_injection_takes_precedence():
    # A separator still ranks CRITICAL even when a substitution is also present.
    r = analyze('echo "{INPUT}"', '"; $(id); #')
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_substitution_field_in_dict():
    data = analyze('echo "{INPUT}"', "$(id)").to_dict()
    assert data["breakout"]["substitution_injected"] is True
