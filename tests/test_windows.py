from xyainjex import Context, Dialect, analyze, mutate
from xyainjex.shell.context import analyze_context

# --- cmd.exe ---


def test_cmd_context_double_quote():
    assert analyze_context('ping "{INPUT}"', Dialect.CMD) == Context.DOUBLE_QUOTE


def test_cmd_no_single_quote_context():
    # cmd has no single quotes; a single quote is an ordinary character.
    assert analyze_context("echo '{INPUT}'", Dialect.CMD) == Context.UNQUOTED


def test_cmd_unquoted_ampersand_breakout():
    result = analyze("ping {INPUT}", "& whoami", Dialect.CMD)
    assert result.breakout.command_injected
    assert "&" in result.breakout.separators
    assert result.risk.value == "CRITICAL"


def test_cmd_quote_breakout_unbalanced():
    result = analyze('ping "{INPUT}"', '" & whoami', Dialect.CMD)
    assert result.breakout.command_injected
    assert not result.balance.syntax_valid
    assert result.risk.value == "HIGH"


def test_cmd_caret_escapes_separator():
    # A caret-escaped ampersand does not start a new command.
    result = analyze("ping {INPUT}", "^& whoami", Dialect.CMD)
    assert not result.breakout.command_injected


def test_cmd_no_semicolon_separator():
    # ; is not a command separator in cmd.exe.
    result = analyze("ping {INPUT}", "; whoami", Dialect.CMD)
    assert not result.breakout.command_injected


def test_cmd_pipe_and_double_ampersand():
    assert analyze("ping {INPUT}", "&& whoami", Dialect.CMD).breakout.command_injected
    assert analyze("ping {INPUT}", "| whoami", Dialect.CMD).breakout.command_injected


def test_cmd_mutate():
    result = mutate("ping {INPUT}", command="whoami", dialect=Dialect.CMD)
    assert result.dialect == Dialect.CMD
    assert result.valid > 0
    # cmd payloads never use ';'
    assert all(";" not in c.payload for c in result.candidates)


# --- PowerShell ---


def test_powershell_double_quote_breakout():
    result = analyze('Get-Content "{INPUT}"', '"; whoami #', Dialect.POWERSHELL)
    assert result.context == Context.DOUBLE_QUOTE
    assert result.breakout.command_injected
    assert ";" in result.breakout.separators
    assert result.risk.value == "CRITICAL"


def test_powershell_single_quote_breakout():
    result = analyze("Get-Content '{INPUT}'", "'; whoami #", Dialect.POWERSHELL)
    assert result.context == Context.SINGLE_QUOTE
    assert result.breakout.command_injected


def test_powershell_backtick_escapes_separator():
    # Backtick is the PowerShell escape character, not command substitution.
    result = analyze("echo {INPUT}", "`; whoami", Dialect.POWERSHELL)
    assert not result.breakout.command_injected


def test_powershell_subexpression_context():
    assert (
        analyze_context('Write-Output "$({INPUT})"', Dialect.POWERSHELL)
        == Context.COMMAND_SUBSTITUTION
    )


def test_powershell_block_comment_ignored():
    # Content inside <# ... #> is a comment and holds no separators.
    result = analyze("echo {INPUT}", "<# ; whoami #>", Dialect.POWERSHELL)
    assert not result.breakout.command_injected


def test_powershell_pipe_breakout():
    result = analyze('Get-Content "{INPUT}"', '" | whoami', Dialect.POWERSHELL)
    assert result.breakout.command_injected
    assert "|" in result.breakout.separators


def test_powershell_mutate():
    result = mutate(
        'Get-Content "{INPUT}"', command="whoami", dialect=Dialect.POWERSHELL
    )
    assert result.dialect == Dialect.POWERSHELL
    assert result.valid > 0
