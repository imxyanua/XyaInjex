import json

import pytest

from xyainjex import differential, fuzz
from xyainjex.cli import main
from xyainjex.fuzz.mutators import expand

SQL_TMPL = "SELECT * FROM users WHERE name = '{INPUT}'"
SHELL_TMPL = 'curl "{INPUT}"'


# --- mutators ---


def test_expand_includes_seed():
    variants = expand("' OR 1=1 -- ", "sql")
    payloads = [p for p, _ in variants]
    assert "' OR 1=1 -- " in payloads
    assert variants[0][1] == "seed"


def test_expand_case_variants():
    strategies = {s for _, s in expand("Union Select", "sql")}
    assert "case-lower" in strategies
    assert "case-upper" in strategies


def test_expand_sql_inline_comment():
    payloads = [p for p, _ in expand("OR 1=1", "sql")]
    assert "OR/**/1=1" in payloads


def test_expand_is_deterministic():
    assert expand("' OR 1=1", "sql") == expand("' OR 1=1", "sql")


# --- fuzz ---


def test_fuzz_sql_finds_paths():
    result = fuzz(SQL_TMPL, lang="sql")
    assert result.generated > 0
    assert result.valid > 0
    assert all(p.risk.value in ("HIGH", "CRITICAL") for p in result.paths)
    assert "sql_string" in result.contexts_reached


def test_fuzz_case_obfuscation_survives():
    # A lowercased keyword still injects because the lexer is case-insensitive.
    result = fuzz(SQL_TMPL, lang="sql")
    assert "case-lower" in result.strategies


def test_fuzz_url_encoding_does_not_inject():
    # Percent encoding is inert against the shell lexer, so it is not a path.
    result = fuzz(SHELL_TMPL, lang="shell")
    assert "url-encode" not in result.strategies


def test_fuzz_paths_have_stages():
    result = fuzz(SQL_TMPL, lang="sql")
    top = result.paths[0]
    assert top.stages[0] == "context"
    assert top.stages[-1] == "execution"


def test_fuzz_rejects_prompt_lang():
    with pytest.raises(ValueError):
        fuzz("{INPUT}", lang="prompt")


def test_fuzz_to_dict():
    data = fuzz(SQL_TMPL, lang="sql").to_dict()
    assert set(["template", "lang", "generated", "valid", "paths"]).issubset(data)


# --- differential ---


def test_differential_semicolon_shell():
    # ; is a separator in posix and powershell but not cmd.
    result = differential(
        "ping {INPUT}",
        "; whoami",
        lang="shell",
        dialects=["posix", "cmd", "powershell"],
    )
    assert result.divergent
    assert result.per_dialect["posix"]["command_injected"]
    assert not result.per_dialect["cmd"]["command_injected"]


def test_differential_no_divergence():
    result = differential(
        SQL_TMPL, "' OR 1=1 -- ", lang="sql", dialects=["mysql", "postgres"]
    )
    assert not result.divergent


def test_differential_to_dict():
    data = differential(
        "ping {INPUT}", "; id", lang="shell", dialects=["posix", "cmd"]
    ).to_dict()
    assert data["divergent"] is True
    assert "posix" in data["per_dialect"]


# --- CLI ---


def test_cli_fuzz_json(capsys):
    code = main(["--fuzz", "-l", "sql", "--json", SQL_TMPL])
    data = json.loads(capsys.readouterr().out)
    assert data["valid"] > 0
    assert code == 2


def test_cli_fuzz_rejects_prompt():
    with pytest.raises(SystemExit):
        main(["--fuzz", "-l", "prompt", "{INPUT}"])
