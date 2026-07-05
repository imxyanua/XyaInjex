import json

from xyainjex import Context, analyze_argument, mutate_argument
from xyainjex.argument.context import analyze_argument_context
from xyainjex.cli import main

OPT = "curl {INPUT}"
VAL = "curl --url={INPUT}"


# --- context ---


def test_context_option():
    assert analyze_argument_context(OPT) == Context.ARG_OPTION
    assert analyze_argument_context("{INPUT}") == Context.ARG_OPTION


def test_context_value():
    assert analyze_argument_context(VAL) == Context.ARG_VALUE


# --- option slot ---


def test_benign_value_is_low():
    r = analyze_argument(OPT, "https://example.com")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_output_flag_is_high():
    r = analyze_argument(OPT, "-o /tmp/pwn")
    assert r.breakout.command_injected
    assert "file-flag" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_long_output_flag_is_high():
    r = analyze_argument(OPT, "--output=/tmp/pwn")
    assert "file-flag" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_config_flag_is_high():
    r = analyze_argument(OPT, "-K /tmp/rc")
    assert "file-flag" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_git_upload_pack_is_critical():
    r = analyze_argument(OPT, "--upload-pack=touch /tmp/x")
    assert "rce-flag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_tar_checkpoint_action_is_critical():
    r = analyze_argument(OPT, "--checkpoint-action=exec=sh")
    assert "rce-flag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_find_exec_is_critical():
    r = analyze_argument(OPT, "-exec touch /tmp/x ;")
    assert "rce-flag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_ssh_proxycommand_value_is_critical():
    r = analyze_argument(OPT, "-o ProxyCommand=id")
    assert "rce-flag" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_unknown_option_is_medium():
    r = analyze_argument(OPT, "--foobar")
    assert r.breakout.command_injected
    assert "option" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_end_of_options_neutralizes():
    r = analyze_argument(OPT, "-- -o /tmp/x")
    assert not r.breakout.command_injected
    assert r.breakout.separators == ["end-of-options"]
    assert r.risk.value == "LOW"


# --- value slot (glued) ---


def test_value_context_needs_word_split():
    r = analyze_argument(VAL, " -o /tmp/pwn")
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_value_benign_is_low():
    r = analyze_argument(VAL, "http://ok")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_option():
    result = mutate_argument(OPT)
    assert result.context == Context.ARG_OPTION
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_value_needs_split():
    result = mutate_argument(VAL)
    assert result.context == Context.ARG_VALUE
    assert result.valid == 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_argument(OPT, "-o /tmp/x").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "arg_option"


def test_cli_argument_json(capsys):
    code = main(["--lang", "argument", "--json", OPT, "--upload-pack=touch /x"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_argument_mutate(capsys):
    code = main(["-l", "argument", "--mutate", OPT])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
