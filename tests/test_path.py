import json

from xyainjex import Context, analyze_path, mutate_path
from xyainjex.cli import main
from xyainjex.path.context import analyze_path_context

BASE = "/var/www/uploads/{INPUT}"
EXT = "include('pages/{INPUT}.php')"
FULL = "{INPUT}"


# --- context ---


def test_context_base():
    assert analyze_path_context(BASE) == Context.PATH_BASE


def test_context_ext():
    assert analyze_path_context(EXT) == Context.PATH_EXT


def test_context_full():
    assert analyze_path_context(FULL) == Context.PATH_FULL


# --- base directory context ---


def test_benign_filename_is_low():
    r = analyze_path(BASE, "avatar.png")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_traversal_is_high():
    r = analyze_path(BASE, "../../../../etc/passwd")
    assert r.breakout.command_injected
    assert "traversal" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_encoded_traversal_is_high():
    r = analyze_path(BASE, "..%2f..%2f..%2fetc%2fpasswd")
    assert "traversal" in r.breakout.separators
    assert "encoded" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_dot_bypass_traversal():
    r = analyze_path(BASE, "....//....//etc/passwd")
    assert "traversal" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_absolute_path_is_high():
    r = analyze_path(BASE, "/etc/passwd")
    assert "absolute" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_read_wrapper_is_high():
    r = analyze_path(BASE, "php://filter/convert.base64-encode/resource=x")
    assert "read-wrapper" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_remote_scheme_is_critical():
    r = analyze_path(BASE, "http://evil.example.com/shell.txt")
    assert "remote-scheme" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- fixed extension context ---


def test_benign_page_is_low():
    r = analyze_path(EXT, "home")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_null_byte_extension_bypass():
    r = analyze_path(EXT, "../../../../etc/passwd%00")
    assert "extension-bypass" in r.breakout.separators
    assert "null-byte" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_php_input_wrapper_is_critical():
    r = analyze_path(EXT, "php://input")
    assert "rce-wrapper" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_expect_wrapper_is_critical():
    r = analyze_path(EXT, "expect://id")
    assert "rce-wrapper" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- full path context ---


def test_full_benign_is_low():
    r = analyze_path(FULL, "report.pdf")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_full_absolute_is_high():
    r = analyze_path(FULL, "/etc/passwd")
    assert r.breakout.command_injected
    assert "absolute" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_full_windows_absolute():
    r = analyze_path(FULL, "C:\\windows\\win.ini")
    assert "absolute" in r.breakout.separators
    assert "sensitive-file" in r.breakout.separators
    assert r.risk.value == "HIGH"


# --- mutation ---


def test_mutate_base():
    result = mutate_path(BASE)
    assert result.context == Context.PATH_BASE
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_ext():
    result = mutate_path(EXT)
    assert result.context == Context.PATH_EXT
    assert result.valid > 0


def test_mutate_full_ranks_remote_first():
    result = mutate_path(FULL)
    assert result.context == Context.PATH_FULL
    assert result.candidates[0].risk.value == "CRITICAL"


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_path(BASE, "../../etc/passwd").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "path_base"


def test_cli_path_json(capsys):
    code = main(["--lang", "path", "--json", BASE, "../../../../etc/passwd"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "HIGH"
    assert data["dialect"] is None
    assert code == 2


def test_cli_path_mutate(capsys):
    code = main(["-l", "path", "--mutate", BASE])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
