import json

from xyainjex import Context, analyze_ssrf, mutate_ssrf
from xyainjex.cli import main
from xyainjex.ssrf.context import analyze_ssrf_context

QUERY = "http://api.example.com/fetch?url={INPUT}"
HOST = "http://{INPUT}/path"
PATH = "http://api.example.com/{INPUT}"
URL = "{INPUT}"


# --- context ---


def test_context_query():
    assert analyze_ssrf_context(QUERY) == Context.SSRF_QUERY


def test_context_host():
    assert analyze_ssrf_context(HOST) == Context.SSRF_HOST


def test_context_path():
    assert analyze_ssrf_context(PATH) == Context.SSRF_PATH


def test_context_url():
    assert analyze_ssrf_context(URL) == Context.SSRF_URL


# --- query (url= param) context ---


def test_metadata_is_critical():
    r = analyze_ssrf(QUERY, "http://169.254.169.254/latest/meta-data/")
    assert r.breakout.command_injected
    assert "metadata" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_loopback_is_high():
    r = analyze_ssrf(QUERY, "http://127.0.0.1:8080/admin")
    assert "loopback" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_private_ip_is_high():
    r = analyze_ssrf(QUERY, "http://10.0.0.5/")
    assert "private-ip" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_file_scheme_is_high():
    r = analyze_ssrf(QUERY, "file:///etc/passwd")
    assert "file" in r.breakout.separators
    assert "scheme-change" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_gopher_is_critical():
    r = analyze_ssrf(QUERY, "gopher://127.0.0.1:6379/_INFO")
    assert "gopher" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_decimal_ip_is_obfuscated_loopback():
    r = analyze_ssrf(QUERY, "http://2130706433/")
    assert "loopback" in r.breakout.separators
    assert "obfuscated-ip" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_protocol_relative_metadata_is_critical():
    r = analyze_ssrf(QUERY, "//169.254.169.254/")
    assert "protocol-relative" in r.breakout.separators
    assert "metadata" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_userinfo_override_to_metadata_is_critical():
    r = analyze_ssrf(QUERY, "http://trusted.com@169.254.169.254/")
    assert "userinfo-override" in r.breakout.separators
    assert "metadata" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_external_absolute_url_is_medium():
    r = analyze_ssrf(QUERY, "https://example.com/ok")
    assert r.breakout.command_injected
    assert "absolute-url" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_relative_value_is_low():
    r = analyze_ssrf(QUERY, "/relative/path")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- host context ---


def test_host_metadata_is_critical():
    r = analyze_ssrf(HOST, "169.254.169.254")
    assert "metadata" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_host_hex_loopback_is_high():
    r = analyze_ssrf(HOST, "0x7f000001")
    assert "loopback" in r.breakout.separators
    assert "obfuscated-ip" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_host_external_is_medium():
    r = analyze_ssrf(HOST, "evil.example.com")
    assert r.breakout.command_injected
    assert "host-controlled" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_host_userinfo_override_is_high():
    r = analyze_ssrf(HOST, "expected.com@127.0.0.1")
    assert "userinfo-override" in r.breakout.separators
    assert r.risk.value == "HIGH"


# --- path context ---


def test_path_stays_on_host_is_low():
    r = analyze_ssrf(PATH, "subdir/file.json")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_path_embedded_url_does_not_redirect():
    r = analyze_ssrf(PATH, "http://169.254.169.254/")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_query():
    result = mutate_ssrf(QUERY)
    assert result.context == Context.SSRF_QUERY
    assert result.valid > 0
    assert all(c.command_injected for c in result.candidates)


def test_mutate_host():
    result = mutate_ssrf(HOST)
    assert result.context == Context.SSRF_HOST
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_ssrf(QUERY, "http://169.254.169.254/").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "ssrf_query"


def test_cli_ssrf_json(capsys):
    code = main(["--lang", "ssrf", "--json", QUERY, "http://169.254.169.254/latest/"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_ssrf_mutate(capsys):
    code = main(["-l", "ssrf", "--mutate", QUERY])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
