import json

from xyainjex import CodeLang, Context, analyze_code, mutate_code, parse_code_lang
from xyainjex.cli import main
from xyainjex.code.balance import code_balance
from xyainjex.code.context import analyze_code_context

PY_STRING = 'eval("result = {INPUT}")'
PY_EXPR = "eval({INPUT})"
JS_TEMPLATE = "const x = `hi {INPUT}`"


# --- context ---


def test_python_string_context():
    assert (
        analyze_code_context('eval("x{INPUT}")', CodeLang.PYTHON) == Context.CODE_STRING
    )


def test_expression_context():
    assert analyze_code_context(PY_EXPR, CodeLang.PYTHON) == Context.CODE_EXPRESSION


def test_js_template_context():
    assert (
        analyze_code_context("`a{INPUT}`", CodeLang.JAVASCRIPT) == Context.CODE_TEMPLATE
    )


# --- balance ---


def test_balanced_code():
    assert code_balance('eval("x")', CodeLang.PYTHON).syntax_valid


def test_unterminated_string():
    assert not code_balance('eval("x', CodeLang.PYTHON).syntax_valid


def test_open_template_substitution_unbalanced():
    b = code_balance("`a ${1", CodeLang.JAVASCRIPT)
    assert not b.syntax_valid
    assert b.unbalanced_pairs.get("${}") == 1


# --- breakout ---


def test_python_string_breakout():
    r = analyze_code(PY_STRING, "\"; __import__('os').system('id') #", CodeLang.PYTHON)
    assert r.context == Context.CODE_STRING
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.breakout.comment_terminated
    assert r.risk.value == "CRITICAL"


def test_wrong_quote_does_not_break_out():
    # A single quote cannot close a double-quoted string.
    r = analyze_code(PY_STRING, "'; system('id')", CodeLang.PYTHON)
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_expression_sink_injection():
    r = analyze_code(PY_EXPR, "os.system('id')", CodeLang.PYTHON)
    assert r.breakout.command_injected
    assert "system" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_js_template_substitution():
    r = analyze_code(
        JS_TEMPLATE, "${require('child_process').execSync('id')}", CodeLang.JAVASCRIPT
    )
    assert r.breakout.substitution_injected
    assert r.breakout.command_injected


def test_php_string_breakout():
    r = analyze_code("eval('{INPUT}')", "'); system('id'); //", CodeLang.PHP)
    assert r.breakout.command_injected
    assert "system" in r.breakout.separators


def test_benign_value():
    r = analyze_code(PY_STRING, "safe input", CodeLang.PYTHON)
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_python_string():
    result = mutate_code(PY_STRING, CodeLang.PYTHON)
    assert result.context == Context.CODE_STRING
    assert result.valid > 0


def test_mutate_js_template():
    result = mutate_code(JS_TEMPLATE, CodeLang.JAVASCRIPT)
    assert result.context == Context.CODE_TEMPLATE
    assert result.valid > 0


# --- language parsing, result shape, and CLI ---


def test_parse_code_lang_aliases():
    assert parse_code_lang("py") == CodeLang.PYTHON
    assert parse_code_lang("js") == CodeLang.JAVASCRIPT
    assert parse_code_lang("php") == CodeLang.PHP


def test_result_dialect_is_language():
    data = analyze_code(PY_EXPR, "os.system('id')", CodeLang.PYTHON).to_dict()
    assert data["dialect"] == "python"
    assert data["context"] == "code_expression"


def test_cli_code_json(capsys):
    code = main(
        ["--lang", "code", "-d", "python", "--json", PY_EXPR, "os.system('id')"]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "python"
    assert data["risk"] == "CRITICAL"
    assert code == 2


def test_cli_code_mutate(capsys):
    code = main(["-l", "code", "-d", "php", "--mutate", "eval('{INPUT}')"])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
