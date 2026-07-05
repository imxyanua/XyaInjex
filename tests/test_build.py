import json

import pytest

from xyainjex import build
from xyainjex.build import BUILD_LANGS
from xyainjex.cli import main

# --- core build behaviour ---


def test_build_shell_double_quote():
    r = build('curl "{INPUT}"', lang="shell", goal="id")
    assert r.validated
    assert "id" in r.payload
    assert r.risk in ("HIGH", "CRITICAL")


def test_build_shell_unquoted_picks_right_shape():
    r = build("echo {INPUT}", lang="shell", goal="whoami")
    assert r.validated
    assert r.strategy == "unquoted"
    assert r.payload == "; whoami ; #"


def test_build_sql_auth_bypass():
    r = build("SELECT * FROM u WHERE n = '{INPUT}'", lang="sql")
    assert r.validated
    assert r.risk == "CRITICAL"


def test_build_sql_union_uses_goal():
    r = build(
        "SELECT * FROM u WHERE n = '{INPUT}'",
        lang="sql",
        goal="username,password FROM users",
    )
    assert r.validated
    assert "UNION SELECT username,password FROM users" in r.payload


def test_build_template_expression():
    r = build("Hello {INPUT}", lang="template", goal="7*7")
    assert r.validated
    assert r.payload == "{{ 7*7 }}"


def test_build_code_string_context():
    r = build('eval("{INPUT}")', lang="code", goal="__import__('os').system('id')")
    assert r.validated


def test_build_xss_attribute_context():
    r = build('<img src="{INPUT}">', lang="xss", goal="alert(1)")
    assert r.validated
    assert r.strategy.startswith("attr-break")


def test_build_ssrf_target():
    r = build("http://api/f?url={INPUT}", lang="ssrf", goal="http://169.254.169.254/")
    assert r.validated
    assert r.payload == "http://169.254.169.254/"


def test_build_path_traversal():
    r = build("/var/www/{INPUT}", lang="path", goal="/etc/passwd")
    assert r.validated
    assert "etc/passwd" in r.payload


def test_build_redis_argument():
    r = build("GET {INPUT}", lang="redis", goal="CONFIG SET dir /tmp")
    assert r.validated
    assert r.payload.startswith("x\r\n")


def test_build_crlf_header():
    r = build("Location: {INPUT}", lang="crlf", goal="Set-Cookie: x=1")
    assert r.validated


def test_build_every_flagship_lang_validates():
    # With default goals, each supported language builds a working payload.
    templates = {
        "shell": 'curl "{INPUT}"',
        "sql": "SELECT '{INPUT}'",
        "template": "Hi {INPUT}",
        "code": "eval({INPUT})",
        "xss": "<div>{INPUT}</div>",
        "ssrf": "http://api/?u={INPUT}",
        "path": "/base/{INPUT}",
        "redis": "GET {INPUT}",
        "xxe": "{INPUT}",
        "crlf": "Location: {INPUT}",
        "mail": "To: {INPUT}",
    }
    assert set(templates) == set(BUILD_LANGS)
    for lang, tmpl in templates.items():
        assert build(tmpl, lang=lang).validated, lang


def test_build_unbuildable_marks_not_validated():
    # An SSRF path context: a relative value stays on the intended host, so no
    # candidate redirects the request and the build is best-effort.
    r = build("http://host/path/{INPUT}", lang="ssrf", goal="notaurl")
    assert not r.validated


def test_build_rejects_unsupported_lang():
    with pytest.raises(ValueError):
        build("{INPUT}", lang="prompt")


# --- result shape and CLI ---


def test_build_to_dict():
    data = build('curl "{INPUT}"', lang="shell", goal="id").to_dict()
    assert data["validated"] is True
    assert data["payload"]
    assert data["goal"] == "id"


def test_cli_build_json(capsys):
    code = main(
        ["--lang", "shell", "--build", "--goal", "id", "--json", 'curl "{INPUT}"']
    )
    data = json.loads(capsys.readouterr().out)
    assert data["validated"] is True
    assert "id" in data["payload"]
    assert code == 0


def test_cli_build_text(capsys):
    code = main(["-l", "template", "--build", "--goal", "7*7", "Hello {INPUT}"])
    out = capsys.readouterr().out
    assert code == 0
    assert "payload builder" in out.lower()
    assert "{{ 7*7 }}" in out


def test_cli_build_rejects_unsupported_lang():
    with pytest.raises(SystemExit):
        main(["-l", "prompt", "--build", "{INPUT}"])
