import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from xyainjex.api import app  # noqa: E402

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_analyze_endpoint():
    resp = client.post(
        "/analyze",
        json={"template": 'curl "{INPUT}"', "payload": '"; id ; #'},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["context"] == "double_quote"
    assert data["risk"] == "CRITICAL"
    assert data["breakout"]["command_injected"] is True
    assert data["syntax_valid"] is True


def test_analyze_no_breakout():
    resp = client.post(
        "/analyze",
        json={"template": 'curl "{INPUT}"', "payload": "http://example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk"] == "LOW"


def test_analyze_missing_marker_returns_400():
    resp = client.post(
        "/analyze",
        json={"template": "curl example.com", "payload": "; id"},
    )
    assert resp.status_code == 400
    assert "marker" in resp.json()["detail"]


def test_mutate_endpoint():
    resp = client.post("/mutate", json={"template": 'curl "{INPUT}"'})
    assert resp.status_code == 200
    data = resp.json()
    assert data["context"] == "double_quote"
    assert data["valid"] > 0
    assert isinstance(data["high_probability"], list)


def test_mutate_missing_marker_returns_400():
    resp = client.post("/mutate", json={"template": "echo hello"})
    assert resp.status_code == 400


def test_analyze_sql_endpoint():
    resp = client.post(
        "/analyze",
        json={
            "template": "SELECT * FROM users WHERE name = '{INPUT}'",
            "payload": "' OR 1=1 -- ",
            "lang": "sql",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["dialect"] == "mysql"
    assert data["context"] == "sql_string"
    assert data["risk"] == "CRITICAL"


def test_analyze_sql_dialect_postgres():
    resp = client.post(
        "/analyze",
        json={
            "template": 'SELECT * FROM t WHERE a = "{INPUT}"',
            "payload": '" OR 1=1 -- ',
            "lang": "sql",
            "dialect": "postgres",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["context"] == "sql_identifier"


def test_bad_lang_returns_400():
    resp = client.post(
        "/analyze",
        json={"template": "x {INPUT}", "payload": "y", "lang": "cobol"},
    )
    assert resp.status_code == 400


def test_mutate_sql_endpoint():
    resp = client.post(
        "/mutate",
        json={
            "template": "SELECT * FROM users WHERE name = '{INPUT}'",
            "lang": "sql",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] > 0
