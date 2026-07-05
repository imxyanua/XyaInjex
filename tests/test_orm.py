import json

from xyainjex import Context, analyze_orm, mutate_orm
from xyainjex.cli import main
from xyainjex.orm.context import analyze_orm_context

KEY = "User.objects.filter({INPUT})"
QS = "?{INPUT}=1"
VAL = "name={INPUT}"


# --- context ---


def test_context_key():
    assert analyze_orm_context(KEY) == Context.ORM_LOOKUP_KEY
    assert analyze_orm_context(QS) == Context.ORM_LOOKUP_KEY


def test_context_value():
    assert analyze_orm_context(VAL) == Context.ORM_LOOKUP_VALUE


# --- key context ---


def test_plain_field_is_low():
    r = analyze_orm(KEY, "name=bob")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_sensitive_exfil_is_high():
    r = analyze_orm(KEY, "password__startswith=a")
    assert r.breakout.command_injected
    assert "sensitive-field" in r.breakout.separators
    assert "exfil-lookup" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_relation_traversal_is_high():
    r = analyze_orm(KEY, "user__password__startswith=a")
    assert "relation-traversal" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_relation_traversal_non_sensitive_is_high():
    r = analyze_orm(KEY, "author__name=x")
    assert "relation-traversal" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_privilege_isnull_is_high():
    r = analyze_orm(KEY, "is_superuser__isnull=False")
    assert "sensitive-field" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_regex_lookup_is_high():
    r = analyze_orm(KEY, "name__regex=.*")
    assert "regex-lookup" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_comparison_lookup_is_medium():
    r = analyze_orm(KEY, "id__gt=0")
    assert "exfil-lookup" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_exact_lookup_is_medium():
    r = analyze_orm(KEY, "email__exact=x")
    assert r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


# --- value context ---


def test_value_context_treats_lookup_as_data():
    r = analyze_orm(VAL, "user__password__startswith=a")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_key():
    result = mutate_orm(KEY)
    assert result.context == Context.ORM_LOOKUP_KEY
    assert result.valid > 0
    assert result.candidates[0].risk.value == "HIGH"


def test_mutate_value_is_empty():
    result = mutate_orm(VAL)
    assert result.context == Context.ORM_LOOKUP_VALUE
    assert result.valid == 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_orm(KEY, "password__startswith=a").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "orm_lookup_key"


def test_cli_orm_json(capsys):
    code = main(["--lang", "orm", "--json", KEY, "user__password__startswith=a"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "HIGH"
    assert data["dialect"] is None
    assert code == 2


def test_cli_orm_mutate(capsys):
    code = main(["-l", "orm", "--mutate", KEY])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
