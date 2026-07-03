import json

from xyainjex import Context, analyze_xml, mutate_xml
from xyainjex.cli import main
from xyainjex.xml.balance import xml_balance
from xyainjex.xml.context import analyze_xml_context

TEXT = "<user><name>{INPUT}</name></user>"
ATTR = '<user name="{INPUT}" />'
ATTR_S = "<user name='{INPUT}' />"
CDATA = "<data><![CDATA[{INPUT}]]></data>"
COMMENT = "<!-- {INPUT} -->"


# --- context ---


def test_text_context():
    assert analyze_xml_context(TEXT) == Context.XML_TEXT


def test_attr_context():
    assert analyze_xml_context(ATTR) == Context.XML_ATTR


def test_cdata_context():
    assert analyze_xml_context(CDATA) == Context.XML_CDATA


def test_comment_context():
    assert analyze_xml_context(COMMENT) == Context.XML_COMMENT


# --- balance ---


def test_balanced_xml():
    assert xml_balance("<a>text</a>").syntax_valid


def test_unclosed_tag():
    b = xml_balance('<a href="x')
    assert not b.syntax_valid


# --- breakout ---


def test_benign_text():
    r = analyze_xml(TEXT, "John Doe")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_element_injection_in_text():
    r = analyze_xml(TEXT, "<script>alert(1)</script>")
    assert r.context == Context.XML_TEXT
    assert r.breakout.command_injected
    assert "element" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


def test_attribute_breakout():
    r = analyze_xml(ATTR, '"><injected/>')
    assert r.breakout.quote_closed
    assert r.breakout.command_injected
    assert r.risk.value == "CRITICAL"


def test_wrong_attr_quote_does_not_break():
    # A single quote cannot close a double-quoted attribute.
    r = analyze_xml(ATTR, "'><injected/>")
    assert not r.breakout.command_injected


def test_single_quote_attribute_breakout():
    r = analyze_xml(ATTR_S, "'><injected/>")
    assert r.breakout.command_injected


def test_attribute_close_without_element_is_medium():
    r = analyze_xml(ATTR, '" onload="x')
    assert r.breakout.quote_closed
    assert not r.breakout.command_injected
    assert r.risk.value == "MEDIUM"


def test_cdata_escape():
    r = analyze_xml(CDATA, "]]><injected/><![CDATA[")
    assert r.breakout.command_injected


def test_comment_escape():
    r = analyze_xml(COMMENT, "--><injected/><!--")
    assert r.breakout.command_injected


def test_entity_in_text_is_medium():
    r = analyze_xml(TEXT, "&xxe;")
    assert not r.breakout.command_injected
    assert "entity" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_xxe_doctype():
    r = analyze_xml(TEXT, '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>')
    assert "xxe" in r.breakout.separators


# --- mutation ---


def test_mutate_text():
    result = mutate_xml(TEXT)
    assert result.context == Context.XML_TEXT
    assert result.valid > 0


def test_mutate_attr():
    result = mutate_xml(ATTR)
    assert result.context == Context.XML_ATTR
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_xml(TEXT, "<a/>").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "xml_text"


def test_cli_xml_json(capsys):
    code = main(["--lang", "xml", "--json", TEXT, "<script/>x"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_xml_mutate(capsys):
    code = main(["-l", "xml", "--mutate", TEXT])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
