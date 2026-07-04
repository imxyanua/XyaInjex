import json

from xyainjex import Context, analyze_mail, mutate_mail
from xyainjex.cli import main
from xyainjex.mail.context import analyze_mail_context

HDR = "To: {INPUT}"
SUBJ = "Subject: {INPUT}"
SMTP = "RCPT TO:<{INPUT}>"
BODY = "Hello,\n\n{INPUT}\n\nRegards"


# --- context ---


def test_context_header():
    assert analyze_mail_context(HDR) == Context.MAIL_HEADER
    assert analyze_mail_context(SUBJ) == Context.MAIL_HEADER


def test_context_smtp():
    assert analyze_mail_context(SMTP) == Context.SMTP_COMMAND


def test_context_body():
    assert analyze_mail_context(BODY) == Context.MAIL_BODY


# --- header context ---


def test_benign_header_is_low():
    r = analyze_mail(HDR, "user@example.com")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_bcc_recipient_injection_is_high():
    r = analyze_mail(HDR, "user@example.com\r\nBcc: attacker@evil.example")
    assert r.breakout.command_injected
    assert "recipient" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_new_header_is_high():
    r = analyze_mail(SUBJ, "Hi\r\nX-Injected: 1")
    assert "new-header" in r.breakout.separators
    assert r.risk.value == "HIGH"


def test_body_override_is_medium():
    r = analyze_mail(SUBJ, "Hi\r\n\r\nInjected body")
    assert "body-injection" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_bare_line_fold_is_medium():
    r = analyze_mail(SUBJ, "Hi\r\nworld")
    assert "line-break" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_encoded_only_is_medium():
    r = analyze_mail(SUBJ, "Hi%0d%0aBcc: a@evil.example")
    assert not r.breakout.command_injected
    assert "encoded" in r.breakout.separators
    assert r.risk.value == "MEDIUM"


def test_smtp_smuggle_from_header_is_critical():
    r = analyze_mail(SUBJ, "Hi\r\nRCPT TO:<a@evil.example>")
    assert "smtp-smuggle" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- smtp command context ---


def test_benign_smtp_is_low():
    r = analyze_mail(SMTP, "a@example.com")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_rcpt_smuggle_is_critical():
    r = analyze_mail(SMTP, "a@example.com>\r\nRCPT TO:<b@evil.example")
    assert "smtp-smuggle" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- body context ---


def test_benign_body_is_low():
    r = analyze_mail(BODY, "just text")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_plain_body_newline_is_low():
    r = analyze_mail(BODY, "line1\r\nline2")
    assert not r.breakout.command_injected
    assert r.risk.value == "LOW"


def test_data_terminator_is_critical():
    r = analyze_mail(BODY, "text\r\n.\r\nMAIL FROM:<x@evil.example>")
    assert "data-terminator" in r.breakout.separators
    assert r.risk.value == "CRITICAL"


# --- mutation ---


def test_mutate_header():
    result = mutate_mail(HDR)
    assert result.context == Context.MAIL_HEADER
    assert result.valid > 0


def test_mutate_smtp_ranks_critical_first():
    result = mutate_mail(SMTP)
    assert result.context == Context.SMTP_COMMAND
    assert result.candidates[0].risk.value == "CRITICAL"


def test_mutate_body():
    result = mutate_mail(BODY)
    assert result.context == Context.MAIL_BODY
    assert result.valid > 0


# --- result shape and CLI ---


def test_result_dialect_is_null():
    data = analyze_mail(HDR, "a\r\nBcc: x@evil.example").to_dict()
    assert data["dialect"] is None
    assert data["context"] == "mail_header"


def test_cli_mail_json(capsys):
    code = main(
        ["--lang", "mail", "--json", SMTP, "a@example.com>\r\nRCPT TO:<b@evil.example"]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "CRITICAL"
    assert data["dialect"] is None
    assert code == 2


def test_cli_mail_mutate(capsys):
    code = main(["-l", "mail", "--mutate", HDR])
    out = capsys.readouterr().out
    assert code == 0
    assert "High probability payloads" in out
