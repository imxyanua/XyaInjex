import pytest

from xyainjex import MockProvider, analyze, explain, get_provider, suggest_payloads
from xyainjex.cli import main
from xyainjex.llm import ClaudeProvider, OpenAIProvider

# --- providers ---


def test_mock_responses_in_order():
    p = MockProvider(responses=["a", "b"])
    assert p.complete("x") == "a"
    assert p.complete("x") == "b"
    assert p.complete("x") == "b"  # last repeats


def test_mock_handler():
    p = MockProvider(handler=lambda prompt, system: f"got:{prompt}")
    assert p.complete("hello") == "got:hello"


def test_get_provider_mock():
    assert isinstance(get_provider("mock"), MockProvider)


def test_get_provider_unknown_raises():
    with pytest.raises(ValueError):
        get_provider("bogus")


def test_provider_classes_exist():
    # The optional backends import lazily; the classes are always importable.
    assert OpenAIProvider is not None
    assert ClaudeProvider is not None


# --- suggest_payloads (LLM proposes, engine validates) ---


def test_suggest_keeps_only_injecting_payloads():
    provider = MockProvider(responses=['plain-host\n"; id ; #\n"$(id)"\nnot-a-payload'])
    result = suggest_payloads('curl "{INPUT}"', provider, lang="shell")
    payloads = [s.payload for s in result.validated]
    assert '"; id ; #' in payloads
    assert '"$(id)"' in payloads
    assert "plain-host" not in payloads
    assert "not-a-payload" not in payloads


def test_suggest_ranks_critical_first():
    provider = MockProvider(responses=['"$(id)"\n"; id ; #'])
    result = suggest_payloads('curl "{INPUT}"', provider, lang="shell")
    assert result.validated[0].risk.value == "CRITICAL"


def test_suggest_strips_list_markers_and_fences():
    provider = MockProvider(responses=['```\n1. "; id ; #\n- "; whoami ; #\n```'])
    result = suggest_payloads('curl "{INPUT}"', provider, lang="shell")
    assert result.proposed == 2
    assert all(not p.payload.startswith(("-", "1.")) for p in result.validated)


def test_suggest_sql():
    provider = MockProvider(responses=["' OR 1=1 -- \nbenign"])
    result = suggest_payloads(
        "SELECT * FROM t WHERE a = '{INPUT}'", provider, lang="sql"
    )
    assert len(result.validated) == 1
    assert result.validated[0].risk.value == "CRITICAL"


def test_suggest_empty_reply():
    result = suggest_payloads('curl "{INPUT}"', MockProvider(), lang="shell")
    assert result.proposed == 0
    assert result.validated == []


def test_suggest_rejects_prompt_lang():
    with pytest.raises(ValueError):
        suggest_payloads("{INPUT}", MockProvider(), lang="prompt")


def test_suggest_to_dict():
    provider = MockProvider(responses=['"; id ; #'])
    data = suggest_payloads('curl "{INPUT}"', provider, lang="shell").to_dict()
    assert data["valid"] == 1
    assert data["validated"][0]["command_injected"] is True


# --- explain ---


def test_explain_uses_provider():
    seen = {}

    def handler(prompt, system):
        seen["prompt"] = prompt
        return "explanation text"

    result = analyze('curl "{INPUT}"', '"; id ; #')
    text = explain(result, MockProvider(handler=handler))
    assert text == "explanation text"
    assert "CRITICAL" in seen["prompt"]
    assert "double_quote" in seen["prompt"]


# --- CLI ---


def test_cli_ai_suggest_empty_mock(capsys):
    # The mock provider returns nothing, so no payloads are validated.
    code = main(["--ai-suggest", "--provider", "mock", 'curl "{INPUT}"'])
    out = capsys.readouterr().out
    assert code == 0
    assert "No proposed payload" in out


def test_cli_ai_unknown_provider(capsys):
    code = main(["--ai-suggest", "--provider", "bogus", 'curl "{INPUT}"'])
    assert code == 1
    assert "unknown provider" in capsys.readouterr().err
