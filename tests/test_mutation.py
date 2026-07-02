from xyainjex import Context
from xyainjex.mutation import mutate


def test_mutate_double_quote_finds_candidates():
    result = mutate('curl "{INPUT}"', command="id")
    assert result.context == Context.DOUBLE_QUOTE
    assert result.generated > 0
    assert result.valid > 0
    # Every reported candidate must actually inject a command.
    assert all(c.command_injected for c in result.candidates)


def test_mutate_high_probability_are_critical_first():
    result = mutate('curl "{INPUT}"', command="id")
    top = result.candidates[0]
    assert top.risk.value == "CRITICAL"


def test_mutate_unquoted():
    result = mutate("ping {INPUT}", command="id")
    assert result.context == Context.UNQUOTED
    assert result.valid > 0


def test_mutate_to_dict_shape():
    result = mutate('curl "{INPUT}"')
    data = result.to_dict()
    assert set(["template", "context", "generated", "valid", "high_probability"]).issubset(
        data.keys()
    )
    assert isinstance(data["high_probability"], list)
