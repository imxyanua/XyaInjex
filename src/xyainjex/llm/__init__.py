"""Optional LLM-assisted analysis.

The deterministic analyzer stays the source of truth. An LLM is used only as an
advisor: it proposes candidate payloads which are then validated by the engine,
and it can explain a result in natural language. Providers are optional and lazy
loaded, so importing this package never requires an LLM SDK.
"""

from .assist import Suggestion, SuggestResult, explain, suggest_payloads
from .providers import (
    ClaudeProvider,
    LLMProvider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
    get_provider,
)

__all__ = [
    "suggest_payloads",
    "explain",
    "Suggestion",
    "SuggestResult",
    "LLMProvider",
    "MockProvider",
    "OpenAIProvider",
    "ClaudeProvider",
    "OllamaProvider",
    "get_provider",
]
