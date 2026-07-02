"""LLM provider abstraction with a deterministic mock and optional backends."""

from __future__ import annotations

import json
import os
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence


class LLMProvider(ABC):
    """A minimal text completion interface."""

    @abstractmethod
    def complete(self, prompt: str, *, system: str | None = None) -> str:
        """Return the model's completion for ``prompt``."""


class MockProvider(LLMProvider):
    """A deterministic provider for testing and offline demos.

    Supply ``handler`` to compute a reply from the prompt, or ``responses`` to
    return canned replies in order (the last is repeated once exhausted).
    """

    def __init__(
        self,
        responses: Sequence[str] | None = None,
        handler: Callable[[str, str | None], str] | None = None,
    ) -> None:
        self._responses = list(responses) if responses else []
        self._handler = handler
        self._i = 0

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        if self._handler is not None:
            return self._handler(prompt, system)
        if not self._responses:
            return ""
        if self._i < len(self._responses):
            reply = self._responses[self._i]
            self._i += 1
            return reply
        return self._responses[-1]


class OpenAIProvider(LLMProvider):  # pragma: no cover - requires the SDK and a key
    """OpenAI Chat Completions backend (requires the ``openai`` package)."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "the OpenAI provider requires `pip install openai`"
            ) from exc
        self._client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))
        self._model = model

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = self._client.chat.completions.create(
            model=self._model, messages=messages, temperature=0
        )
        return resp.choices[0].message.content or ""


class ClaudeProvider(LLMProvider):  # pragma: no cover - requires the SDK and a key
    """Anthropic Claude backend (requires the ``anthropic`` package)."""

    def __init__(
        self, model: str = "claude-sonnet-5", api_key: str | None = None
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "the Claude provider requires `pip install anthropic`"
            ) from exc
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._model = model

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in resp.content if block.type == "text")


class OllamaProvider(LLMProvider):  # pragma: no cover - requires a running server
    """Local Ollama backend over HTTP (no extra dependency)."""

    def __init__(
        self, model: str = "llama3", host: str = "http://localhost:11434"
    ) -> None:
        self._model = model
        self._host = host.rstrip("/")

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        body = {
            "model": self._model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {"temperature": 0},
        }
        req = urllib.request.Request(
            f"{self._host}/api/generate",
            data=json.dumps(body).encode(),
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read()).get("response", "")


def get_provider(name: str, **kwargs) -> LLMProvider:
    """Construct a provider by name (mock, openai, claude, ollama)."""
    key = name.strip().lower()
    if key in ("mock", "test"):
        return MockProvider(**kwargs)
    if key in ("openai", "gpt"):
        return OpenAIProvider(**kwargs)
    if key in ("claude", "anthropic"):
        return ClaudeProvider(**kwargs)
    if key in ("ollama", "local"):
        return OllamaProvider(**kwargs)
    raise ValueError(
        f"unknown provider {name!r}; valid values: mock, openai, claude, ollama"
    )
