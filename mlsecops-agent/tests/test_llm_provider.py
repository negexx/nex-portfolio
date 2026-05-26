"""Provider-layer tests.

These never touch the network. They cover:

- MockLLMProvider hands out canned responses in order and raises when drained.
- MockLLMProvider records the calls it received so agent-loop tests can assert
  on the exact messages sent.
- LLMProvider raises a clear error when DEEPSEEK_API_KEY is missing and a
  ``chat`` call is attempted.
"""

from __future__ import annotations

import pytest

from mlsecops_agent.llm import (
    AssistantMessage,
    ChatMessage,
    ChatResponse,
    LLMProvider,
    LLMProviderError,
    MockLLMProvider,
)


def _response(content: str = "ok") -> ChatResponse:
    return ChatResponse(message=AssistantMessage(content=content))


def test_mock_provider_returns_responses_in_order() -> None:
    provider = MockLLMProvider([_response("first"), _response("second")])
    msgs = [ChatMessage(role="user", content="hi")]

    r1 = provider.chat(msgs)
    r2 = provider.chat(msgs)

    assert r1.message.content == "first"
    assert r2.message.content == "second"
    assert provider.remaining == 0


def test_mock_provider_raises_when_drained() -> None:
    provider = MockLLMProvider([_response()])
    msgs = [ChatMessage(role="user", content="hi")]
    provider.chat(msgs)

    with pytest.raises(LLMProviderError, match="exhausted"):
        provider.chat(msgs)


def test_mock_provider_captures_calls() -> None:
    provider = MockLLMProvider([_response()])
    msgs = [ChatMessage(role="user", content="audit this")]
    provider.chat(msgs)

    assert len(provider.calls) == 1
    captured = provider.calls[0]
    assert captured["tier"] == "default"
    # `messages` is the model_dump'd form
    captured_msgs = captured["messages"]
    assert isinstance(captured_msgs, list)
    assert captured_msgs[0]["content"] == "audit this"


def test_real_provider_errors_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    provider = LLMProvider(api_key=None)
    msgs = [ChatMessage(role="user", content="hi")]

    with pytest.raises(LLMProviderError, match="DEEPSEEK_API_KEY"):
        provider.chat(msgs)
