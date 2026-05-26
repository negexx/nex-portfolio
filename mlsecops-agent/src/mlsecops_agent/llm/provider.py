"""LLM provider abstraction.

Wraps an OpenAI-compatible chat-completions client (DeepSeek by default) behind
a narrow Pydantic-typed surface.  Nothing outside this module imports the
``openai`` SDK directly — that keeps the project's blast radius tiny when we
need to swap providers (OpenRouter, a local stub, a future SDK).

Two implementations live here:

- :class:`LLMProvider` — real client; lazy-imports ``openai`` so the SDK is
  only required at the point of an actual API call.  Tests never trigger it.
- :class:`MockLLMProvider` — returns a pre-canned list of :class:`ChatResponse`
  in order.  Used exclusively by the test suite so we never make live calls.

Configuration is via environment variables (all read with ``os.environ.get`` so
the defaults are documented in code, not magic strings scattered around):

- ``DEEPSEEK_API_KEY``       (required at call-time)
- ``DEEPSEEK_BASE_URL``      (default ``https://api.deepseek.com/v1``)
- ``DEEPSEEK_MODEL_DEFAULT`` (default ``deepseek-v4-flash``)
- ``DEEPSEEK_MODEL_HARD``    (default ``deepseek-v4-pro``)
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Literal, cast

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from collections.abc import Sequence

    from openai.types.chat import (
        ChatCompletionMessageParam,
        ChatCompletionToolParam,
    )


DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_MODEL_DEFAULT = "deepseek-v4-flash"
DEFAULT_MODEL_HARD = "deepseek-v4-pro"

Tier = Literal["default", "hard"]


class LLMProviderError(RuntimeError):
    """Raised for any provider-layer failure (missing key, transport, malformed reply)."""


class ToolDefinition(BaseModel):
    """OpenAI-style ``tools`` entry.

    ``parameters`` is the JSON Schema for the tool's arguments.  We model it as
    a free-form mapping rather than a typed schema because the schema *is* the
    data — each tool defines its own shape.
    """

    name: str
    description: str
    parameters: dict[str, object]


class ToolCall(BaseModel):
    """A single tool invocation requested by the assistant."""

    id: str
    name: str
    arguments: dict[str, object] = Field(default_factory=dict)


class ChatMessage(BaseModel):
    """A message in the chat transcript.

    ``role`` follows OpenAI's convention.  For ``"tool"`` messages the
    ``tool_call_id`` is required so the provider can wire the result back to
    the originating call.
    """

    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


class Usage(BaseModel):
    """Token usage for one completion."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class AssistantMessage(BaseModel):
    """Assistant turn extracted from a chat completion."""

    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


class ChatResponse(BaseModel):
    """A single completion result, normalized away from the openai SDK shape."""

    message: AssistantMessage
    usage: Usage = Field(default_factory=Usage)
    model: str = ""
    tier: Tier = "default"


def _parse_tool_arguments(raw: str | None) -> dict[str, object]:
    """Parse a tool-call ``arguments`` JSON blob into a dict.

    The OpenAI tool-call spec sends arguments as a JSON-encoded string.  We
    surface ``LLMProviderError`` on malformed payloads — the agent loop catches
    it and reports back to the LLM as a tool error rather than crashing.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMProviderError(f"tool arguments are not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMProviderError("tool arguments JSON must decode to an object")
    # Re-key to make mypy happy — dict[str, object] is what we promised.
    return {str(k): v for k, v in parsed.items()}


class LLMProvider:
    """Real provider hitting an OpenAI-compatible chat-completions endpoint.

    The ``openai`` SDK is imported lazily inside :meth:`chat` so that test
    runs never touch it (and so a missing optional dep at import time can't
    take the whole CLI down).
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model_default: str | None = None,
        model_hard: str | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self._base_url = base_url or os.environ.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL)
        self._model_default = model_default or os.environ.get(
            "DEEPSEEK_MODEL_DEFAULT", DEFAULT_MODEL_DEFAULT
        )
        self._model_hard = model_hard or os.environ.get(
            "DEEPSEEK_MODEL_HARD", DEFAULT_MODEL_HARD
        )

    def _model_for_tier(self, tier: Tier) -> str:
        return self._model_hard if tier == "hard" else self._model_default

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolDefinition] | None = None,
        tier: Tier = "default",
    ) -> ChatResponse:
        """Call the chat-completions endpoint and return a normalized response.

        Raises :class:`LLMProviderError` when the API key is missing, the SDK
        cannot be imported, or the upstream call fails.
        """
        if not self._api_key:
            raise LLMProviderError(
                "DEEPSEEK_API_KEY is not set — export it or pass api_key= explicitly. "
                "See .env.example."
            )

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMProviderError(
                "openai SDK is not installed — `uv sync` to install runtime deps."
            ) from exc

        client = OpenAI(api_key=self._api_key, base_url=self._base_url)
        model = self._model_for_tier(tier)

        payload_messages = cast(
            "list[ChatCompletionMessageParam]",
            [self._serialize_message(m) for m in messages],
        )
        payload_tools = (
            cast(
                "list[ChatCompletionToolParam]",
                [self._serialize_tool(t) for t in tools],
            )
            if tools
            else None
        )

        try:
            if payload_tools is not None:
                completion = client.chat.completions.create(
                    model=model,
                    messages=payload_messages,
                    tools=payload_tools,
                )
            else:
                completion = client.chat.completions.create(
                    model=model,
                    messages=payload_messages,
                )
        except Exception as exc:
            raise LLMProviderError(f"upstream chat-completions call failed: {exc}") from exc

        return self._normalize_completion(completion, model=model, tier=tier)

    @staticmethod
    def _serialize_message(message: ChatMessage) -> dict[str, object]:
        """Map a ChatMessage to the OpenAI chat-completions JSON shape."""
        payload: dict[str, object] = {"role": message.role, "content": message.content}
        if message.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in message.tool_calls
            ]
        if message.tool_call_id is not None:
            payload["tool_call_id"] = message.tool_call_id
        if message.name is not None:
            payload["name"] = message.name
        return payload

    @staticmethod
    def _serialize_tool(tool: ToolDefinition) -> dict[str, object]:
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }

    @staticmethod
    def _normalize_completion(
        completion: object,
        *,
        model: str,
        tier: Tier,
    ) -> ChatResponse:
        """Extract the parts we care about from a raw openai completion."""
        # The openai SDK returns pydantic-like objects; we access them dynamically
        # and validate as we go so the rest of the codebase never sees their types.
        choices = getattr(completion, "choices", None)
        if not choices:
            raise LLMProviderError("chat completion returned no choices")
        first = choices[0]
        raw_message = getattr(first, "message", None)
        if raw_message is None:
            raise LLMProviderError("chat completion choice has no message")

        content_value = getattr(raw_message, "content", None) or ""
        if not isinstance(content_value, str):
            content_value = str(content_value)

        tool_calls: list[ToolCall] = []
        raw_tool_calls = getattr(raw_message, "tool_calls", None) or []
        for raw_tc in raw_tool_calls:
            tc_id = getattr(raw_tc, "id", None) or ""
            function = getattr(raw_tc, "function", None)
            if function is None:
                continue
            name = getattr(function, "name", None) or ""
            arguments = _parse_tool_arguments(getattr(function, "arguments", None))
            tool_calls.append(ToolCall(id=tc_id, name=name, arguments=arguments))

        raw_usage = getattr(completion, "usage", None)
        usage = Usage()
        if raw_usage is not None:
            usage = Usage(
                prompt_tokens=int(getattr(raw_usage, "prompt_tokens", 0) or 0),
                completion_tokens=int(getattr(raw_usage, "completion_tokens", 0) or 0),
                total_tokens=int(getattr(raw_usage, "total_tokens", 0) or 0),
            )

        return ChatResponse(
            message=AssistantMessage(content=content_value, tool_calls=tool_calls),
            usage=usage,
            model=model,
            tier=tier,
        )


class MockLLMProvider:
    """In-memory provider returning canned :class:`ChatResponse` values in order.

    Used by the test suite so we never need an API key or network access.  When
    the canned list is exhausted, the next ``chat`` call raises
    :class:`LLMProviderError` rather than hanging or returning ``None`` —
    silent fall-off is a debugging nightmare.

    The mock also captures every call (``calls``) so tests can assert on the
    exact messages and tool definitions the agent sent.
    """

    def __init__(self, responses: Sequence[ChatResponse]) -> None:
        self._responses: list[ChatResponse] = list(responses)
        self._cursor = 0
        self.calls: list[dict[str, object]] = []

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[ToolDefinition] | None = None,
        tier: Tier = "default",
    ) -> ChatResponse:
        self.calls.append(
            {
                "messages": [m.model_dump() for m in messages],
                "tools": [t.model_dump() for t in (tools or [])],
                "tier": tier,
            }
        )
        if self._cursor >= len(self._responses):
            raise LLMProviderError(
                f"MockLLMProvider exhausted: {len(self._responses)} canned response(s) "
                "consumed, but the agent asked for another."
            )
        response = self._responses[self._cursor]
        self._cursor += 1
        return response

    @property
    def remaining(self) -> int:
        return len(self._responses) - self._cursor
