"""LLM provider abstraction.

The agent loop talks to a provider through a small Pydantic-typed interface so
the underlying SDK (openai/DeepSeek today) never leaks past this package.
Swapping to OpenRouter or a local stub is a one-file change.
"""

from __future__ import annotations

from .provider import (
    AssistantMessage,
    ChatMessage,
    ChatResponse,
    LLMProvider,
    LLMProviderError,
    MockLLMProvider,
    ToolCall,
    ToolDefinition,
    Usage,
)

__all__ = [
    "AssistantMessage",
    "ChatMessage",
    "ChatResponse",
    "LLMProvider",
    "LLMProviderError",
    "MockLLMProvider",
    "ToolCall",
    "ToolDefinition",
    "Usage",
]
