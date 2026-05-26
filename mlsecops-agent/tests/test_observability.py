"""Langfuse observability wrapper tests.

Covers three scenarios:

1. No-op when ``LANGFUSE_PUBLIC_KEY`` is unset — the loop produces the same
   transcript as if the wrapper didn't exist.
2. Fail-open when ``LANGFUSE_PUBLIC_KEY`` is set but the ``langfuse`` package
   cannot be imported (simulated via ``sys.modules`` monkeypatching) — the
   loop STILL completes successfully.
3. When ``LANGFUSE_PUBLIC_KEY`` is set and a mock langfuse client is injected,
   generation spans receive the correct input/output payloads.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from mlsecops_agent.agent import run_audit_with_agent
from mlsecops_agent.llm import (
    AssistantMessage,
    ChatResponse,
    LangfuseTracer,
    MockLLMProvider,
)
from mlsecops_agent.llm.tracer import _build_client, _langfuse_enabled

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _response(content: str = "done") -> ChatResponse:
    return ChatResponse(message=AssistantMessage(content=content))


def _make_mock_span() -> MagicMock:
    """Return a MagicMock that satisfies the context manager protocol."""
    span = MagicMock()
    span.__enter__ = MagicMock(return_value=span)
    span.__exit__ = MagicMock(return_value=False)
    return span


def _make_tracer_with_mock_client() -> tuple[LangfuseTracer, MagicMock]:
    """Return a LangfuseTracer wired to a fresh MagicMock client."""
    mock_span = _make_mock_span()
    mock_client = MagicMock()
    mock_client.start_as_current_observation.return_value = mock_span

    tracer = LangfuseTracer.__new__(LangfuseTracer)
    tracer._client = mock_client
    tracer._current_generation = None
    tracer._enabled = True
    return tracer, mock_client


# ---------------------------------------------------------------------------
# Scenario 1: no-op when LANGFUSE_PUBLIC_KEY is absent
# ---------------------------------------------------------------------------


def test_tracer_disabled_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    tracer = LangfuseTracer()
    assert tracer._client is None
    assert not tracer._enabled


def test_loop_produces_same_transcript_without_langfuse_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)

    provider = MockLLMProvider([_response("Audit complete.")])
    transcript = run_audit_with_agent(tmp_path, provider=provider, max_iterations=5)

    assert transcript.final_summary == "Audit complete."
    assert transcript.iterations == 1
    assert transcript.hit_iteration_cap is False
    # system + user + assistant — identical to the no-observability case
    assert len(transcript.messages) == 3


# ---------------------------------------------------------------------------
# Scenario 2: fail-open when langfuse import fails
# ---------------------------------------------------------------------------


def test_build_client_returns_none_on_import_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
    # Simulate package missing: setting sys.modules[key] = None causes ImportError.
    saved = sys.modules.pop("langfuse", None)
    sys.modules["langfuse"] = cast("types.ModuleType", None)
    try:
        client = _build_client()
    finally:
        if saved is not None:
            sys.modules["langfuse"] = saved
        else:
            sys.modules.pop("langfuse", None)

    assert client is None


def test_loop_succeeds_when_langfuse_import_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-test")

    saved = sys.modules.pop("langfuse", None)
    sys.modules["langfuse"] = cast("types.ModuleType", None)
    try:
        provider = MockLLMProvider([_response("Audit complete.")])
        transcript = run_audit_with_agent(tmp_path, provider=provider, max_iterations=5)
    finally:
        if saved is not None:
            sys.modules["langfuse"] = saved
        else:
            sys.modules.pop("langfuse", None)

    assert transcript.final_summary == "Audit complete."
    assert transcript.hit_iteration_cap is False


# ---------------------------------------------------------------------------
# Scenario 3: generation spans receive correct payloads when langfuse is active
# ---------------------------------------------------------------------------


def test_generation_span_receives_input_and_output_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")

    tracer, mock_client = _make_tracer_with_mock_client()
    input_payload: dict[str, Any] = {
        "messages": [{"role": "user", "content": "hello"}],
        "tools": [],
    }

    with tracer.generation(
        "llm.chat",
        input_payload=input_payload,
        model="deepseek-v4-flash",
        metadata={"tier": "default", "iteration": "0"},
    ):
        tracer.update_generation(
            output={"content": "hi", "tool_calls": []},
            usage_details={
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        )

    mock_client.start_as_current_observation.assert_called_once()
    call_kwargs = mock_client.start_as_current_observation.call_args.kwargs
    assert call_kwargs["as_type"] == "generation"
    assert call_kwargs["model"] == "deepseek-v4-flash"
    assert call_kwargs["metadata"]["iteration"] == "0"
    assert call_kwargs["input"]["messages"][0]["role"] == "user"

    mock_span = mock_client.start_as_current_observation.return_value
    mock_span.update.assert_called_once()
    update_kwargs = mock_span.update.call_args.kwargs
    assert update_kwargs["output"]["content"] == "hi"
    assert update_kwargs["usage_details"]["total_tokens"] == 15


def test_trace_context_manager_wraps_audit_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")

    tracer, mock_client = _make_tracer_with_mock_client()

    with tracer.trace("mlsecops.audit:test"):
        pass

    mock_client.start_as_current_observation.assert_called_once_with(
        name="mlsecops.audit:test", as_type="span"
    )


def test_langfuse_enabled_returns_false_without_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    assert _langfuse_enabled() is False


def test_langfuse_enabled_returns_true_with_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-anything")
    assert _langfuse_enabled() is True


def test_trace_metadata_threaded_into_mock_provider_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Iteration index appears in each chat() call's trace_metadata."""
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)

    from mlsecops_agent.llm import ToolCall

    tool_call = ToolCall(id="tc1", name="list_checks", arguments={})
    provider = MockLLMProvider(
        [
            ChatResponse(message=AssistantMessage(tool_calls=[tool_call])),
            _response("done"),
        ]
    )
    run_audit_with_agent(tmp_path, provider=provider, max_iterations=5)

    assert provider.calls[0]["trace_metadata"] == {"iteration": "0"}
    assert provider.calls[1]["trace_metadata"] == {"iteration": "1"}
