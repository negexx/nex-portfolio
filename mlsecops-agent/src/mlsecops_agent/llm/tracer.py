"""Langfuse observability wrapper for LLM calls.

Design rationale
----------------
This module sits between ``LLMProvider.chat()`` and the Langfuse SDK so that:

1. If ``LANGFUSE_PUBLIC_KEY`` is absent the tracer is a no-op — the rest of
   the codebase never knows Langfuse exists.
2. If the ``langfuse`` package cannot be imported (e.g. a minimal test
   environment), the same no-op path is taken.  Import failures are treated
   identically to "env not set".
3. The public surface of ``LLMProvider`` is unchanged except for an optional
   ``trace_metadata`` kwarg added to ``chat()``.

All langfuse types are confined to this module.  The rest of the codebase only
imports ``LangfuseTracer`` — a concrete class whose public methods return plain
context managers that yield ``None``.  That makes the wrapper transparent to
callers that ignore the yielded value.
"""

from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    import langfuse as _langfuse_mod


def _langfuse_enabled() -> bool:
    """Return True only when the minimum required env vars are present."""
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY"))


class LangfuseTracer:
    """Thin wrapper around the Langfuse SDK that degrades to a no-op.

    Instantiate once (typically inside ``LLMProvider.__init__``) and call
    :meth:`trace` / :meth:`generation` around the relevant code sections.
    Both methods are context managers; the yielded value is ``None`` when
    tracing is disabled or unavailable.
    """

    def __init__(self) -> None:
        self._client: _langfuse_mod.Langfuse | None = None
        self._current_generation: _langfuse_mod.LangfuseGeneration | None = None
        self._enabled = _langfuse_enabled()
        if self._enabled:
            self._client = _build_client()

    # ------------------------------------------------------------------
    # Public context-manager API
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def trace(self, name: str) -> Iterator[None]:
        """Context manager that wraps a top-level trace (e.g. one audit run)."""
        if self._client is None:
            yield
            return
        try:
            # ``start_as_current_observation`` as_type="span" is the top-level
            # container; Langfuse calls this a "trace root".
            with self._client.start_as_current_observation(name=name, as_type="span"):
                yield
        except Exception:
            yield

    @contextlib.contextmanager
    def generation(
        self,
        name: str,
        *,
        input_payload: object = None,
        model: str = "",
        metadata: dict[str, str] | None = None,
    ) -> Iterator[None]:
        """Context manager that wraps a single LLM call as a generation span.

        The yielded value is intentionally ``None`` — callers use
        :meth:`update_generation` to attach output and usage after the call.
        """
        if self._client is None:
            yield
            return
        try:
            with self._client.start_as_current_observation(
                name=name,
                as_type="generation",
                input=input_payload,
                model=model or None,
                metadata=metadata,
            ) as gen_span:
                self._current_generation = gen_span
                yield
                self._current_generation = None
        except Exception:
            yield

    def update_generation(
        self,
        *,
        output: object = None,
        usage_details: dict[str, int] | None = None,
    ) -> None:
        """Attach output and token usage to the in-flight generation span."""
        span = self._current_generation
        if span is None:
            return
        with contextlib.suppress(Exception):
            span.update(output=output, usage_details=usage_details)


def _build_client() -> _langfuse_mod.Langfuse | None:
    """Lazy-import langfuse and return an initialised client, or None."""
    try:
        import langfuse  # TCH002 — intentional lazy import, not for TYPE_CHECKING

        host = os.environ.get("LANGFUSE_HOST", "https://cloud.langfuse.com")
        return langfuse.Langfuse(host=host)
    except Exception:
        return None
