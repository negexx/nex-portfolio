"""Agent prompts.

The system prompt is loaded from ``system.md`` (a sibling file) so it can be
edited and reviewed independently of the code that uses it.
"""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).resolve().parent


def load_system_prompt() -> str:
    """Return the agent's system prompt.

    Reading from disk on every call keeps things simple and lets tests swap the
    file without restarting the interpreter.  The prompt is small (<400 tokens)
    so the I/O cost is irrelevant.
    """
    return (_PROMPTS_DIR / "system.md").read_text(encoding="utf-8")


__all__ = ["load_system_prompt"]
