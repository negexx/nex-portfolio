"""Report renderers. The CLI calls these; the agent loop (W3) will too."""

from __future__ import annotations

from .markdown import render_markdown
from .sarif import render_sarif

__all__ = ["render_markdown", "render_sarif"]
