"""SQLite run history.

The CLI ``audit`` and ``agent`` commands persist every run plus its findings
so users can compare runs over time and the eval harness can score a check's
behavior change across versions.
"""

from __future__ import annotations

from .db import Repository, init_db

__all__ = ["Repository", "init_db"]
