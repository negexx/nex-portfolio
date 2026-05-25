"""Audit checks. Each module exports ``run(target: Path) -> CheckResult``.

The CLI and the agent loop both look up checks through ``CHECKS`` rather than
importing modules directly — keeps the dispatch table the single source of truth
for what's wired up.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..models import CheckName, CheckResult
from . import deserialization, supply_chain

CheckRunner = Callable[[Path], CheckResult]

CHECKS: dict[CheckName, CheckRunner] = {
    CheckName.SUPPLY_CHAIN: supply_chain.run,
    CheckName.DESERIALIZATION: deserialization.run,
    # leakage, secrets, adversarial — coming next.
}

__all__ = ["CHECKS", "CheckRunner"]
