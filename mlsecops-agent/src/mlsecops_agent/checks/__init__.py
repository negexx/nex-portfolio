"""Audit checks. Each module exports ``run(target: Path) -> CheckResult``.

The CLI and the agent loop both look up checks through ``CHECKS`` rather than
importing modules directly — keeps the dispatch table the single source of truth
for what's wired up.

``CheckRunner`` is typed as ``Callable[..., CheckResult]`` (rather than the
narrower ``Callable[[Path], CheckResult]``) because ``adversarial.run`` accepts
an optional keyword argument ``include_adversarial``.  The CLI and agent loop
only ever call ``runner(target)`` positionally, so the looser type is safe —
the extra parameter simply defaults.  Narrowing here would either require a
wrapper shim that discards the useful kwarg or a Union type that buys nothing.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import CheckName, CheckResult
from . import adversarial, deserialization, leakage, secrets, supply_chain

# Callable[..., CheckResult] — see module docstring for the rationale.
CheckRunner = Callable[..., CheckResult]

CHECKS: dict[CheckName, CheckRunner] = {
    CheckName.SUPPLY_CHAIN: supply_chain.run,
    CheckName.DESERIALIZATION: deserialization.run,
    CheckName.SECRETS: secrets.run,
    CheckName.LEAKAGE: leakage.run,
    CheckName.ADVERSARIAL: adversarial.run,
}

__all__ = ["CHECKS", "CheckRunner"]
