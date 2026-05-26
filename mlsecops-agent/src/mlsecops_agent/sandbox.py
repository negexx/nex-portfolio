"""Sandbox abstraction for executing audited ML code in isolation.

**This module is a contract stub.** The MVP runs target ML code in-process,
which is fine for static checks (supply_chain, secrets, deserialization,
leakage) but breaks the threat model for the ``adversarial`` check, which
calls ``tf.keras.models.load_model`` on user-supplied ``.h5`` / ``.keras``
files. Those files are arbitrary-code-execution vectors — exactly what the
project warns about.

A live implementation (Vercel Sandbox or e2b — see
``.claude/docs/decisions/0005-sandbox.md``) will land before the project
accepts target repos from anywhere but the operator's own machine.

Usage when the live backend lands:

    >>> sb = Sandbox.from_env()                            # picks Vercel or e2b
    >>> with sb.session(timeout_s=300) as s:
    ...     s.upload(target_dir)
    ...     result = s.run("python -m mlsecops_agent run_check adversarial ./model.h5")
    ...     findings = json.loads(result.stdout)

Callers that need the sandbox today should treat its absence as a hard
failure rather than silently degrading to in-process execution.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


SandboxBackend = Literal["vercel", "e2b", "none"]


class SandboxNotConfigured(RuntimeError):
    """Raised when sandbox isolation is requested but no backend is wired."""


class Sandbox:
    """Stub interface. The methods below all raise ``SandboxNotConfigured``."""

    def __init__(self, backend: SandboxBackend = "none") -> None:
        self.backend = backend

    @classmethod
    def from_env(cls) -> "Sandbox":
        """Resolve the configured backend from environment variables.

        Currently always returns the ``none`` stub. Implementation lands when
        the Vercel Sandbox / e2b integration ships — see ADR 0005.
        """
        if os.environ.get("VERCEL_TOKEN"):
            return cls(backend="vercel")
        if os.environ.get("E2B_API_KEY"):
            return cls(backend="e2b")
        return cls(backend="none")

    def session(self, *, timeout_s: int = 300) -> "SandboxSession":  # noqa: ARG002
        if self.backend == "none":
            raise SandboxNotConfigured(
                "No sandbox backend configured. Set VERCEL_TOKEN or E2B_API_KEY "
                "to enable isolated execution of target ML code. See ADR 0005."
            )
        raise NotImplementedError(
            f"Sandbox backend {self.backend!r} is wired in env but not implemented yet."
        )


class SandboxSession:
    """Per-run session against a live sandbox. Stub for now."""

    def __enter__(self) -> "SandboxSession":  # pragma: no cover — never reached
        return self

    def __exit__(self, *_args: object) -> None:  # pragma: no cover
        return

    def upload(self, _local_path: "Path") -> None:  # pragma: no cover
        raise NotImplementedError

    def run(self, _command: str) -> "SandboxRunResult":  # pragma: no cover
        raise NotImplementedError

    def iter_results(self) -> "Iterator[str]":  # pragma: no cover
        raise NotImplementedError


class SandboxRunResult:
    """Result of a single command executed inside the sandbox. Stub."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
