"""Pydantic types shared across the agent loop, checks, storage, and reporting.

Every value that crosses a process or I/O boundary lives here. If a new field
is needed, write an ADR before adding it — the schema is the contract.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckName(StrEnum):
    LEAKAGE = "leakage"
    DESERIALIZATION = "deserialization"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply_chain"
    ADVERSARIAL = "adversarial"
    # Synthetic "check" populated by scenarios.synthesise_scenarios — chains
    # findings from the five detection checks into named threat patterns.
    # Never has a runner registered in checks.CHECKS.
    SCENARIO = "scenario"


class FixProposal(BaseModel):
    """A suggested fix for a Finding. Either a unified diff or a replacement snippet."""

    summary: str
    diff: str | None = None
    replacement: str | None = None
    confidence: Literal["low", "medium", "high"]


class Finding(BaseModel):
    """A single audit result. Always produced by a deterministic tool, never by an LLM alone."""

    id: str = Field(description="Stable identifier: '<check>.<kebab-rule>'. Never reused.")
    check: CheckName
    severity: Severity
    category: str
    file: Path
    line_start: int | None = None
    line_end: int | None = None
    message: str
    evidence: str = Field(description="Raw tool output excerpt that produced this finding.")
    fix: FixProposal | None = None


class CheckResult(BaseModel):
    """Outcome of running one check. Empty `findings` = clean."""

    check: CheckName
    findings: list[Finding] = Field(default_factory=list)
    tool_status: Literal["ok", "tool_missing", "tool_error"] = "ok"
    duration_ms: int


class RunContext(BaseModel):
    """The agent's per-invocation handle. Passed to every check."""

    model_config = {"arbitrary_types_allowed": True}

    run_id: str
    target_path: Path
    db_path: Path
    sandbox_enabled: bool = True


class MLSecOpsError(Exception):
    """Base exception for project-internal errors."""


class CheckError(MLSecOpsError):
    """Raised when a check fails for reasons other than 'issue found'."""


class ToolError(MLSecOpsError):
    """Raised when an external tool wrapper fails (missing binary, malformed output)."""


class SandboxError(MLSecOpsError):
    """Raised when the sandbox is unreachable or rejects an operation."""
