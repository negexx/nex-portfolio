"""LLM-orchestrated audit loop.

Runs the registered checks through an LLM that decides sequencing and authors
fix narratives, while every actual *finding* still comes from a deterministic
check tool.  The loop is the unit under test — pass a
:class:`~mlsecops_agent.llm.MockLLMProvider` and you can exercise every code
path without a network or an API key.

The three tools the LLM can call:

- ``list_checks``   — list registered checks and one-line descriptions.
- ``run_check``     — invoke one check against the target, return findings.
- ``propose_fix``   — record an LLM-authored fix against a finding produced
  earlier in the same run.
- ``judge_finding`` — ask the LLM whether a deterministic candidate is a real
  issue. The LLM cannot invent findings; it can only confirm/downgrade an
  existing AST hit, identified by ``(rule_id, file, line_start)``.

Any other tool name, malformed arguments, or unknown finding id is reported
back to the LLM as a structured tool error so it can recover, rather than
crashing the loop.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from .checks import CHECKS
from .llm import (
    ChatMessage,
    LangfuseTracer,
    LLMProvider,
    MockLLMProvider,
    ToolCall,
    ToolDefinition,
)
from .models import CheckName, CheckResult, Finding, FixProposal, Severity
from .prompts import load_system_prompt

# ---------------------------------------------------------------------------
# Tool I/O schemas
# ---------------------------------------------------------------------------


class ListChecksArgs(BaseModel):
    """``list_checks`` takes no arguments — declared empty for schema clarity."""


class RunCheckArgs(BaseModel):
    """Arguments accepted by the ``run_check`` tool."""

    check: str
    target: str
    include_adversarial: bool = False


class ProposeFixArgs(BaseModel):
    """Arguments accepted by the ``propose_fix`` tool."""

    finding_id_in_run: int = Field(
        description="Zero-based index into the run's collected findings list."
    )
    narrative: str


class JudgeFindingArgs(BaseModel):
    """Arguments accepted by the ``judge_finding`` tool.

    The (rule_id, file, line_start) triple must match an existing in-flight
    finding exactly — the LLM cannot invent a new one.
    """

    rule_id: str
    file: str
    line_start: int
    evidence: str
    confirmed: bool
    confidence: Literal["low", "medium", "high"]
    reasoning: str


class Verdict(BaseModel):
    """The LLM's judgement on an AST-flagged candidate."""

    confirmed: bool
    confidence: Literal["low", "medium", "high"]
    reasoning: str


class JudgeFindingResult(BaseModel):
    """Confirmation payload returned by ``judge_finding``."""

    ok: Literal[True]
    rule_id: str
    file: str
    line_start: int
    previous_severity: str
    new_severity: str
    previous_fix_confidence: str | None
    new_fix_confidence: str | None
    verdict: Verdict


class CheckSummary(BaseModel):
    """Shape returned by ``list_checks``."""

    name: str
    description: str


class FindingSummary(BaseModel):
    """Trimmed finding shape returned by ``run_check``.

    ``evidence`` is dropped to keep the LLM's context budget low; the agent can
    re-query a check or read the report if it needs the raw text.
    """

    finding_id_in_run: int
    rule_id: str
    severity: str
    file: str
    line_start: int | None
    message: str


class RunCheckResult(BaseModel):
    """Shape returned by ``run_check``."""

    check: str
    tool_status: str
    duration_ms: int
    findings: list[FindingSummary]


class FixProposalRecord(BaseModel):
    """One LLM-authored fix narrative attached to a finding from the current run."""

    finding_id_in_run: int
    rule_id: str
    file: str
    line_start: int | None
    narrative: str


class ToolErrorPayload(BaseModel):
    """Structured error returned to the LLM when a tool call cannot proceed."""

    error: str
    detail: str


class AuditTranscript(BaseModel):
    """The full record of an LLM-orchestrated audit run."""

    target: Path
    messages: list[ChatMessage]
    final_summary: str
    findings: list[Finding]
    fix_proposals: list[FixProposalRecord]
    iterations: int
    hit_iteration_cap: bool


# ---------------------------------------------------------------------------
# Static descriptions — kept here (not in checks/__init__.py) because they're
# only relevant to the LLM's tool catalog, not to deterministic dispatch.
# ---------------------------------------------------------------------------

_CHECK_DESCRIPTIONS: dict[CheckName, str] = {
    CheckName.LEAKAGE: (
        "Data-leakage detector — flags preprocessing fitted before train/test split, "
        "fit-on-test mistakes, and SMOTE/resampling before split."
    ),
    CheckName.DESERIALIZATION: (
        "Insecure deserialization — flags pickle.load, joblib.load, torch.load without "
        "weights_only, and numpy.load with allow_pickle=True."
    ),
    CheckName.SECRETS: (
        "Secrets scanner — hardcoded credentials in source plus leaks in committed "
        "notebook outputs (escalated severity)."
    ),
    CheckName.SUPPLY_CHAIN: (
        "Supply-chain hygiene — unpinned `!pip install`, untrusted downloads with no "
        "checksum, unpinned requirements.txt entries, and CVEs via pip-audit."
    ),
    CheckName.ADVERSARIAL: (
        "Adversarial robustness — loads saved Keras models and runs FGSM evasion. "
        "Opt-in: pass include_adversarial=true."
    ),
}


# ---------------------------------------------------------------------------
# OpenAI-format tool definitions
# ---------------------------------------------------------------------------


def _tool_definitions() -> list[ToolDefinition]:
    """Build the JSON-schema tool specs the LLM sees."""
    return [
        ToolDefinition(
            name="list_checks",
            description=(
                "List every check registered in this audit agent, with a one-line "
                "description of each. Call this first to discover what is available."
            ),
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="run_check",
            description=(
                "Run one named check against the target path and return the findings. "
                "Findings are produced deterministically — they are ground truth, not "
                "suggestions to be filtered by your own judgement."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "check": {
                        "type": "string",
                        "description": (
                            "Check name. One of: "
                            + ", ".join(c.value for c in CheckName)
                        ),
                    },
                    "target": {
                        "type": "string",
                        "description": "Filesystem path to audit (file or directory).",
                    },
                    "include_adversarial": {
                        "type": "boolean",
                        "description": (
                            "Only meaningful for the adversarial check. Set true to "
                            "actually run FGSM evasion (loads TensorFlow). Default false."
                        ),
                        "default": False,
                    },
                },
                "required": ["check", "target"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="propose_fix",
            description=(
                "Record a fix narrative against a finding from the current run. "
                "Use the finding_id_in_run returned by an earlier run_check call. "
                "Reserve for high/critical findings unless the user asked for more."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "finding_id_in_run": {
                        "type": "integer",
                        "description": (
                            "Zero-based index of the finding within the run's "
                            "collected findings list."
                        ),
                    },
                    "narrative": {
                        "type": "string",
                        "description": (
                            "Concrete, actionable fix description — name the file, "
                            "the offending construct, and the minimum change required."
                        ),
                    },
                },
                "required": ["finding_id_in_run", "narrative"],
                "additionalProperties": False,
            },
        ),
        ToolDefinition(
            name="judge_finding",
            description=(
                "Adjudicate a deterministic candidate from an earlier run_check. "
                "Identify the finding by (rule_id, file, line_start) — these must "
                "match a finding already in this run; the tool cannot create new "
                "ones. confirmed=False downgrades severity one tier (CRITICAL->HIGH, "
                "HIGH->MEDIUM, MEDIUM->LOW); confirmed=True with confidence='high' "
                "bumps the fix confidence to 'high'. The reasoning is appended to "
                "the finding's evidence with a [LLM judgement] prefix. Use this for "
                "leakage findings that are name-match heuristics (label-proxy)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Stable rule id, e.g. 'leakage.label-proxy-feature'.",
                    },
                    "file": {
                        "type": "string",
                        "description": "Absolute file path of the finding.",
                    },
                    "line_start": {
                        "type": "integer",
                        "description": "Line number of the finding.",
                    },
                    "evidence": {
                        "type": "string",
                        "description": (
                            "Raw evidence text the AST produced. Echoed back for "
                            "audit but not used to match the finding."
                        ),
                    },
                    "confirmed": {
                        "type": "boolean",
                        "description": "True if you judge this to be a real issue.",
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Your confidence in the verdict.",
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "One-sentence justification appended to evidence.",
                    },
                },
                "required": [
                    "rule_id",
                    "file",
                    "line_start",
                    "evidence",
                    "confirmed",
                    "confidence",
                    "reasoning",
                ],
                "additionalProperties": False,
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatcher — pure, no LLM dependency
# ---------------------------------------------------------------------------


class _AuditState:
    """Mutable per-run state shared by the dispatcher and the loop."""

    def __init__(self, target: Path) -> None:
        self.target = target
        self.findings: list[Finding] = []
        self.fix_proposals: list[FixProposalRecord] = []
        self.check_results: list[CheckResult] = []


def _serialize_tool_result(payload: BaseModel | ToolErrorPayload) -> str:
    """JSON-serialize a tool result for the assistant to read."""
    return payload.model_dump_json()


def _handle_list_checks(_state: _AuditState, _raw_args: dict[str, object]) -> str:
    summaries = [
        CheckSummary(name=check.value, description=_CHECK_DESCRIPTIONS[check])
        for check in CHECKS
    ]
    payload = {"checks": [s.model_dump() for s in summaries]}
    return json.dumps(payload)


def _handle_run_check(state: _AuditState, raw_args: dict[str, object]) -> str:
    try:
        args = RunCheckArgs.model_validate(raw_args)
    except ValidationError as exc:
        return _serialize_tool_result(
            ToolErrorPayload(error="invalid_arguments", detail=exc.errors().__repr__())
        )

    try:
        check_name = CheckName(args.check)
    except ValueError:
        valid = ", ".join(c.value for c in CheckName)
        return _serialize_tool_result(
            ToolErrorPayload(
                error="unknown_check",
                detail=f"'{args.check}' is not registered. Valid: {valid}.",
            )
        )

    runner = CHECKS[check_name]
    target_path = Path(args.target)
    if not target_path.exists():
        return _serialize_tool_result(
            ToolErrorPayload(
                error="target_not_found",
                detail=f"path '{args.target}' does not exist on disk.",
            )
        )

    try:
        if check_name is CheckName.ADVERSARIAL:
            result = runner(target_path, include_adversarial=args.include_adversarial)
        else:
            result = runner(target_path)
    except Exception as exc:
        return _serialize_tool_result(
            ToolErrorPayload(error="check_failed", detail=f"{type(exc).__name__}: {exc}")
        )

    state.check_results.append(result)
    summaries: list[FindingSummary] = []
    for finding in result.findings:
        idx = len(state.findings)
        # Deep-copy so later judge_finding mutations on the in-flight list do
        # not bleed into state.check_results (which is the raw AST history).
        state.findings.append(finding.model_copy(deep=True))
        summaries.append(
            FindingSummary(
                finding_id_in_run=idx,
                rule_id=finding.id,
                severity=finding.severity.value,
                file=str(finding.file),
                line_start=finding.line_start,
                message=finding.message,
            )
        )

    return _serialize_tool_result(
        RunCheckResult(
            check=check_name.value,
            tool_status=result.tool_status,
            duration_ms=result.duration_ms,
            findings=summaries,
        )
    )


def _handle_propose_fix(state: _AuditState, raw_args: dict[str, object]) -> str:
    try:
        args = ProposeFixArgs.model_validate(raw_args)
    except ValidationError as exc:
        return _serialize_tool_result(
            ToolErrorPayload(error="invalid_arguments", detail=exc.errors().__repr__())
        )

    if not (0 <= args.finding_id_in_run < len(state.findings)):
        return _serialize_tool_result(
            ToolErrorPayload(
                error="unknown_finding",
                detail=(
                    f"finding_id_in_run={args.finding_id_in_run} is out of range; "
                    f"this run has {len(state.findings)} finding(s) so far."
                ),
            )
        )

    finding = state.findings[args.finding_id_in_run]
    record = FixProposalRecord(
        finding_id_in_run=args.finding_id_in_run,
        rule_id=finding.id,
        file=str(finding.file),
        line_start=finding.line_start,
        narrative=args.narrative,
    )
    state.fix_proposals.append(record)
    return _serialize_tool_result(
        _ProposeFixAck(
            ok=True,
            recorded_for=finding.id,
            total_proposals=len(state.fix_proposals),
        )
    )


class _ProposeFixAck(BaseModel):
    """Confirmation payload returned by ``propose_fix``."""

    ok: Literal[True]
    recorded_for: str
    total_proposals: int


# Severity downgrade ladder. CRITICAL/HIGH/MEDIUM step down one tier on a
# confirmed=False verdict; LOW/INFO stay put (no tier below INFO).
_SEVERITY_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
}


def _handle_judge_finding(state: _AuditState, raw_args: dict[str, object]) -> str:
    try:
        args = JudgeFindingArgs.model_validate(raw_args)
    except ValidationError as exc:
        return _serialize_tool_result(
            ToolErrorPayload(error="invalid_arguments", detail=exc.errors().__repr__())
        )

    # The LLM cannot invent findings: locate an in-flight finding matching the
    # (rule_id, file, line_start) triple. If none, error.
    match_idx: int | None = None
    for idx, finding in enumerate(state.findings):
        if (
            finding.id == args.rule_id
            and str(finding.file) == args.file
            and finding.line_start == args.line_start
        ):
            match_idx = idx
            break

    if match_idx is None:
        return _serialize_tool_result(
            ToolErrorPayload(
                error="unknown_finding",
                detail=(
                    f"no in-flight finding matches rule_id='{args.rule_id}' "
                    f"file='{args.file}' line_start={args.line_start}. "
                    "judge_finding cannot create new findings — it can only "
                    "evaluate ones already produced by a check."
                ),
            )
        )

    finding = state.findings[match_idx]
    previous_severity = finding.severity
    previous_fix_conf = finding.fix.confidence if finding.fix is not None else None

    verdict = Verdict(
        confirmed=args.confirmed,
        confidence=args.confidence,
        reasoning=args.reasoning,
    )

    new_severity = previous_severity
    new_fix: FixProposal | None = finding.fix
    if args.confirmed:
        if args.confidence == "high" and finding.fix is not None:
            new_fix = finding.fix.model_copy(update={"confidence": "high"})
    else:
        new_severity = _SEVERITY_DOWNGRADE.get(previous_severity, previous_severity)

    appended_evidence = (
        f"\n[LLM judgement] confirmed={args.confirmed} "
        f"confidence={args.confidence}: {args.reasoning}"
    )
    new_evidence = finding.evidence + appended_evidence

    state.findings[match_idx] = finding.model_copy(
        update={
            "severity": new_severity,
            "evidence": new_evidence,
            "fix": new_fix,
        }
    )

    return _serialize_tool_result(
        JudgeFindingResult(
            ok=True,
            rule_id=args.rule_id,
            file=args.file,
            line_start=args.line_start,
            previous_severity=previous_severity.value,
            new_severity=new_severity.value,
            previous_fix_confidence=previous_fix_conf,
            new_fix_confidence=new_fix.confidence if new_fix is not None else None,
            verdict=verdict,
        )
    )


_ToolHandlerFn = Callable[[_AuditState, dict[str, object]], str]
_DISPATCH_TABLE: dict[str, _ToolHandlerFn] = {
    "list_checks": _handle_list_checks,
    "run_check": _handle_run_check,
    "propose_fix": _handle_propose_fix,
    "judge_finding": _handle_judge_finding,
}


def _dispatch_tool_call(state: _AuditState, call: ToolCall) -> str:
    handler = _DISPATCH_TABLE.get(call.name)
    if handler is None:
        return _serialize_tool_result(
            ToolErrorPayload(
                error="unknown_tool",
                detail=(
                    f"'{call.name}' is not a registered tool. "
                    f"Available: {', '.join(_DISPATCH_TABLE)}."
                ),
            )
        )
    try:
        return handler(state, call.arguments)
    except Exception as exc:
        return _serialize_tool_result(
            ToolErrorPayload(
                error="tool_runtime_error",
                detail=f"{type(exc).__name__}: {exc}",
            )
        )


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def run_audit_with_agent(
    target: Path,
    *,
    provider: LLMProvider | MockLLMProvider,
    max_iterations: int = 10,
) -> AuditTranscript:
    """Drive the audit through an LLM tool-use loop.

    Iterates until either the assistant returns a message with no tool calls
    (final answer) or ``max_iterations`` is reached.  The transcript records
    whether the cap was hit so callers can flag a stalled run.

    Each ``provider.chat()`` call is wrapped as a Langfuse generation child
    span under a parent trace named ``mlsecops.audit``.  When Langfuse is not
    configured (or the package is absent) the behaviour is identical to before.
    """
    # Obtain the tracer from the provider when it is a real LLMProvider;
    # MockLLMProvider does not hold one so we fall back to a fresh no-op tracer.
    tracer: LangfuseTracer = (
        provider._tracer if isinstance(provider, LLMProvider) else LangfuseTracer()
    )

    state = _AuditState(target=target)
    tools = _tool_definitions()
    system_prompt = load_system_prompt()
    messages: list[ChatMessage] = [
        ChatMessage(role="system", content=system_prompt),
        ChatMessage(
            role="user",
            content=(
                f"Audit `{target}`. Use the available tools. "
                "End with an executive summary."
            ),
        ),
    ]

    final_summary = ""
    hit_cap = True  # flipped to False once we exit cleanly via no-more-tool-calls
    iterations = 0

    with tracer.trace(f"mlsecops.audit:{target.name}"):
        for iteration in range(max_iterations):
            iterations = iteration + 1
            response = provider.chat(
                messages,
                tools=tools,
                trace_metadata={"iteration": str(iteration)},
            )
            assistant_msg = response.message

            messages.append(
                ChatMessage(
                    role="assistant",
                    content=assistant_msg.content,
                    tool_calls=list(assistant_msg.tool_calls),
                )
            )

            if not assistant_msg.tool_calls:
                final_summary = assistant_msg.content
                hit_cap = False
                break

            for call in assistant_msg.tool_calls:
                result_json = _dispatch_tool_call(state, call)
                messages.append(
                    ChatMessage(
                        role="tool",
                        content=result_json,
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )

    return AuditTranscript(
        target=target,
        messages=messages,
        final_summary=final_summary,
        findings=state.findings,
        fix_proposals=state.fix_proposals,
        iterations=iterations,
        hit_iteration_cap=hit_cap,
    )


# Re-export the bits external callers (tests, CLI) need.
__all__ = [
    "AuditTranscript",
    "FindingSummary",
    "FixProposalRecord",
    "JudgeFindingResult",
    "RunCheckResult",
    "ToolErrorPayload",
    "Verdict",
    "run_audit_with_agent",
]


# ---------------------------------------------------------------------------
# Internal helpers re-exported for test access
# ---------------------------------------------------------------------------

# Tests import these to assert dispatcher behaviour without going through a
# fake LLM.  They are not part of the public API.
def _build_tool_definitions_for_test() -> list[ToolDefinition]:
    return _tool_definitions()


def _new_state_for_test(target: Path) -> _AuditState:
    return _AuditState(target=target)


def _dispatch_for_test(state: _AuditState, call: ToolCall) -> str:
    return _dispatch_tool_call(state, call)
