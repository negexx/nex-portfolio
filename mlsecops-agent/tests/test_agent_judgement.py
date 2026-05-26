"""Tests for the LLM-judgement layer (``judge_finding`` tool).

The judgement layer lets the LLM adjudicate AST-flagged leakage candidates
without ever fabricating a new finding.  These tests verify the deterministic
philosophy: the tool can only confirm/downgrade existing findings, mutations
land on the in-flight transcript (not the raw CheckResult history), and an
unknown rule triple produces a structured error rather than a crash.
"""

from __future__ import annotations

import json
from pathlib import Path

from mlsecops_agent.agent import (
    _dispatch_for_test,
    _new_state_for_test,
    run_audit_with_agent,
)
from mlsecops_agent.checks import leakage as leakage_check
from mlsecops_agent.llm import (
    AssistantMessage,
    ChatResponse,
    MockLLMProvider,
    ToolCall,
)
from mlsecops_agent.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"
LEAKAGE_PROXY_FIXTURE = FIXTURES / "leakage" / "positive_difficulty_proxy.ipynb"
SUPPLY_CHAIN_FIXTURE = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"


def _assistant_msg(
    content: str = "", tool_calls: list[ToolCall] | None = None
) -> ChatResponse:
    return ChatResponse(
        message=AssistantMessage(content=content, tool_calls=tool_calls or [])
    )


def _seed_leakage_findings(state_target: Path) -> tuple[object, list[dict[str, object]]]:
    """Run the leakage check and return (state, run_check_payload_findings).

    Helper for tests that need the in-flight state primed with the AST hits
    against the difficulty-proxy fixture.
    """
    state = _new_state_for_test(state_target)
    result = _dispatch_for_test(
        state,
        ToolCall(
            id="r",
            name="run_check",
            arguments={"check": "leakage", "target": str(LEAKAGE_PROXY_FIXTURE)},
        ),
    )
    payload = json.loads(result)
    assert payload["tool_status"] == "ok"
    assert payload["findings"], (
        "leakage fixture must produce at least one finding for these tests"
    )
    return state, payload["findings"]


# ---------------------------------------------------------------------------
# 1. Confirmed=True, confidence=high -> bumps fix.confidence to "high"
# ---------------------------------------------------------------------------


def test_judge_confirmed_high_bumps_fix_confidence(tmp_path: Path) -> None:
    state, findings = _seed_leakage_findings(tmp_path)
    target = findings[0]

    # Sanity: the AST hit ships with medium confidence per the leakage module.
    pre_state_finding = state.findings[target["finding_id_in_run"]]
    assert pre_state_finding.fix is not None
    assert pre_state_finding.fix.confidence == "medium"
    pre_severity = pre_state_finding.severity
    pre_evidence = pre_state_finding.evidence

    result = _dispatch_for_test(
        state,
        ToolCall(
            id="j1",
            name="judge_finding",
            arguments={
                "rule_id": target["rule_id"],
                "file": target["file"],
                "line_start": target["line_start"],
                "evidence": "ast-evidence",
                "confirmed": True,
                "confidence": "high",
                "reasoning": "difficulty_level is the NSL-KDD label proxy.",
            },
        ),
    )

    payload = json.loads(result)
    assert payload["ok"] is True
    assert payload["new_fix_confidence"] == "high"
    assert payload["previous_fix_confidence"] == "medium"
    # Severity unchanged on a confirmation.
    assert payload["new_severity"] == pre_severity.value

    mutated = state.findings[target["finding_id_in_run"]]
    assert mutated.fix is not None
    assert mutated.fix.confidence == "high"
    assert mutated.severity == pre_severity
    assert mutated.evidence.startswith(pre_evidence)
    assert "[LLM judgement]" in mutated.evidence
    assert "difficulty_level is the NSL-KDD label proxy." in mutated.evidence


# ---------------------------------------------------------------------------
# 2. Confirmed=False -> severity downgrades one tier
# ---------------------------------------------------------------------------


def test_judge_confirmed_false_downgrades_severity_one_tier(tmp_path: Path) -> None:
    state, findings = _seed_leakage_findings(tmp_path)
    target = findings[0]

    pre = state.findings[target["finding_id_in_run"]]
    pre_severity = pre.severity
    assert pre_severity in {Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM}, (
        "fixture should expose a finding eligible for downgrade"
    )
    expected_new = {
        Severity.CRITICAL: Severity.HIGH,
        Severity.HIGH: Severity.MEDIUM,
        Severity.MEDIUM: Severity.LOW,
    }[pre_severity]

    result = _dispatch_for_test(
        state,
        ToolCall(
            id="j2",
            name="judge_finding",
            arguments={
                "rule_id": target["rule_id"],
                "file": target["file"],
                "line_start": target["line_start"],
                "evidence": "ast-evidence",
                "confirmed": False,
                "confidence": "medium",
                "reasoning": "Column is actually a benign categorical, not a label proxy.",
            },
        ),
    )

    payload = json.loads(result)
    assert payload["ok"] is True
    assert payload["previous_severity"] == pre_severity.value
    assert payload["new_severity"] == expected_new.value

    mutated = state.findings[target["finding_id_in_run"]]
    assert mutated.severity == expected_new
    assert "[LLM judgement]" in mutated.evidence
    assert "benign categorical" in mutated.evidence
    # Fix confidence should be untouched on a downgrade (only confirmed=True+high bumps).
    assert mutated.fix is not None
    assert mutated.fix.confidence == "medium"


# ---------------------------------------------------------------------------
# 3. Unknown (rule_id, file, line_start) triple -> structured ToolError
# ---------------------------------------------------------------------------


def test_judge_unknown_finding_returns_structured_error(tmp_path: Path) -> None:
    state, findings = _seed_leakage_findings(tmp_path)
    target = findings[0]

    result = _dispatch_for_test(
        state,
        ToolCall(
            id="j3",
            name="judge_finding",
            arguments={
                "rule_id": "leakage.hallucinated-rule",
                "file": target["file"],
                "line_start": target["line_start"],
                "evidence": "n/a",
                "confirmed": True,
                "confidence": "high",
                "reasoning": "should not be accepted",
            },
        ),
    )

    payload = json.loads(result)
    assert payload["error"] == "unknown_finding"
    assert "judge_finding cannot create new findings" in payload["detail"]

    # No mutation occurred.
    for finding in state.findings:
        assert "[LLM judgement]" not in finding.evidence


def test_judge_known_rule_but_wrong_line_returns_error(tmp_path: Path) -> None:
    state, findings = _seed_leakage_findings(tmp_path)
    target = findings[0]
    assert isinstance(target["line_start"], int)
    wrong_line = target["line_start"] + 9999

    result = _dispatch_for_test(
        state,
        ToolCall(
            id="j4",
            name="judge_finding",
            arguments={
                "rule_id": target["rule_id"],
                "file": target["file"],
                "line_start": wrong_line,
                "evidence": "n/a",
                "confirmed": False,
                "confidence": "low",
                "reasoning": "wrong line",
            },
        ),
    )
    payload = json.loads(result)
    assert payload["error"] == "unknown_finding"


# ---------------------------------------------------------------------------
# 4. An agent loop that never calls judge_finding leaves leakage findings alone
# ---------------------------------------------------------------------------


def test_agent_loop_without_judge_finding_leaves_findings_unchanged() -> None:
    run_call = ToolCall(
        id="r",
        name="run_check",
        arguments={"check": "leakage", "target": str(LEAKAGE_PROXY_FIXTURE)},
    )
    provider = MockLLMProvider(
        [
            _assistant_msg(tool_calls=[run_call]),
            _assistant_msg(content="Leakage check complete; no LLM adjudication."),
        ]
    )

    transcript = run_audit_with_agent(
        LEAKAGE_PROXY_FIXTURE, provider=provider, max_iterations=5
    )

    assert transcript.findings, "fixture must yield findings"
    for finding in transcript.findings:
        assert "[LLM judgement]" not in finding.evidence
        assert finding.fix is not None
        # The leakage check ships with medium confidence; without judgement it
        # should stay that way.
        assert finding.fix.confidence == "medium"


# ---------------------------------------------------------------------------
# 5. Verdict mutation only affects in-transcript findings, not CheckResult
# ---------------------------------------------------------------------------


def test_judge_finding_does_not_mutate_underlying_check_result(tmp_path: Path) -> None:
    # Drive the check directly so we hold a reference to the original CheckResult.
    original = leakage_check.run(LEAKAGE_PROXY_FIXTURE)
    assert original.findings, "leakage fixture must yield at least one finding"
    pre_severities = [f.severity for f in original.findings]
    pre_evidences = [f.evidence for f in original.findings]
    pre_fix_confs = [
        f.fix.confidence if f.fix is not None else None for f in original.findings
    ]

    state, findings = _seed_leakage_findings(tmp_path)
    assert len(state.check_results) == 1
    stored_result = state.check_results[0]

    target = findings[0]
    _dispatch_for_test(
        state,
        ToolCall(
            id="j5",
            name="judge_finding",
            arguments={
                "rule_id": target["rule_id"],
                "file": target["file"],
                "line_start": target["line_start"],
                "evidence": "ast-evidence",
                "confirmed": False,
                "confidence": "medium",
                "reasoning": "false positive in this codebase.",
            },
        ),
    )

    # The transcript-level finding was mutated.
    transcript_finding = state.findings[target["finding_id_in_run"]]
    assert "[LLM judgement]" in transcript_finding.evidence

    # But the underlying CheckResult held in state.check_results is untouched.
    for stored, pre_sev, pre_ev, pre_conf in zip(
        stored_result.findings, pre_severities, pre_evidences, pre_fix_confs, strict=True
    ):
        assert stored.severity == pre_sev
        assert stored.evidence == pre_ev
        assert "[LLM judgement]" not in stored.evidence
        if stored.fix is not None:
            assert stored.fix.confidence == pre_conf
