"""Agent-loop tests.

Every test here uses :class:`MockLLMProvider` — no live API calls, no openai
SDK invocation.  We verify:

- The loop terminates when the assistant returns content with no tool_calls.
- The loop terminates at ``max_iterations`` even if the assistant keeps
  calling tools; the transcript flags ``hit_iteration_cap=True``.
- ``list_checks`` returns exactly the registered set.
- ``run_check`` against the real supply_chain fixture produces structured
  findings in the transcript.
- ``propose_fix`` is recorded against the right finding.
- Unknown tool name returns a structured error.
- Malformed tool args (missing required field) return a structured error.
"""

from __future__ import annotations

import json
from pathlib import Path

from mlsecops_agent.agent import (
    _build_tool_definitions_for_test,
    _dispatch_for_test,
    _new_state_for_test,
    run_audit_with_agent,
)
from mlsecops_agent.checks import CHECKS
from mlsecops_agent.llm import (
    AssistantMessage,
    ChatResponse,
    MockLLMProvider,
    ToolCall,
)

FIXTURES = Path(__file__).parent / "fixtures"
SUPPLY_CHAIN_FIXTURE = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"


def _assistant_msg(content: str = "", tool_calls: list[ToolCall] | None = None) -> ChatResponse:
    return ChatResponse(
        message=AssistantMessage(content=content, tool_calls=tool_calls or [])
    )


# ---------------------------------------------------------------------------
# Loop-shape tests
# ---------------------------------------------------------------------------


def test_loop_terminates_on_assistant_message_with_no_tool_calls(tmp_path: Path) -> None:
    provider = MockLLMProvider([_assistant_msg(content="Audit complete.")])
    transcript = run_audit_with_agent(tmp_path, provider=provider, max_iterations=5)

    assert transcript.final_summary == "Audit complete."
    assert transcript.iterations == 1
    assert transcript.hit_iteration_cap is False
    assert transcript.findings == []
    assert transcript.fix_proposals == []
    # system + user + assistant
    assert len(transcript.messages) == 3


def test_loop_stops_at_max_iterations_when_assistant_keeps_calling_tools(
    tmp_path: Path,
) -> None:
    call = ToolCall(id="call_1", name="list_checks", arguments={})
    # Every response asks to call a tool — the loop must bail at the cap.
    canned = [_assistant_msg(tool_calls=[call]) for _ in range(5)]
    provider = MockLLMProvider(canned)

    transcript = run_audit_with_agent(tmp_path, provider=provider, max_iterations=3)

    assert transcript.iterations == 3
    assert transcript.hit_iteration_cap is True
    assert transcript.final_summary == ""


# ---------------------------------------------------------------------------
# Tool-dispatch tests (no LLM at all — pure dispatcher)
# ---------------------------------------------------------------------------


def test_list_checks_returns_every_registered_check(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state, ToolCall(id="x", name="list_checks", arguments={})
    )

    payload = json.loads(result)
    names = {c["name"] for c in payload["checks"]}
    assert names == {c.value for c in CHECKS}
    # 5 MVP checks per the project plan
    assert len(payload["checks"]) == 5


def test_run_check_supply_chain_produces_structured_findings(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state,
        ToolCall(
            id="x",
            name="run_check",
            arguments={"check": "supply_chain", "target": str(SUPPLY_CHAIN_FIXTURE)},
        ),
    )

    payload = json.loads(result)
    assert payload["check"] == "supply_chain"
    assert payload["tool_status"] == "ok"
    assert len(payload["findings"]) >= 1
    first = payload["findings"][0]
    assert first["finding_id_in_run"] == 0
    assert first["rule_id"].startswith("supply_chain.")
    # State was updated with the full Finding for later propose_fix lookups
    assert len(state.findings) == len(payload["findings"])


def test_propose_fix_records_against_correct_finding(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    _dispatch_for_test(
        state,
        ToolCall(
            id="x",
            name="run_check",
            arguments={"check": "supply_chain", "target": str(SUPPLY_CHAIN_FIXTURE)},
        ),
    )
    assert state.findings, "fixture must produce at least one finding for this test"

    result = _dispatch_for_test(
        state,
        ToolCall(
            id="y",
            name="propose_fix",
            arguments={
                "finding_id_in_run": 0,
                "narrative": "Pin the package with ==.",
            },
        ),
    )

    payload = json.loads(result)
    assert payload["ok"] is True
    assert payload["recorded_for"] == state.findings[0].id
    assert len(state.fix_proposals) == 1
    assert state.fix_proposals[0].narrative == "Pin the package with ==."


def test_propose_fix_unknown_finding_returns_error(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state,
        ToolCall(
            id="x",
            name="propose_fix",
            arguments={"finding_id_in_run": 99, "narrative": "n/a"},
        ),
    )

    payload = json.loads(result)
    assert payload["error"] == "unknown_finding"


def test_unknown_tool_returns_structured_error(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state, ToolCall(id="x", name="hallucinated_tool", arguments={})
    )
    payload = json.loads(result)
    assert payload["error"] == "unknown_tool"


def test_run_check_malformed_args_returns_error(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    # `target` is missing entirely
    result = _dispatch_for_test(
        state,
        ToolCall(id="x", name="run_check", arguments={"check": "supply_chain"}),
    )
    payload = json.loads(result)
    assert payload["error"] == "invalid_arguments"


def test_run_check_unknown_check_name_returns_error(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state,
        ToolCall(
            id="x",
            name="run_check",
            arguments={"check": "not_a_check", "target": str(tmp_path)},
        ),
    )
    payload = json.loads(result)
    assert payload["error"] == "unknown_check"


def test_run_check_missing_target_returns_error(tmp_path: Path) -> None:
    state = _new_state_for_test(tmp_path)
    result = _dispatch_for_test(
        state,
        ToolCall(
            id="x",
            name="run_check",
            arguments={"check": "supply_chain", "target": "no/such/path"},
        ),
    )
    payload = json.loads(result)
    assert payload["error"] == "target_not_found"


# ---------------------------------------------------------------------------
# End-to-end loop test wiring real tool dispatch through a mocked LLM
# ---------------------------------------------------------------------------


def test_full_loop_runs_check_then_summarises() -> None:
    """An LLM that calls run_check once and then writes a summary should produce
    a transcript with findings, no fix proposals, and a non-empty summary.
    """
    call = ToolCall(
        id="call_a",
        name="run_check",
        arguments={
            "check": "supply_chain",
            "target": str(SUPPLY_CHAIN_FIXTURE),
        },
    )
    provider = MockLLMProvider(
        [
            _assistant_msg(tool_calls=[call]),
            _assistant_msg(content="One supply-chain issue surfaced; pin your deps."),
        ]
    )

    transcript = run_audit_with_agent(
        SUPPLY_CHAIN_FIXTURE, provider=provider, max_iterations=5
    )

    assert transcript.hit_iteration_cap is False
    assert transcript.iterations == 2
    assert transcript.final_summary.startswith("One supply-chain")
    assert len(transcript.findings) >= 1
    assert all(f.check.value == "supply_chain" for f in transcript.findings)


def test_full_loop_propose_fix_records_against_finding() -> None:
    """LLM calls run_check, then propose_fix, then summarises."""
    run_call = ToolCall(
        id="r1",
        name="run_check",
        arguments={
            "check": "supply_chain",
            "target": str(SUPPLY_CHAIN_FIXTURE),
        },
    )
    fix_call = ToolCall(
        id="f1",
        name="propose_fix",
        arguments={"finding_id_in_run": 0, "narrative": "Add ==X.Y.Z to the pip install."},
    )
    provider = MockLLMProvider(
        [
            _assistant_msg(tool_calls=[run_call]),
            _assistant_msg(tool_calls=[fix_call]),
            _assistant_msg(content="Done."),
        ]
    )

    transcript = run_audit_with_agent(
        SUPPLY_CHAIN_FIXTURE, provider=provider, max_iterations=5
    )

    assert len(transcript.fix_proposals) == 1
    assert transcript.fix_proposals[0].finding_id_in_run == 0
    assert transcript.fix_proposals[0].narrative.startswith("Add ==")


# ---------------------------------------------------------------------------
# Tool-definition sanity
# ---------------------------------------------------------------------------


def test_tool_definitions_cover_all_tools() -> None:
    defs = _build_tool_definitions_for_test()
    names = {d.name for d in defs}
    assert names == {"list_checks", "run_check", "propose_fix", "judge_finding"}
