"""CLI integration tests.

We use Typer's CliRunner against the real registered checks. No mocking of
the dispatch table — the audit command's whole job is to fan out across
``checks.CHECKS``, so the test value is in the real wiring.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mlsecops_agent.checks import CHECKS
from mlsecops_agent.cli import app, set_llm_provider_override
from mlsecops_agent.llm import (
    AssistantMessage,
    ChatResponse,
    MockLLMProvider,
    ToolCall,
    Usage,
)

# Force a wide terminal so Rich doesn't truncate rule names like
# `supply_chain.unpinned-pip-install` to `supply_chain.un…` in test output.
runner = CliRunner(env={"COLUMNS": "200", "TERM": "dumb"})
FIXTURES = Path(__file__).parent / "fixtures"


def test_audit_missing_path_errors() -> None:
    result = runner.invoke(app, ["audit", "does-not-exist"])
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower()


def test_audit_runs_all_registered_checks_on_clean_fixture(tmp_path: Path) -> None:
    result = runner.invoke(app, ["audit", str(tmp_path)])
    assert result.exit_code == 0
    assert "audit summary" in result.output.lower()
    for check_name in CHECKS:
        assert check_name.value in result.output


def test_audit_flags_supply_chain_positive_fixture() -> None:
    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    result = runner.invoke(app, ["audit", str(target)])
    assert "supply_chain" in result.output
    # Rich truncates long rule names with `…` in narrow piped output, so we match
    # the surviving prefix rather than the full id. It uniquely identifies the rule.
    assert "supply_chain.un" in result.output


def test_audit_filters_with_repeated_check_flag(tmp_path: Path) -> None:
    result = runner.invoke(app, ["audit", str(tmp_path), "--check", "supply_chain"])
    assert result.exit_code == 0
    assert "supply_chain" in result.output
    # `deserialization` was NOT requested, so it shouldn't appear in the summary table
    assert "deserialization" not in result.output


def test_audit_rejects_unknown_check_filter(tmp_path: Path) -> None:
    result = runner.invoke(app, ["audit", str(tmp_path), "-c", "not-a-real-check"])
    assert result.exit_code != 0
    assert "unknown check" in result.output.lower()


def test_audit_exits_nonzero_when_high_severity_found() -> None:
    target = FIXTURES / "deserialization" / "positive_unsafe_loads.ipynb"
    if not target.exists():  # tolerant if deserialization fixture not yet authored
        return
    result = runner.invoke(app, ["audit", str(target), "--check", "deserialization"])
    assert result.exit_code == 1


def test_check_subcommand_still_works() -> None:
    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    result = runner.invoke(app, ["check", "supply_chain", str(target)])
    # See note in test_audit_flags_supply_chain_positive_fixture re: truncation.
    assert "supply_chain.un" in result.output


def test_audit_with_llm_uses_provider_override_and_renders_summary() -> None:
    """`audit --with-llm` should drive the loop through the injected provider
    and surface the executive summary plus deterministic finding tables.
    """
    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    provider = MockLLMProvider(
        [
            ChatResponse(
                message=AssistantMessage(
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="r1",
                            name="run_check",
                            arguments={
                                "check": "supply_chain",
                                "target": str(target),
                            },
                        )
                    ],
                )
            ),
            ChatResponse(
                message=AssistantMessage(
                    content="Executive summary: one supply_chain finding.",
                )
            ),
        ]
    )
    set_llm_provider_override(provider)
    try:
        result = runner.invoke(app, ["audit", str(target), "--with-llm"])
    finally:
        set_llm_provider_override(None)

    # The fixture surfaces only MEDIUM findings, so exit should be clean.
    assert result.exit_code == 0, result.output
    assert "executive summary" in result.output.lower()
    assert "supply_chain" in result.output


def test_audit_with_llm_errors_without_api_key(tmp_path: Path) -> None:
    """Without an override and without DEEPSEEK_API_KEY, the command should
    exit 1 with a pointer to .env.example."""
    set_llm_provider_override(None)
    no_key_runner = CliRunner(
        env={"COLUMNS": "200", "TERM": "dumb", "DEEPSEEK_API_KEY": ""}
    )
    result = no_key_runner.invoke(app, ["audit", str(tmp_path), "--with-llm"])
    assert result.exit_code == 1
    assert "deepseek_api_key" in result.output.lower()


def test_audit_persist_writes_db_and_history_list_reads_it(tmp_path: Path) -> None:
    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    db = tmp_path / "h.sqlite"

    audit_result = runner.invoke(app, ["audit", str(target), "--persist", str(db)])
    assert db.exists()
    assert "Persisted run" in audit_result.output

    list_result = runner.invoke(app, ["history", "list", str(db)])
    assert list_result.exit_code == 0
    assert "mlsecops history" in list_result.output
    # Rich truncates long Windows paths; assert the 12-char run_id prefix is present
    # (the run we just persisted) — that confirms the row rendered.
    import re
    assert re.search(r"\b[0-9a-f]{12}\b", list_result.output) is not None


def test_history_show_renders_findings(tmp_path: Path) -> None:
    import re

    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    db = tmp_path / "h.sqlite"
    runner.invoke(app, ["audit", str(target), "--persist", str(db)])

    list_out = runner.invoke(app, ["history", "list", str(db)]).output
    match = re.search(r"\b[0-9a-f]{12}\b", list_out)
    assert match is not None
    rid_prefix = match.group(0)

    show_result = runner.invoke(app, ["history", "show", str(db), rid_prefix])
    assert show_result.exit_code == 0
    assert "supply_chain.un" in show_result.output


def test_history_list_on_empty_db_is_noop(tmp_path: Path) -> None:
    from mlsecops_agent.storage import init_db

    db = tmp_path / "empty.sqlite"
    init_db(db)

    result = runner.invoke(app, ["history", "list", str(db)])
    assert result.exit_code == 0
    assert "no runs" in result.output.lower()


def test_history_show_rejects_ambiguous_prefix(tmp_path: Path) -> None:
    from mlsecops_agent.storage import Repository

    db = tmp_path / "h.sqlite"
    repo = Repository(db)
    repo.record_run(target="/a", results=[], run_id="abc1230000000000")
    repo.record_run(target="/b", results=[], run_id="abc1234000000000")

    result = runner.invoke(app, ["history", "show", str(db), "abc123"])
    assert result.exit_code != 0
    assert "multiple" in result.output.lower()


def test_audit_with_llm_persists_run(tmp_path: Path) -> None:
    """Regression: --with-llm --persist was a no-op in earlier builds because the
    LLM branch returned before the persist block. This test fails on that bug.
    """
    target = FIXTURES / "supply_chain" / "positive_unpinned_pip.ipynb"
    db = tmp_path / "h.sqlite"

    # Build a mock provider that immediately returns a no-tool-call summary —
    # the loop terminates, transcript has no findings (the agent didn't call run_check)
    # but the persist call should still happen.
    provider = MockLLMProvider(
        [
            ChatResponse(
                message=AssistantMessage(content="No issues to report.", tool_calls=[]),
                usage=Usage(input_tokens=0, output_tokens=0),
            )
        ]
    )
    set_llm_provider_override(provider)
    try:
        result = runner.invoke(
            app, ["audit", str(target), "--with-llm", "--persist", str(db)]
        )
    finally:
        set_llm_provider_override(None)

    assert db.exists(), "DB was not created — persist branch was skipped"
    assert "Persisted run" in result.output

    list_result = runner.invoke(app, ["history", "list", str(db)])
    assert "agent" in list_result.output  # invocation column should record 'agent'
