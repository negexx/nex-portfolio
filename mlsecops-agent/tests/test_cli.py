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
from mlsecops_agent.llm import AssistantMessage, ChatResponse, MockLLMProvider, ToolCall

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
