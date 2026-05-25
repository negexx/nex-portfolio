"""Markdown report renderer tests.

Deterministic snapshot-ish tests. We don't compare against a baseline file —
just assert structural invariants so the renderer can evolve format without
test churn while still catching real regressions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mlsecops_agent.models import (
    CheckName,
    CheckResult,
    Finding,
    FixProposal,
    Severity,
)
from mlsecops_agent.reporting import render_markdown

_FIXED_TIME = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)


def _f(rule: str, sev: Severity, *, with_fix: bool = False) -> Finding:
    return Finding(
        id=rule,
        check=CheckName.SUPPLY_CHAIN,
        severity=sev,
        category="test",
        file=Path("example.ipynb"),
        line_start=1,
        message="test message",
        evidence="raw | evidence\nwith newline",
        fix=FixProposal(summary="pin it", confidence="high") if with_fix else None,
    )


def _r(check: CheckName, findings: list[Finding], status: str = "ok") -> CheckResult:
    return CheckResult(
        check=check,
        findings=findings,
        tool_status=status,  # type: ignore[arg-type]
        duration_ms=12,
    )


def test_empty_results_render_clean_report() -> None:
    md = render_markdown([], target="x.py", generated_at=_FIXED_TIME)
    assert "Total findings:** 0" in md
    assert "non-blocking" in md
    assert "blocking" not in md.replace("non-blocking", "")


def test_high_severity_flips_status_to_blocking() -> None:
    r = _r(CheckName.SUPPLY_CHAIN, [_f("supply_chain.rule-x", Severity.HIGH)])
    md = render_markdown([r], target="x.ipynb", generated_at=_FIXED_TIME)
    assert "blocking (HIGH/CRITICAL present)" in md
    assert "supply_chain.rule-x" in md


def test_summary_table_orders_highest_severity_first() -> None:
    low = _r(CheckName.SUPPLY_CHAIN, [_f("supply_chain.x", Severity.LOW)])
    crit = _r(CheckName.DESERIALIZATION, [_f("deserialization.y", Severity.CRITICAL)])
    md = render_markdown([low, crit], target=".", generated_at=_FIXED_TIME)
    summary_start = md.index("## Summary")
    deser_pos = md.index("`deserialization`", summary_start)
    supply_pos = md.index("`supply_chain`", summary_start)
    assert deser_pos < supply_pos


def test_pipes_in_evidence_are_escaped() -> None:
    r = _r(CheckName.SUPPLY_CHAIN, [_f("supply_chain.x", Severity.MEDIUM)])
    md = render_markdown([r], target="x", generated_at=_FIXED_TIME)
    # Raw evidence contains `|` and a newline; rendered must escape pipe and join line
    assert "raw \\| evidence with newline" in md


def test_fix_proposals_section_present_when_fixes_exist() -> None:
    r = _r(
        CheckName.SUPPLY_CHAIN,
        [_f("supply_chain.x", Severity.MEDIUM, with_fix=True)],
    )
    md = render_markdown([r], target="x", generated_at=_FIXED_TIME)
    assert "### Fix proposals" in md
    assert "pin it" in md


def test_tool_status_non_ok_shows_in_summary() -> None:
    r = _r(CheckName.SUPPLY_CHAIN, [], status="tool_missing")
    md = render_markdown([r], target="x", generated_at=_FIXED_TIME)
    assert "tool_missing" in md


def test_render_is_deterministic_for_fixed_time() -> None:
    r = _r(CheckName.SUPPLY_CHAIN, [_f("supply_chain.x", Severity.MEDIUM)])
    a = render_markdown([r], target="x", generated_at=_FIXED_TIME)
    b = render_markdown([r], target="x", generated_at=_FIXED_TIME)
    assert a == b
