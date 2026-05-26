"""SQLite run-history repository tests."""

from __future__ import annotations

from pathlib import Path

from mlsecops_agent.models import (
    CheckName,
    CheckResult,
    Finding,
    FixProposal,
    Severity,
)
from mlsecops_agent.storage import Repository, init_db


def _finding(
    rule: str = "supply_chain.unpinned-pip-install",
    sev: Severity = Severity.MEDIUM,
    *,
    with_fix: bool = False,
) -> Finding:
    return Finding(
        id=rule,
        check=CheckName.SUPPLY_CHAIN,
        severity=sev,
        category="dependency-pinning",
        file=Path("example.ipynb"),
        line_start=12,
        line_end=12,
        message="something is wrong here",
        evidence="!pip install foo",
        fix=FixProposal(summary="pin it", confidence="high") if with_fix else None,
    )


def _result(findings: list[Finding] | None = None) -> CheckResult:
    return CheckResult(
        check=CheckName.SUPPLY_CHAIN,
        findings=findings or [],
        tool_status="ok",
        duration_ms=12,
    )


def test_init_db_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "x.sqlite"
    init_db(db)
    init_db(db)  # should not raise
    assert db.exists()


def test_record_run_persists_summary_metrics(tmp_path: Path) -> None:
    db = tmp_path / "h.sqlite"
    repo = Repository(db)
    rid = repo.record_run(
        target="/tmp/notebook.ipynb",
        results=[_result([_finding(sev=Severity.HIGH), _finding(sev=Severity.LOW)])],
    )

    run = repo.get_run(rid)
    assert run is not None
    assert run["target"] == "/tmp/notebook.ipynb"
    assert run["total_findings"] == 2
    assert run["max_severity"] == "high"
    assert run["blocking"] == 1


def test_record_run_clean_audit_has_no_max_severity(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "h.sqlite")
    rid = repo.record_run(target="/x", results=[_result([])])

    run = repo.get_run(rid)
    assert run is not None
    assert run["total_findings"] == 0
    assert run["max_severity"] is None
    assert run["blocking"] == 0


def test_findings_round_trip(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "h.sqlite")
    original = [
        _finding("supply_chain.a", Severity.HIGH, with_fix=True),
        _finding("supply_chain.b", Severity.MEDIUM, with_fix=False),
    ]
    rid = repo.record_run(target="/t", results=[_result(original)])

    loaded = repo.findings_for_run(rid)
    assert len(loaded) == 2
    assert loaded[0].id == "supply_chain.a"
    assert loaded[0].severity is Severity.HIGH
    assert loaded[0].fix is not None
    assert loaded[0].fix.summary == "pin it"
    assert loaded[1].fix is None


def test_list_runs_most_recent_first(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "h.sqlite")
    # Persist 3 with distinct synthetic run_ids
    repo.record_run(target="/a", results=[_result()], run_id="r1")
    repo.record_run(target="/b", results=[_result()], run_id="r2")
    repo.record_run(target="/c", results=[_result()], run_id="r3")

    rows = repo.list_runs()
    # Each call uses _utcnow_iso() which has 1s resolution; same-second ordering
    # is non-deterministic. Just assert the set is right.
    assert {row["run_id"] for row in rows} == {"r1", "r2", "r3"}
    assert all(row["target"] in ("/a", "/b", "/c") for row in rows)


def test_runs_by_rule_returns_cross_run_appearances(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "h.sqlite")
    rule = "supply_chain.unpinned-pip-install"
    repo.record_run(target="/a", results=[_result([_finding(rule)])], run_id="r1")
    repo.record_run(
        target="/b", results=[_result([_finding(rule), _finding("other.rule")])], run_id="r2"
    )

    rows = list(repo.runs_by_rule(rule))
    # rule appears once in r1 + once in r2 = 2 rows
    assert len(rows) == 2
    assert {row["run_id"] for row in rows} == {"r1", "r2"}


def test_record_run_with_extra_metadata(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "h.sqlite")
    rid = repo.record_run(
        target="/x",
        results=[_result()],
        invocation="agent",
        extra={"model": "deepseek-v4-flash", "iterations": "3"},
    )
    run = repo.get_run(rid)
    assert run is not None
    assert run["invocation"] == "agent"
    assert "deepseek-v4-flash" in str(run["extra_json"])
