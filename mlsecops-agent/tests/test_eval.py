"""Tests for the eval harness."""

from __future__ import annotations

from pathlib import Path

from mlsecops_agent.eval import EvalReport, ReportRow, run_eval, write_baseline
from mlsecops_agent.eval.harness import EvalBaseline, _score_one
from mlsecops_agent.models import CheckName

REPO_FIXTURES = Path(__file__).parent / "fixtures"
REPO_BASELINE = REPO_FIXTURES / "EVAL_BASELINE.json"


def test_committed_baseline_passes() -> None:
    """The checked-in baseline should match the current check output exactly."""
    report = run_eval(REPO_FIXTURES, REPO_BASELINE)
    for row in report.rows:
        assert row.false_negatives == 0, f"{row.check.value} regressed — missing expected findings"
        assert row.false_positives == 0, (
            f"{row.check.value} produced unexpected new findings — "
            "if intentional, rerun mlsecops eval --update-baseline"
        )
    assert report.missing_baseline == []


def test_score_one_multiset_semantics() -> None:
    # Two expected, one actual -> 1 TP, 0 FP, 1 FN
    tp, fp, fn = _score_one(["a", "a"], ["a"])
    assert (tp, fp, fn) == (1, 0, 1)

    # Two expected, three actual same id -> 2 TP, 1 FP, 0 FN
    tp, fp, fn = _score_one(["a", "a"], ["a", "a", "a"])
    assert (tp, fp, fn) == (2, 1, 0)

    # Disjoint -> all FP + all FN
    tp, fp, fn = _score_one(["a"], ["b"])
    assert (tp, fp, fn) == (0, 1, 1)


def test_metrics_math() -> None:
    row = ReportRow(
        check=CheckName.SUPPLY_CHAIN,
        true_positives=3,
        false_positives=1,
        false_negatives=2,
    )
    assert row.precision == 0.75
    assert row.recall == 0.6
    # F1 = 2*P*R/(P+R) = 2*0.75*0.6/1.35 = 0.6667
    assert abs(row.f1 - 0.6667) < 1e-3


def test_metrics_with_zero_findings_default_to_one() -> None:
    row = ReportRow(check=CheckName.SECRETS)
    # No findings at all = perfect P/R (nothing to be wrong about)
    assert row.precision == 1.0
    assert row.recall == 1.0


def test_write_baseline_round_trips(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    written = write_baseline(REPO_FIXTURES, baseline_path)
    parsed = EvalBaseline.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    assert parsed.fixtures == written.fixtures


def test_fixture_without_baseline_entry_is_flagged_missing(tmp_path: Path) -> None:
    # Build a tiny fixtures tree with one supply_chain fixture, and an EMPTY baseline.
    fx = tmp_path / "supply_chain"
    fx.mkdir()
    (fx / "x.ipynb").write_text(
        '{"cells": [{"cell_type":"code","source":"!pip install x","outputs":[],"metadata":{}}], '
        '"metadata":{}, "nbformat":4, "nbformat_minor":5}',
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(EvalBaseline().model_dump_json(), encoding="utf-8")

    report = run_eval(tmp_path, baseline)
    assert "supply_chain/x.ipynb" in report.missing_baseline


def test_overall_recall_aggregates_across_checks() -> None:
    report = EvalReport(
        rows=[
            ReportRow(check=CheckName.SUPPLY_CHAIN, true_positives=3, false_negatives=1),
            ReportRow(check=CheckName.SECRETS, true_positives=1, false_negatives=2),
        ]
    )
    # tp=4, fn=3, overall recall = 4/7 ≈ 0.5714
    assert abs(report.overall_recall - 4 / 7) < 1e-3
