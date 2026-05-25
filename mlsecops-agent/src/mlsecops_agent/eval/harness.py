"""Fixture-based eval harness.

The baseline (``tests/fixtures/EVAL_BASELINE.json``) records, for each
fixture file, the multiset of finding ids the check is expected to produce.
Running the harness re-executes each check against its fixtures and compares
the produced finding-id multiset to the baseline:

- **TP** — expected id appears in actual output
- **FP** — actual id is not in the expected list
- **FN** — expected id is missing from actual output

Aggregated to precision, recall, F1 per check. The harness exits non-zero
when any check's recall drops below its baseline (we're tolerant of new
TP/FP for now — the regression we really care about is "we used to catch
this and now we don't").

The baseline is regenerated with ``mlsecops eval --update-baseline``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from ..checks import CHECKS
from ..models import CheckName, Finding

if TYPE_CHECKING:
    from pathlib import Path

# Fixture directory name -> CheckName. The folder layout *is* the dispatch table.
_FIXTURE_DIR_TO_CHECK: dict[str, CheckName] = {
    "supply_chain": CheckName.SUPPLY_CHAIN,
    "deserialization": CheckName.DESERIALIZATION,
    "secrets": CheckName.SECRETS,
    "leakage": CheckName.LEAKAGE,
    "adversarial": CheckName.ADVERSARIAL,
}


class FixtureExpectation(BaseModel):
    """Expected findings for a single fixture file."""

    file: str  # relative path under tests/fixtures, forward-slash separated
    expected_ids: list[str] = Field(default_factory=list)


class EvalBaseline(BaseModel):
    """Persisted eval baseline (the contents of EVAL_BASELINE.json)."""

    schema_version: int = 1
    fixtures: list[FixtureExpectation] = Field(default_factory=list)


@dataclass
class ReportRow:
    check: CheckName
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class EvalReport:
    rows: list[ReportRow] = field(default_factory=list)
    missing_baseline: list[str] = field(default_factory=list)  # fixture paths w/o baseline

    @property
    def overall_recall(self) -> float:
        tp = sum(r.true_positives for r in self.rows)
        fn = sum(r.false_negatives for r in self.rows)
        denom = tp + fn
        return tp / denom if denom else 1.0


def _iter_fixtures(fixtures_root: Path) -> list[tuple[CheckName, Path]]:
    """Yield (check_name, fixture_path) for every supported fixture file."""
    pairs: list[tuple[CheckName, Path]] = []
    for sub in sorted(fixtures_root.iterdir()):
        if not sub.is_dir():
            continue
        check_name = _FIXTURE_DIR_TO_CHECK.get(sub.name)
        if check_name is None:
            continue
        for f in sorted(sub.rglob("*")):
            if f.is_file() and f.suffix in (".ipynb", ".py"):
                pairs.append((check_name, f))
    return pairs


def _relpath(fixture: Path, root: Path) -> str:
    return fixture.relative_to(root).as_posix()


def _ids_from_run(check: CheckName, fixture: Path) -> list[str]:
    runner = CHECKS.get(check)
    if runner is None:
        return []
    result = runner(fixture)
    return [_finding_id(f) for f in result.findings]


def _finding_id(finding: Finding) -> str:
    return finding.id


def _score_one(
    expected_ids: list[str],
    actual_ids: list[str],
) -> tuple[int, int, int]:
    """Multiset-based TP/FP/FN for a single fixture."""
    expected = Counter(expected_ids)
    actual = Counter(actual_ids)
    tp_counter = expected & actual
    tp = sum(tp_counter.values())
    fp = sum((actual - expected).values())
    fn = sum((expected - actual).values())
    return tp, fp, fn


def run_eval(fixtures_root: Path, baseline_path: Path) -> EvalReport:
    """Run every check on its fixtures, score against the baseline, return a report."""
    if baseline_path.exists():
        baseline = EvalBaseline.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    else:
        baseline = EvalBaseline()
    baseline_index = {fx.file: fx.expected_ids for fx in baseline.fixtures}

    rows_by_check: dict[CheckName, ReportRow] = {}
    missing: list[str] = []

    for check, fixture in _iter_fixtures(fixtures_root):
        row = rows_by_check.setdefault(check, ReportRow(check=check))
        rel = _relpath(fixture, fixtures_root)
        actual_ids = _ids_from_run(check, fixture)

        if rel not in baseline_index:
            missing.append(rel)
            # Treat as "all actual findings are FPs" so the report still flags
            # the gap rather than silently absorbing new findings.
            for _ in actual_ids:
                row.false_positives += 1
            continue

        expected_ids = baseline_index[rel]
        tp, fp, fn = _score_one(expected_ids, actual_ids)
        row.true_positives += tp
        row.false_positives += fp
        row.false_negatives += fn

    return EvalReport(
        rows=sorted(rows_by_check.values(), key=lambda r: r.check.value),
        missing_baseline=missing,
    )


def write_baseline(fixtures_root: Path, baseline_path: Path) -> EvalBaseline:
    """Regenerate the baseline by running every check against every fixture."""
    fixtures: list[FixtureExpectation] = []
    for check, fixture in _iter_fixtures(fixtures_root):
        actual_ids = sorted(_ids_from_run(check, fixture))
        fixtures.append(
            FixtureExpectation(file=_relpath(fixture, fixtures_root), expected_ids=actual_ids)
        )
    baseline = EvalBaseline(fixtures=fixtures)
    baseline_path.write_text(
        baseline.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return baseline
