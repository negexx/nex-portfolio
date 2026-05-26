"""Tests for the semgrep-based ML hygiene rule runner.

Coverage:
- Positive fixture: model.fit(X_test) → ml-hygiene.fit-on-test-arg
- Positive fixture: train_test_split(shuffle=False, no stratify)
  → ml-hygiene.train-test-split-with-shuffle-false
- Negative fixture: clean pipeline → no findings
- Semgrep binary missing → clean result (graceful no-op)
- Canned JSON response → correct Finding fields produced
- Deduplication in leakage.run: same (rule_id, file, line_start) appears once
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mlsecops_agent.checks import semgrep_rules
from mlsecops_agent.checks.leakage import _dedup_findings
from mlsecops_agent.models import CheckName, Finding, FixProposal, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "semgrep"


# ---------------------------------------------------------------------------
# Helper: build a minimal canned semgrep JSON payload
# ---------------------------------------------------------------------------


def _semgrep_payload(
    check_id: str,
    path: str,
    line_start: int,
    line_end: int,
    lines: str,
    severity: str = "ERROR",
    message: str = "test message",
) -> str:
    return json.dumps(
        {
            "results": [
                {
                    "check_id": check_id,
                    "path": path,
                    "start": {"line": line_start, "col": 1},
                    "end": {"line": line_end, "col": 30},
                    "extra": {
                        "lines": lines,
                        "message": message,
                        "severity": severity,
                    },
                }
            ],
            "errors": [],
            "version": "1.0.0",
        }
    )


# ---------------------------------------------------------------------------
# Positive fixture: fit on test arg
# ---------------------------------------------------------------------------


def test_positive_fit_on_test_semgrep_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """model.fit(X_test) must produce ml-hygiene.fit-on-test-arg."""
    fixture = FIXTURES / "positive_fit_on_test_semgrep.py"
    payload = _semgrep_payload(
        check_id="ml-hygiene.fit-on-test-arg",
        path=str(fixture),
        line_start=14,
        line_end=14,
        lines="model.fit(X_test, y_test)",
        severity="ERROR",
        message="model.fit(X_test, ...) fits on the test set.",
    )

    def _fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=list(args), returncode=1, stdout=payload, stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    findings = semgrep_rules.run_semgrep(fixture)

    ids = [f.id for f in findings]
    assert "ml-hygiene.fit-on-test-arg" in ids, f"Expected fit-on-test-arg; got: {ids}"

    f = findings[0]
    assert f.check is CheckName.LEAKAGE
    assert f.severity is Severity.HIGH  # ERROR maps to HIGH
    assert f.line_start == 14
    assert f.line_end == 14
    assert "X_test" in f.evidence
    assert f.fix is not None
    assert f.fix.confidence == "medium"


# ---------------------------------------------------------------------------
# Positive fixture: shuffle=False without stratify
# ---------------------------------------------------------------------------


def test_positive_shuffle_false_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """train_test_split(shuffle=False) without stratify must produce the shuffle rule."""
    fixture = FIXTURES / "positive_shuffle_false.py"
    payload = _semgrep_payload(
        check_id="ml-hygiene.train-test-split-with-shuffle-false",
        path=str(fixture),
        line_start=9,
        line_end=9,
        lines="X_train, X_test, y_train, y_test = train_test_split(X, y, shuffle=False)",
        severity="WARNING",
        message="train_test_split with shuffle=False and no stratify.",
    )

    def _fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=list(args), returncode=1, stdout=payload, stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    findings = semgrep_rules.run_semgrep(fixture)

    ids = [f.id for f in findings]
    assert "ml-hygiene.train-test-split-with-shuffle-false" in ids, (
        f"Expected train-test-split-with-shuffle-false; got: {ids}"
    )

    f = findings[0]
    assert f.check is CheckName.LEAKAGE
    assert f.severity is Severity.MEDIUM  # WARNING maps to MEDIUM
    assert f.line_start == 9
    assert "shuffle=False" in f.evidence


# ---------------------------------------------------------------------------
# Negative fixture: clean pipeline produces no findings
# ---------------------------------------------------------------------------


def test_negative_clean_pipeline_is_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """A correct pipeline must produce no semgrep findings."""
    clean_payload = json.dumps({"results": [], "errors": [], "version": "1.0.0"})

    def _fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=list(args), returncode=0, stdout=clean_payload, stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    findings = semgrep_rules.run_semgrep(FIXTURES / "negative_clean_pipeline.py")
    assert findings == [], f"Expected no findings; got: {[f.id for f in findings]}"


# ---------------------------------------------------------------------------
# Semgrep binary missing → graceful no-op
# ---------------------------------------------------------------------------


def test_semgrep_binary_missing_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """When semgrep is not on PATH, run_semgrep must return [] without raising."""
    monkeypatch.setattr(semgrep_rules, "_semgrep_binary", lambda: None)

    findings = semgrep_rules.run_semgrep(FIXTURES / "positive_fit_on_test_semgrep.py")
    assert findings == []


# ---------------------------------------------------------------------------
# Binary missing via subprocess OSError path
# ---------------------------------------------------------------------------


def test_semgrep_oserror_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError from subprocess (binary gone mid-run) must return [] without raising."""
    monkeypatch.setattr(
        semgrep_rules, "_semgrep_binary", lambda: "/usr/local/bin/semgrep"
    )

    def _raise(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("No such file or directory")

    monkeypatch.setattr(subprocess, "run", _raise)

    findings = semgrep_rules.run_semgrep(FIXTURES / "positive_fit_on_test_semgrep.py")
    assert findings == []


# ---------------------------------------------------------------------------
# Canned JSON response: verify all Finding fields are populated correctly
# ---------------------------------------------------------------------------


def test_parse_semgrep_output_canned_response() -> None:
    """_parse_semgrep_output must map all semgrep fields to the correct Finding attrs."""
    payload = {
        "results": [
            {
                "check_id": "ml-hygiene.fit-on-test-arg",
                "path": "/some/project/train.py",
                "start": {"line": 42, "col": 4},
                "end": {"line": 42, "col": 28},
                "extra": {
                    "lines": "  scaler.fit(X_test)",
                    "message": "Fits on test set.",
                    "severity": "ERROR",
                },
            }
        ],
        "errors": [],
    }

    findings = semgrep_rules._parse_semgrep_output(payload)

    assert len(findings) == 1
    f = findings[0]
    assert f.id == "ml-hygiene.fit-on-test-arg"
    assert f.check is CheckName.LEAKAGE
    assert f.severity is Severity.HIGH
    assert f.category == "data-leakage"
    assert f.file == Path("/some/project/train.py")
    assert f.line_start == 42
    assert f.line_end == 42
    assert "X_test" in f.evidence
    assert f.message == "Fits on test set."
    assert f.fix is not None
    assert "transform" in f.fix.summary.lower()
    assert f.fix.confidence == "medium"


# ---------------------------------------------------------------------------
# _parse_semgrep_output: malformed inputs are skipped
# ---------------------------------------------------------------------------


def test_parse_semgrep_output_malformed_item_skipped() -> None:
    """Results with missing required fields must be silently skipped."""
    payload = {
        "results": [
            # missing 'path'
            {
                "check_id": "ml-hygiene.fit-on-test-arg",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 10},
                "extra": {"lines": "", "message": "x", "severity": "ERROR"},
            },
            # not a dict at all
            "bad item",
        ]
    }
    findings = semgrep_rules._parse_semgrep_output(payload)
    assert findings == []


# ---------------------------------------------------------------------------
# Deduplication: same (rule_id, file, line_start) yields one finding
# ---------------------------------------------------------------------------


def test_dedup_findings_removes_duplicate() -> None:
    """_dedup_findings keeps the first occurrence and drops later duplicates."""
    path = Path("/fake/file.py")

    def _make(line: int, evidence: str) -> Finding:
        return Finding(
            id="ml-hygiene.fit-on-test-arg",
            check=CheckName.LEAKAGE,
            severity=Severity.HIGH,
            category="data-leakage",
            file=path,
            line_start=line,
            line_end=line,
            message="fits on test set",
            evidence=evidence,
            fix=FixProposal(summary="use transform", confidence="medium"),
        )

    ast_finding = _make(10, "ast evidence")
    sg_finding = _make(10, "semgrep evidence")
    other = _make(20, "different line")

    result = _dedup_findings([ast_finding, sg_finding, other])

    assert len(result) == 2
    # First occurrence (AST) is kept
    assert result[0].evidence == "ast evidence"
    assert result[1].evidence == "different line"


def test_dedup_findings_none_line_start_not_deduped() -> None:
    """Findings with line_start=None are never considered duplicates."""
    path = Path("/fake/file.py")

    def _make_no_line(evidence: str) -> Finding:
        return Finding(
            id="ml-hygiene.fit-on-test-arg",
            check=CheckName.LEAKAGE,
            severity=Severity.HIGH,
            category="data-leakage",
            file=path,
            line_start=None,
            line_end=None,
            message="no line info",
            evidence=evidence,
            fix=FixProposal(summary="use transform", confidence="medium"),
        )

    f1 = _make_no_line("first")
    f2 = _make_no_line("second")

    result = _dedup_findings([f1, f2])
    assert len(result) == 2
