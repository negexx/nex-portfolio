"""Tests for the leakage check.

Fixture pair: one notebook per rule class (positive), one clean notebook
(negative), cross-cell cases, line-translation assertion, alias detection,
and an integration run against the real v1 NIDS notebook.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mlsecops_agent.checks import leakage
from mlsecops_agent.checks.leakage import (
    _build_synthetic_module,
    _is_label_proxy,
    _synthetic_line_to_cell_line,
)
from mlsecops_agent.models import CheckName, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "leakage"

# The real v1 notebook sits one directory above the repo root.
NIDS_V1 = Path(__file__).parent.parent.parent.parent / "nids_v1_baseline.ipynb"


# ---------------------------------------------------------------------------
# Positive fixtures
# ---------------------------------------------------------------------------


def test_smote_before_split_cross_cell_flagged() -> None:
    """SMOTE in an earlier cell than train_test_split must be flagged."""
    result = leakage.run(FIXTURES / "positive_smote_before_split.ipynb")

    assert result.check is CheckName.LEAKAGE
    assert result.tool_status == "ok"

    ids = [f.id for f in result.findings]
    assert "leakage.preprocessing-before-split" in ids, (
        f"Expected preprocessing-before-split; got: {ids}"
    )


def test_difficulty_proxy_flagged() -> None:
    """difficulty_level in a feature list must trigger label-proxy-feature."""
    result = leakage.run(FIXTURES / "positive_difficulty_proxy.ipynb")

    ids = [f.id for f in result.findings]
    assert "leakage.label-proxy-feature" in ids, (
        f"Expected label-proxy-feature; got: {ids}"
    )


def test_fit_on_test_flagged() -> None:
    """scaler.fit(X_test) in a .py file must trigger fit-on-test."""
    result = leakage.run(FIXTURES / "positive_fit_on_test.py")

    ids = [f.id for f in result.findings]
    assert "leakage.fit-on-test" in ids, (
        f"Expected fit-on-test; got: {ids}"
    )


def test_positive_findings_have_required_fields() -> None:
    """Every finding must have line_start, line_end, evidence, and a fix."""
    for fixture in (
        FIXTURES / "positive_smote_before_split.ipynb",
        FIXTURES / "positive_difficulty_proxy.ipynb",
        FIXTURES / "positive_fit_on_test.py",
    ):
        result = leakage.run(fixture)
        assert result.findings, f"Expected findings from {fixture.name}"
        for finding in result.findings:
            assert finding.line_start is not None, f"{finding.id} missing line_start"
            assert finding.line_end is not None, f"{finding.id} missing line_end"
            assert finding.evidence, f"{finding.id} has empty evidence"
            assert finding.fix is not None, f"{finding.id} missing fix"
            assert finding.fix.summary, f"{finding.id} empty fix.summary"
            assert finding.fix.confidence == "medium", (
                f"{finding.id} should have confidence=medium (W3 LLM will re-evaluate)"
            )


def test_preprocessing_before_split_severity_is_high() -> None:
    result = leakage.run(FIXTURES / "positive_smote_before_split.ipynb")
    for f in result.findings:
        if f.id == "leakage.preprocessing-before-split":
            assert f.severity is Severity.HIGH
            return
    pytest.fail("preprocessing-before-split finding not found")


def test_fit_on_test_severity_is_critical() -> None:
    result = leakage.run(FIXTURES / "positive_fit_on_test.py")
    for f in result.findings:
        if f.id == "leakage.fit-on-test":
            assert f.severity is Severity.CRITICAL
            return
    pytest.fail("fit-on-test finding not found")


def test_label_proxy_severity_is_high() -> None:
    result = leakage.run(FIXTURES / "positive_difficulty_proxy.ipynb")
    for f in result.findings:
        if f.id == "leakage.label-proxy-feature":
            assert f.severity is Severity.HIGH
            return
    pytest.fail("label-proxy-feature finding not found")


# ---------------------------------------------------------------------------
# Negative fixture
# ---------------------------------------------------------------------------


def test_negative_correct_pipeline_is_clean() -> None:
    """The clean pipeline notebook must produce zero leakage findings."""
    result = leakage.run(FIXTURES / "negative_correct_pipeline.ipynb")

    assert result.tool_status == "ok"
    # The negative fixture drops difficulty_level explicitly before feature_cols,
    # so the remaining feature list is clean. SMOTE runs after the split.
    # Only flag if leakage rules actually fire (not supply-chain or other checks).
    leakage_ids = [f.id for f in result.findings if f.id.startswith("leakage.")]
    assert leakage_ids == [], (
        "negative fixture must produce no leakage findings; got: "
        + ", ".join(leakage_ids)
    )


# ---------------------------------------------------------------------------
# Cross-cell ordering tests (inline notebooks)
# ---------------------------------------------------------------------------


def _make_nb(cells: list[str]) -> bytes:
    """Build a minimal .ipynb JSON from a list of code cell source strings."""
    import json

    nb_cells = [
        {
            "cell_type": "code",
            "id": f"c{i}",
            "metadata": {},
            "outputs": [],
            "source": [src],
        }
        for i, src in enumerate(cells)
    ]
    data = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": nb_cells,
    }
    return json.dumps(data).encode()


def test_cross_cell_positive_smote_before_split(tmp_path: Path) -> None:
    """SMOTE fit_resample in cell 0, train_test_split in cell 1 → flagged."""
    nb = tmp_path / "positive_cross.ipynb"
    nb.write_bytes(
        _make_nb([
            "from imblearn.over_sampling import SMOTE\n"
            "smote = SMOTE(random_state=42)\n"
            "X_res, y_res = smote.fit_resample(X, y)\n",
            "from sklearn.model_selection import train_test_split\n"
            "X_train, X_test, y_train, y_test = train_test_split(X_res, y_res)\n",
        ])
    )
    result = leakage.run(nb)
    ids = [f.id for f in result.findings]
    assert "leakage.preprocessing-before-split" in ids


def test_cross_cell_negative_split_before_smote(tmp_path: Path) -> None:
    """train_test_split in cell 0, SMOTE in cell 1 → no preprocessing-before-split."""
    nb = tmp_path / "negative_cross.ipynb"
    nb.write_bytes(
        _make_nb([
            "from sklearn.model_selection import train_test_split\n"
            "X_train, X_test, y_train, y_test = train_test_split(X, y)\n",
            "from imblearn.over_sampling import SMOTE\n"
            "smote = SMOTE(random_state=42)\n"
            "X_res, y_res = smote.fit_resample(X_train, y_train)\n",
        ])
    )
    result = leakage.run(nb)
    ids = [f.id for f in result.findings]
    assert "leakage.preprocessing-before-split" not in ids, (
        "SMOTE after split should not be flagged; findings: " + str(ids)
    )


# ---------------------------------------------------------------------------
# Line translation: finding.line_start must be within the source cell
# ---------------------------------------------------------------------------


def test_line_translation_stays_within_cell(tmp_path: Path) -> None:
    """line_start must refer to the line inside the source cell, not the synthetic module."""
    cell0 = "x = 1\ny = 2\nz = 3\n"  # 3 lines
    cell1 = (
        "from imblearn.over_sampling import SMOTE\n"
        "smote = SMOTE()\n"
        "X_res, y_res = smote.fit_resample(X, y)\n"
    )
    cell2 = (
        "from sklearn.model_selection import train_test_split\n"
        "X_train, X_test, y_train, y_test = train_test_split(X_res, y_res)\n"
    )

    nb = tmp_path / "line_translation.ipynb"
    nb.write_bytes(_make_nb([cell0, cell1, cell2]))

    result = leakage.run(nb)
    before_split = [f for f in result.findings if f.id == "leakage.preprocessing-before-split"]
    assert before_split, "Expected at least one preprocessing-before-split finding"

    for finding in before_split:
        # line_start must be within cell1 (3 lines)
        assert finding.line_start is not None
        assert 1 <= finding.line_start <= len(cell1.splitlines()), (
            f"line_start={finding.line_start} is outside cell1 "
            f"(which has {len(cell1.splitlines())} lines). "
            "Line was not translated from synthetic-module coordinates."
        )


# ---------------------------------------------------------------------------
# Synthetic module line translation unit tests
# ---------------------------------------------------------------------------


def test_build_synthetic_module_cell_start_lines() -> None:
    """cell_start_lines[0] is always 1; subsequent cells start after their markers."""
    sources = ["a = 1\nb = 2\n", "c = 3\n", "d = 4\ne = 5\nf = 6\n"]
    synthetic, starts = _build_synthetic_module(sources)

    assert starts[0] == 1
    # Every start must be within the synthetic string
    for start in starts:
        assert 1 <= start <= synthetic.count("\n") + 1


def test_synthetic_line_to_cell_line_first_cell() -> None:
    sources = ["line1\nline2\nline3\n", "other\n"]
    _, starts = _build_synthetic_module(sources)
    cell_idx, line_in_cell = _synthetic_line_to_cell_line(2, starts, sources)
    assert cell_idx == 0
    assert line_in_cell == 2


def test_synthetic_line_to_cell_line_second_cell() -> None:
    sources = ["line1\nline2\n", "cell2_line1\ncell2_line2\n"]
    synthetic, starts = _build_synthetic_module(sources)
    # Find the actual line of "cell2_line1" in the synthetic source
    cell2_line = synthetic.count("\n", 0, synthetic.index("cell2_line1")) + 1
    cell_idx, line_in_cell = _synthetic_line_to_cell_line(cell2_line, starts, sources)
    assert cell_idx == 1
    assert line_in_cell == 1


# ---------------------------------------------------------------------------
# alias: train_test_split as tts must still be recognised
# ---------------------------------------------------------------------------


def test_tts_alias_is_recognised(tmp_path: Path) -> None:
    """``from sklearn... import train_test_split as tts`` aliased calls are detected."""
    py = tmp_path / "alias_split.py"
    py.write_text(
        "from sklearn.preprocessing import StandardScaler\n"
        "from sklearn.model_selection import train_test_split as tts\n"
        "scaler = StandardScaler()\n"
        "X_scaled = scaler.fit_transform(X)\n"  # before split → should flag
        "X_train, X_test, y_train, y_test = tts(X_scaled, y)\n",
        encoding="utf-8",
    )
    result = leakage.run(py)
    ids = [f.id for f in result.findings]
    assert "leakage.preprocessing-before-split" in ids, (
        "Aliased tts() call must be treated as train_test_split; got: " + str(ids)
    )


# ---------------------------------------------------------------------------
# Label-proxy name heuristic — parametrized positive + negative names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "col_name",
    [
        "difficulty_level",
        "difficulty",
        "attack_label",
        "some_target",
        "target_class",
        "label_encoded",
        "outcome",
        "result_class",
        "class_id",
        "is_credit_fraud",
        "data_leak",
        "leak_score",
        "cheat_feature",
    ],
)
def test_label_proxy_names_are_flagged(col_name: str, tmp_path: Path) -> None:
    """Each label-proxy column name must be detected."""
    py = tmp_path / "proxy.py"
    py.write_text(
        f"features = ['duration', 'src_bytes', '{col_name}', 'count']\n",
        encoding="utf-8",
    )
    result = leakage.run(py)
    ids = [f.id for f in result.findings]
    assert "leakage.label-proxy-feature" in ids, (
        f"Expected label-proxy-feature for column '{col_name}'; got: {ids}"
    )


@pytest.mark.parametrize(
    "col_name",
    [
        "src_bytes",
        "dst_bytes",
        "protocol_type",
        "duration",
        "count",
        "flag",
        "service",
        "num_failed_logins",
    ],
)
def test_safe_column_names_are_not_flagged(col_name: str, tmp_path: Path) -> None:
    """Legitimate feature column names must not trigger label-proxy-feature."""
    py = tmp_path / "safe.py"
    py.write_text(
        f"features = ['duration', 'src_bytes', '{col_name}']\n",
        encoding="utf-8",
    )
    result = leakage.run(py)
    proxy_findings = [f for f in result.findings if f.id == "leakage.label-proxy-feature"]
    assert proxy_findings == [], (
        f"Column '{col_name}' falsely flagged as label proxy"
    )


def test_is_label_proxy_function_directly() -> None:
    """Unit-test the _is_label_proxy predicate."""
    assert _is_label_proxy("difficulty_level")
    assert _is_label_proxy("DIFFICULTY_LEVEL")
    assert _is_label_proxy("attack_label")
    assert _is_label_proxy("target_class")
    assert _is_label_proxy("outcome")
    assert _is_label_proxy("is_bank_fraud")
    assert not _is_label_proxy("src_bytes")
    assert not _is_label_proxy("count")
    assert not _is_label_proxy("duration")
    assert not _is_label_proxy("protocol_type")


# ---------------------------------------------------------------------------
# Empty / malformed inputs
# ---------------------------------------------------------------------------


def test_empty_directory_produces_no_findings(tmp_path: Path) -> None:
    result = leakage.run(tmp_path)
    assert result.findings == []
    assert result.tool_status == "ok"


def test_malformed_notebook_is_skipped(tmp_path: Path) -> None:
    nb = tmp_path / "bad.ipynb"
    nb.write_text("this is not json", encoding="utf-8")
    result = leakage.run(nb)
    assert result.tool_status == "ok"
    assert result.findings == []


# ---------------------------------------------------------------------------
# v1 integration: at least 2 distinct rule ids on the real notebook
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not NIDS_V1.exists(),
    reason="nids_v1_baseline.ipynb not present in sibling directory",
)
def test_nids_v1_fires_at_least_one_rule() -> None:
    """The real v1 NIDS notebook must produce at least one leakage finding.

    The v1 notebook uses separate CSV files for train/test (no train_test_split
    call), so ``leakage.preprocessing-before-split`` cannot fire — the SMOTE
    runs on ``X_train_scaled`` (correctly post-split). The guaranteed finding
    is ``leakage.label-proxy-feature`` for ``difficulty_level``.
    """
    result = leakage.run(NIDS_V1)

    assert result.findings, (
        "Expected at least one leakage finding on nids_v1_baseline.ipynb; got none."
    )
    rule_ids = {f.id for f in result.findings}
    assert "leakage.label-proxy-feature" in rule_ids, (
        f"Expected label-proxy-feature; got: {sorted(rule_ids)}"
    )


@pytest.mark.skipif(
    not NIDS_V1.exists(),
    reason="nids_v1_baseline.ipynb not present in sibling directory",
)
def test_nids_v1_fires_label_proxy_for_difficulty_level() -> None:
    """difficulty_level in the v1 column list must trigger label-proxy-feature."""
    result = leakage.run(NIDS_V1)

    proxy_findings = [f for f in result.findings if f.id == "leakage.label-proxy-feature"]
    difficulty_findings = [
        f for f in proxy_findings if "difficulty_level" in f.message
    ]
    assert difficulty_findings, (
        "Expected at least one label-proxy-feature finding mentioning difficulty_level. "
        f"All proxy findings: {[f.message for f in proxy_findings]}"
    )
