"""Tests for the deserialization check.

Fixture pair: one notebook that must produce findings for all 4 rule classes,
one that must produce zero findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mlsecops_agent.checks import deserialization
from mlsecops_agent.models import CheckName, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "deserialization"

# The real v1 notebook sits one directory above the repo root.
NIDS_V1 = Path(__file__).parent.parent.parent.parent / "nids_v1_baseline.ipynb"


def test_positive_fixture_flags_all_four_rule_classes() -> None:
    result = deserialization.run(FIXTURES / "positive_unsafe_loads.ipynb")

    assert result.check is CheckName.DESERIALIZATION
    assert result.tool_status == "ok"

    ids = {f.id for f in result.findings}
    assert "deserialization.unsafe-joblib-load" in ids
    assert "deserialization.unsafe-pickle-load" in ids
    assert "deserialization.unsafe-torch-load" in ids
    assert "deserialization.unsafe-numpy-load" in ids


def test_positive_fixture_findings_have_required_fields() -> None:
    result = deserialization.run(FIXTURES / "positive_unsafe_loads.ipynb")

    for finding in result.findings:
        assert finding.line_start is not None, f"{finding.id} missing line_start"
        assert finding.line_end is not None, f"{finding.id} missing line_end"
        assert finding.evidence, f"{finding.id} has empty evidence"
        assert finding.fix is not None, f"{finding.id} missing fix"
        assert finding.fix.summary, f"{finding.id} has empty fix.summary"


def test_positive_fixture_severities() -> None:
    result = deserialization.run(FIXTURES / "positive_unsafe_loads.ipynb")

    high_ids = {
        "deserialization.unsafe-joblib-load",
        "deserialization.unsafe-pickle-load",
        "deserialization.unsafe-torch-load",
    }
    for finding in result.findings:
        if finding.id in high_ids:
            assert finding.severity is Severity.HIGH, (
                f"{finding.id} should be HIGH, got {finding.severity}"
            )
        elif finding.id == "deserialization.unsafe-numpy-load":
            assert finding.severity is Severity.MEDIUM, (
                f"numpy-load should be MEDIUM, got {finding.severity}"
            )


def test_negative_fixture_is_clean() -> None:
    result = deserialization.run(FIXTURES / "negative_safe_loads.ipynb")

    assert result.tool_status == "ok"
    assert result.findings == [], (
        "negative fixture must produce no findings; got: "
        + ", ".join(f.id for f in result.findings)
    )


def test_alias_import_is_flagged(tmp_path: Path) -> None:
    """``import joblib as jl; jl.load(...)`` must be detected."""
    nb = tmp_path / "alias.ipynb"
    nb.write_text(
        '{"nbformat":4,"nbformat_minor":5,"metadata":{},"cells":['
        '{"cell_type":"code","id":"c0","metadata":{},"outputs":[],'
        '"source":["import joblib as jl\\n","model = jl.load(\'m.pkl\')"]}'
        "]}",
        encoding="utf-8",
    )
    result = deserialization.run(nb)
    ids = [f.id for f in result.findings]
    assert "deserialization.unsafe-joblib-load" in ids


def test_from_import_torch_is_flagged(tmp_path: Path) -> None:
    """``from torch import load; load(...)`` without weights_only must be detected.

    QualifiedNameProvider resolves from-imports to their fully qualified name,
    so torch.load is detected regardless of import style.
    """
    py = tmp_path / "from_import.py"
    py.write_text(
        "from torch import load\n"
        "checkpoint = load('model.pt')\n",
        encoding="utf-8",
    )
    result = deserialization.run(py)
    ids = [f.id for f in result.findings]
    assert "deserialization.unsafe-torch-load" in ids


def test_torch_load_with_weights_only_true_is_not_flagged(tmp_path: Path) -> None:
    py = tmp_path / "safe_torch.py"
    py.write_text(
        "import torch\n"
        "checkpoint = torch.load('model.pt', weights_only=True)\n",
        encoding="utf-8",
    )
    result = deserialization.run(py)
    assert not any(
        f.id == "deserialization.unsafe-torch-load" for f in result.findings
    ), "torch.load(weights_only=True) must not be flagged"


def test_numpy_load_without_allow_pickle_is_not_flagged(tmp_path: Path) -> None:
    py = tmp_path / "safe_numpy.py"
    py.write_text(
        "import numpy as np\n"
        "arr = np.load('data.npy')\n"
        "arr2 = np.load('data.npy', allow_pickle=False)\n",
        encoding="utf-8",
    )
    result = deserialization.run(py)
    assert not any(
        f.id == "deserialization.unsafe-numpy-load" for f in result.findings
    ), "numpy.load without allow_pickle=True must not be flagged"


def test_empty_directory_produces_no_findings(tmp_path: Path) -> None:
    result = deserialization.run(tmp_path)
    assert result.findings == []
    assert result.tool_status == "ok"


def test_pure_python_file(tmp_path: Path) -> None:
    """Check that .py files are scanned in addition to notebooks."""
    py = tmp_path / "train.py"
    py.write_text(
        "import pickle\n"
        "with open('model.pkl', 'rb') as f:\n"
        "    clf = pickle.load(f)\n",
        encoding="utf-8",
    )
    result = deserialization.run(py)
    ids = [f.id for f in result.findings]
    assert "deserialization.unsafe-pickle-load" in ids


@pytest.mark.skipif(
    not NIDS_V1.exists(),
    reason="nids_v1_baseline.ipynb not present in sibling directory",
)
def test_nids_v1_joblib_load_findings() -> None:
    """The real v1 NIDS notebook contains exactly 4 ``joblib.load`` calls."""
    result = deserialization.run(NIDS_V1)

    joblib_findings = [
        f for f in result.findings if f.id == "deserialization.unsafe-joblib-load"
    ]
    assert len(joblib_findings) >= 4, (
        f"Expected >= 4 unsafe-joblib-load findings in nids_v1_baseline.ipynb, "
        f"got {len(joblib_findings)}"
    )
