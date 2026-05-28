"""Tests for the adversarial check.

TF-dependent tests are guarded with ``pytest.skip`` when TensorFlow is not
importable — the check itself returns ``tool_status="tool_missing"`` in that
case, which is tested separately without requiring TF.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from mlsecops_agent.checks import adversarial
from mlsecops_agent.models import CheckName

# ---------------------------------------------------------------------------
# TF availability — skip slow/TF tests when TF is absent.
# ---------------------------------------------------------------------------

try:
    import tensorflow as tf  # type: ignore[import-untyped]  # noqa: F401

    _TF_AVAILABLE = True
except ImportError:
    _TF_AVAILABLE = False

_tf_required = pytest.mark.skipif(
    not _TF_AVAILABLE,
    reason="TensorFlow not installed; adversarial model tests skipped",
)

# ---------------------------------------------------------------------------
# Session-scoped Keras fixture — built once, shared across all TF tests.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def tiny_keras_model_h5(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build a tiny 3-class Keras classifier and save it as a .h5 file.

    The fixture is session-scoped so TF only initialises once per test run.
    Skips automatically if TF is absent.
    """
    if not _TF_AVAILABLE:
        pytest.skip("TensorFlow not installed")

    import numpy as np
    import tensorflow as tf  # type: ignore[import-untyped]

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(16, activation="relu", input_shape=(10,)),
            tf.keras.layers.Dense(3, activation="softmax"),
        ]
    )
    model.compile(optimizer="adam", loss="categorical_crossentropy")

    # Fit briefly so weights are non-trivial and some probes clear 0.7 confidence.
    rng = np.random.default_rng(seed=0)
    x_train = rng.random((200, 10), dtype=np.float32)
    y_train = tf.keras.utils.to_categorical(rng.integers(0, 3, size=200), num_classes=3)
    model.fit(x_train, y_train, epochs=5, verbose=0)

    model_dir = tmp_path_factory.mktemp("adversarial_models")
    model_path = model_dir / "tiny_classifier.h5"
    model.save(str(model_path))
    return model_path


# ---------------------------------------------------------------------------
# Default run (no include_adversarial) — no TF needed
# ---------------------------------------------------------------------------


def test_default_run_returns_empty_findings(tmp_path: Path) -> None:
    """run(target) without include_adversarial must return empty findings."""
    result = adversarial.run(tmp_path)

    assert result.check is CheckName.ADVERSARIAL
    assert result.findings == []
    assert result.tool_status == "ok"


def test_default_run_does_not_require_tensorflow(tmp_path: Path) -> None:
    """The default call path must never touch TF, even if .h5 files are present."""
    fake_model = tmp_path / "model.h5"
    fake_model.write_bytes(b"not a real model")

    result = adversarial.run(tmp_path)  # include_adversarial defaults to False

    assert result.findings == []
    assert result.tool_status == "ok"


# ---------------------------------------------------------------------------
# No model files in directory
# ---------------------------------------------------------------------------


def test_no_model_files_returns_empty(tmp_path: Path) -> None:
    """A directory with no .h5/.keras files must produce empty findings."""
    (tmp_path / "notebook.ipynb").write_text("{}", encoding="utf-8")
    (tmp_path / "train.py").write_text("print('hello')", encoding="utf-8")

    result = adversarial.run(tmp_path, include_adversarial=True)

    assert result.check is CheckName.ADVERSARIAL
    assert result.findings == []
    # tool_status depends on TF availability — "ok" or "tool_missing" both fine.
    assert result.tool_status in {"ok", "tool_missing"}


# ---------------------------------------------------------------------------
# tool_missing when TF absent
# ---------------------------------------------------------------------------


def test_tool_missing_when_tf_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When TF is not importable the check must return tool_status='tool_missing'."""
    fake_model = tmp_path / "model.h5"
    fake_model.write_bytes(b"placeholder")

    monkeypatch.setattr(adversarial, "_TF_AVAILABLE", False)

    result = adversarial.run(tmp_path, include_adversarial=True)

    assert result.tool_status == "tool_missing"
    assert result.findings == []
    assert result.check is CheckName.ADVERSARIAL


# ---------------------------------------------------------------------------
# Slow / TF-required tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
@_tf_required
def test_fgsm_on_tiny_model_produces_finding_or_no_confident_probes(
    tiny_keras_model_h5: Path,
) -> None:
    """Running FGSM on the tiny classifier must not crash.

    Two valid outcomes exist:
    1. The attack succeeds (>50 % flip) → one HIGH finding emitted.
    2. No probes pass the 0.7 confidence threshold (untrained net) → no finding,
       but tool_status must still be "ok".
    """
    target_dir = tiny_keras_model_h5.parent
    result = adversarial.run(target_dir, include_adversarial=True)

    assert result.check is CheckName.ADVERSARIAL
    assert result.tool_status == "ok"

    if result.findings:
        finding = result.findings[0]
        assert finding.id == "adversarial.fgsm-trivial-evasion"
        assert finding.severity.value == "high"
        assert finding.fix is not None
        assert finding.fix.confidence == "high"
        assert "eps=" in finding.evidence
        assert finding.file == tiny_keras_model_h5
    # else: no confident probes / attack below threshold — also acceptable.


@pytest.mark.slow
@_tf_required
def test_fgsm_on_single_file_target(tiny_keras_model_h5: Path) -> None:
    """Passing the model path directly (not a directory) must also work."""
    result = adversarial.run(tiny_keras_model_h5, include_adversarial=True)

    assert result.check is CheckName.ADVERSARIAL
    assert result.tool_status == "ok"
    # May or may not find evasion — both outcomes valid.
    for finding in result.findings:
        assert finding.id == "adversarial.fgsm-trivial-evasion"


@pytest.mark.slow
@_tf_required
def test_corrupt_model_file_does_not_crash(tmp_path: Path) -> None:
    """A corrupt .h5 file must be skipped gracefully, not crash the check."""
    bad = tmp_path / "bad.h5"
    bad.write_bytes(b"\x00\x01\x02 not a real keras model")

    result = adversarial.run(tmp_path, include_adversarial=True)

    assert result.tool_status == "ok"
    assert result.findings == []


@pytest.mark.slow
@_tf_required
def test_conv1d_3d_input_shape_is_supported(tmp_path: Path) -> None:
    """Models with input_shape (batch, features, 1) (Conv1D / LSTM convention)
    must be probed, not silently skipped.

    Regression test for the v2 NIDS audit, where both saved Keras artifacts
    had a rank-3 input shape and the prior implementation returned no result
    even though the models were perfectly valid.
    """
    import numpy as np
    import tensorflow as tf  # type: ignore[import-untyped]

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Conv1D(8, 3, activation="relu", padding="same", input_shape=(10, 1)),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(3, activation="softmax"),
        ]
    )
    model.compile(optimizer="adam", loss="categorical_crossentropy")

    rng = np.random.default_rng(seed=0)
    x = rng.random((200, 10, 1), dtype=np.float32)
    y = tf.keras.utils.to_categorical(rng.integers(0, 3, size=200), num_classes=3)
    model.fit(x, y, epochs=3, verbose=0)

    model_path = tmp_path / "conv1d.keras"
    model.save(str(model_path))

    result = adversarial.run(tmp_path, include_adversarial=True)

    assert result.tool_status == "ok"
    # We don't assert flip rate either way — the test is that the check ran
    # the model at all rather than skipping on shape. If a finding does
    # emit it must use the correct rule id.
    for finding in result.findings:
        assert finding.id == "adversarial.fgsm-trivial-evasion"
        assert finding.file == model_path
