"""Adversarial-robustness check.

Loads saved Keras classifiers (``.h5`` or ``.keras`` files) found under the
target directory and measures how easily an attacker can flip their predictions
using the Fast Gradient Sign Method (FGSM).

This check is **opt-in** — pass ``include_adversarial=True`` to the ``run``
function.  Without that flag it returns an empty result immediately so that the
default agent loop and CLI do not incur the TensorFlow startup cost for audits
where the caller hasn't explicitly requested it.

A finding ``adversarial.fgsm-trivial-evasion`` at severity HIGH is emitted for
every model where FGSM with eps=0.05 flips more than 50 % of probe samples.

``tool_status`` meanings used here:

- ``"ok"`` — check ran normally (findings may be empty).
- ``"tool_missing"`` — TensorFlow is not importable; check is skipped.
- ``"tool_error"`` — unexpected error during setup/teardown.
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

import numpy as np
import structlog
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import KerasClassifier

from ..models import CheckName, CheckResult, Finding, FixProposal, Severity

if TYPE_CHECKING:
    from pathlib import Path

_log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TensorFlow runtime-guard — TF is NOT a declared project dependency.
# We import at module level so _probe_model can branch on _TF_AVAILABLE.
# The type: ignore suppresses mypy's "untyped" complaint; tensorflow.* is in
# the mypy overrides section of pyproject.toml so errors are silenced there.
# ---------------------------------------------------------------------------

try:
    import tensorflow as tf

    _TF_AVAILABLE = True
except ImportError:
    _TF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

_FGSM_EPS: float = 0.05
_N_PROBES: int = 100
_CONFIDENCE_THRESHOLD: float = 0.7
_EVASION_THRESHOLD: float = 0.50  # flag when attack success > 50 %


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_SKIP_PARTS = frozenset({".venv", "venv", "__pycache__", "site-packages", ".git", "node_modules"})


def _find_model_files(target: Path) -> list[Path]:
    """Return ``.h5`` and ``.keras`` files under *target* (or *target* itself).

    Skips files inside virtualenvs and other dependency directories — picking up
    `h5py`'s test fixtures from `site-packages/h5py/tests/data_files/*.h5` would
    produce useless ``load-failed`` warnings on every audit.
    """
    if target.is_file():
        if target.suffix in {".h5", ".keras"}:
            return [target]
        return []
    found: list[Path] = []
    for pattern in ("**/*.h5", "**/*.keras"):
        for path in target.glob(pattern):
            if any(part in _SKIP_PARTS for part in path.parts):
                continue
            found.append(path)
    return sorted(found)


def _probe_model(model_path: Path) -> Finding | None:
    """Load the Keras model at *model_path*, run FGSM, and return a Finding or None.

    Returns None when:
    - the model fails to load,
    - no confident probes can be synthesised (an untrained random network may
      never exceed the confidence threshold for randomly generated inputs),
    - the attack success rate is at or below ``_EVASION_THRESHOLD``.

    All exceptions are caught so a single corrupt model cannot crash the check.
    """
    try:
        model = tf.keras.models.load_model(str(model_path))
    except Exception as exc:
        _log.warning("adversarial.load-failed", model=str(model_path), error=str(exc))
        return None

    # Determine input shape — typically (None, n_features) for dense networks.
    try:
        input_shape = model.input_shape
    except Exception as exc:
        _log.warning("adversarial.input-shape-failed", model=str(model_path), error=str(exc))
        return None

    # Supported shapes:
    #  - (batch, features)           — dense networks
    #  - (batch, features, 1)        — Conv1D / LSTM with single-channel features,
    #                                  the standard NSL-KDD / tabular-sequence layout.
    if not isinstance(input_shape, tuple):
        _log.info(
            "adversarial.unsupported-input-shape",
            model=str(model_path),
            shape=str(input_shape),
        )
        return None

    rank = len(input_shape)
    if rank == 2:
        n_features = int(input_shape[1])
        probe_shape: tuple[int, ...] = (_N_PROBES, n_features)
        art_input_shape: tuple[int, ...] = (n_features,)
    elif rank == 3 and input_shape[-1] == 1:
        n_features = int(input_shape[1])
        probe_shape = (_N_PROBES, n_features, 1)
        art_input_shape = (n_features, 1)
    else:
        _log.info(
            "adversarial.unsupported-input-shape",
            model=str(model_path),
            shape=str(input_shape),
        )
        return None

    n_classes: int = int(model.output_shape[-1])

    # Synthesise probe inputs: uniform random in [0, 1].
    rng = np.random.default_rng(seed=42)
    x_raw: np.ndarray = rng.random(probe_shape, dtype=np.float32)

    # Score probes; keep only the ones the model is confident about.
    try:
        preds_raw: np.ndarray = model.predict(x_raw, verbose=0)
    except Exception as exc:
        _log.warning("adversarial.predict-failed", model=str(model_path), error=str(exc))
        return None

    top_conf: np.ndarray = preds_raw.max(axis=1)
    x_probe: np.ndarray = x_raw[top_conf > _CONFIDENCE_THRESHOLD]

    if x_probe.shape[0] == 0:
        # An untrained random network may not be confident about anything —
        # not a finding, just nothing to attack.
        _log.info(
            "adversarial.no-confident-probes",
            model=str(model_path),
            n_raw=_N_PROBES,
        )
        return None

    # Wrap the Keras model with ART's KerasClassifier.
    try:
        # ART >= 1.20 dropped nb_classes / input_shape — both are inferred from
        # the model.  Keep clip_values to constrain perturbations to [0, 1].
        del n_classes, art_input_shape  # explicitly unused after the rank check
        classifier = KerasClassifier(
            model=model,
            clip_values=(0.0, 1.0),
        )
    except Exception as exc:
        _log.warning("adversarial.art-wrap-failed", model=str(model_path), error=str(exc))
        return None

    # Run FGSM to generate adversarial examples.
    try:
        fgsm = FastGradientMethod(estimator=classifier, eps=_FGSM_EPS)
        x_adv: np.ndarray = fgsm.generate(x=x_probe)
    except Exception as exc:
        _log.warning("adversarial.fgsm-failed", model=str(model_path), error=str(exc))
        return None

    # Measure attack success = fraction of probes where argmax prediction flipped.
    try:
        preds_clean: np.ndarray = classifier.predict(x_probe)
        preds_adv: np.ndarray = classifier.predict(x_adv)
    except Exception as exc:
        _log.warning(
            "adversarial.post-attack-predict-failed",
            model=str(model_path),
            error=str(exc),
        )
        return None

    labels_clean: np.ndarray = preds_clean.argmax(axis=1)
    labels_adv: np.ndarray = preds_adv.argmax(axis=1)
    n_flipped: int = int((labels_clean != labels_adv).sum())
    attack_success: float = n_flipped / len(x_probe)

    _log.info(
        "adversarial.fgsm-result",
        model=str(model_path),
        n_probes=len(x_probe),
        n_flipped=n_flipped,
        attack_success=f"{attack_success:.1%}",
        eps=_FGSM_EPS,
    )

    if attack_success <= _EVASION_THRESHOLD:
        return None

    pct = f"{attack_success:.0%}"
    return Finding(
        id="adversarial.fgsm-trivial-evasion",
        check=CheckName.ADVERSARIAL,
        severity=Severity.HIGH,
        category="adversarial-robustness",
        file=model_path,
        line_start=None,
        line_end=None,
        message=(
            f"`{model_path.name}` is trivially evadable: FGSM with eps={_FGSM_EPS} "
            f"flips {pct} of confident probe predictions "
            f"({n_flipped}/{len(x_probe)} samples). "
            "An adversary can craft inputs that bypass this classifier with minimal perturbation."
        ),
        evidence=(
            f"attack_success={pct}, eps={_FGSM_EPS}, n_probes={len(x_probe)}, n_flipped={n_flipped}"
        ),
        fix=FixProposal(
            summary=(
                "Apply adversarial training (e.g. `art.defences.trainer.AdversarialTrainer`) "
                "or a certified defence (randomised smoothing, interval-bound propagation) "
                "to make the model robust to small-norm perturbations. "
                "Re-evaluate with FGSM, PGD, and AutoAttack after each defence iteration."
            ),
            confidence="high",
        ),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run(target: Path, *, include_adversarial: bool = False) -> CheckResult:
    """Run the adversarial-robustness check against *target*.

    By default (``include_adversarial=False``) this is a no-op — loading Keras
    models and running TensorFlow incurs heavy startup cost and requires
    TensorFlow to be installed.  Pass ``include_adversarial=True`` to opt in.

    The CLI ``--include-adversarial`` flag wiring is a follow-up task; this
    parameter is the extension point.
    """
    started = time.perf_counter()

    if not include_adversarial:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return CheckResult(
            check=CheckName.ADVERSARIAL,
            findings=[],
            tool_status="ok",
            duration_ms=elapsed_ms,
        )

    if not _TF_AVAILABLE:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        _log.warning("adversarial.tensorflow-missing")
        print(
            "adversarial check: TensorFlow is not installed — skipping model loading.",
            file=sys.stderr,
        )
        return CheckResult(
            check=CheckName.ADVERSARIAL,
            findings=[],
            tool_status="tool_missing",
            duration_ms=elapsed_ms,
        )

    model_files = _find_model_files(target)
    findings: list[Finding] = []

    for model_path in model_files:
        try:
            finding = _probe_model(model_path)
        except Exception as exc:
            # Belt-and-suspenders: _probe_model already catches internally.
            _log.error("adversarial.unexpected-error", model=str(model_path), error=str(exc))
            continue
        if finding is not None:
            findings.append(finding)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        check=CheckName.ADVERSARIAL,
        findings=findings,
        tool_status="ok",
        duration_ms=elapsed_ms,
    )
