# mlsecops audit report

- **Target:** `..\nids_pipeline_v2.ipynb`
- **Generated:** 2026-05-28 00:28:58 UTC
- **Total findings:** 4 (3 from the deterministic checks + 1 from the FGSM robustness sweep on the LSTM)
- **Exit status:** ❌ blocking (HIGH/CRITICAL present)

> **Why this report exists.** v1 of this NIDS notebook was audited and produced [17 findings](v1_audit_report.md). I applied the recommended fixes in v2. This report is the closing-loop measurement.
>
> **Headline**: 17 → 4 findings (–76 %). The deserialization, secrets, and leakage pillars are clean. The 3 supply-chain items are documented Colab-pasteability compromises. The 1 adversarial finding is a real, measured brittleness in the LSTM under in-distribution FGSM perturbations — the v1 README's "LSTM trivially evadable" claim turned out to be right, just at higher epsilon than initial measurements suggested.

## v1 → v2 delta

| Check | v1 | v2 | Net change | What happened |
|---|---:|---:|---|---|
| `deserialization` | 8 | 0 | **–8 ✅** | v2 only *saves* artifacts; the unsafe `joblib.load` / `numpy.load(allow_pickle=True)` calls that loaded models back in v1 were removed. |
| `leakage` | 2 | **0** | **–2 ✅** | The two earlier "false positives" are now correctly suppressed by the smarter AST analysis: `df.drop(columns=['difficulty_level'])` cancels the label-proxy finding for that column, and `le.fit(['DoS', 'Normal', …])` is recognised as class registration against a literal list rather than data-dependent fitting. |
| `supply_chain` | 7 | 3 | –4 | `!pip install imbalanced-learn -q` + two `!wget` calls from raw GitHub remain. v2 intentionally didn't pin or checksum these — the pipeline must remain Colab-pasteable. Documented compromise. |
| `secrets` | 0 | 0 | 0 | Both clean. |
| `adversarial` | 0 | **1 (HIGH)** | +1 | FGSM sweep on real `KDDTest+` attack samples: LSTM is trivially evadable at ε≥0.10 (49.8 %) and dramatically so at ε=0.20 (77 %). The CNN stays under the threshold across the sweep but climbs to 43.4 % at ε=0.30. See the dedicated section below. |
| `scenario` | 2 (CRITICAL) | **0** | **–2 ✅** | v1's chained findings (supply-chain → RCE; label-leakage → inflated metrics) no longer have all the required ingredients in v2. |
| **Total** | **17** | **4** | **–13 (–76 %)** | 3 documented compromises (supply chain), 1 real, severe finding (LSTM adversarial brittleness) that v1 only speculated about and v2 now measures. |

## Summary

| Check | Findings | Max severity | Duration | Status |
|---|---:|---|---:|---|
| `adversarial` | **1** | 🟠 high | sweep | issues |
| `supply_chain` | 3 | 🟡 medium | 1ms | issues |
| `deserialization` | 0 | — | 318ms | clean |
| `leakage` | 0 | — | 3185ms | clean |
| `secrets` | 0 | — | 0ms | clean |
| `scenario` | 0 | — | 0ms | clean |

## `supply_chain` — 3 finding(s)

_Tool status: `ok`. Duration: 1ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟡 medium | `supply_chain.unpinned-pip-install` | `..\nids_pipeline_v2.ipynb:3` | `!pip install imbalanced-learn` has no version pin (cell 2). Re-runs may install a different version and silently break the pipeline. | `!pip install imbalanced-learn -q` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_pipeline_v2.ipynb:1` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 2). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_pipeline_v2.ipynb:2` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 2). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt` |

### Fix proposals

- **`supply_chain.unpinned-pip-install`** at `..\nids_pipeline_v2.ipynb`:3 (high confidence) — Pin `imbalanced-learn` to a known-good version: `!pip install imbalanced-learn==X.Y.Z` and record it in `requirements.txt` / `pyproject.toml`.
- **`supply_chain.untrusted-wget-source`** at `..\nids_pipeline_v2.ipynb`:1 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.
- **`supply_chain.untrusted-wget-source`** at `..\nids_pipeline_v2.ipynb`:2 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.

## `adversarial` — 1 finding (FGSM robustness sweep)

_Tool status: `ok`._

### Robustness sweep — FGSM with real KDDTest+ attack samples

Probes are 1000 in-distribution attack samples from `KDDTest+` (filtered to those the model is confident about — softmax max > 0.7). FGSM `L∞` perturbations at five `ε` values; `clip_values` set to the empirical feature-range of the probes.

| Model | ε=0.01 | ε=0.05 | ε=0.10 | ε=0.20 | ε=0.30 |
|---|---:|---:|---:|---:|---:|
| `nids_v2_cnn.keras` | 4.3 % | 16.0 % | 26.4 % | 38.2 % | 43.4 % |
| `nids_v2_lstm.keras` | 3.9 % | 19.6 % | **49.8 %** | **77.0 %** | **83.6 %** |

(Confident probes after filtering: 973 / 1000 for CNN, 827 / 1000 for LSTM.)

### Finding

`adversarial.fgsm-trivial-evasion` HIGH severity on `nids_v2_lstm.keras`. At ε=0.20 — a perturbation of 20 % of the feature range, well within the budget a real attacker on a network flow has — 77 % of in-distribution attack predictions flip to the wrong class. At ε=0.10 the LSTM is exactly at the trivial-evasion threshold; at ε=0.30 83.6 % of predictions can be moved.

The Conv1D CNN does **not** cross the 50 % threshold at any ε in the sweep — it's the more robust of the two architectures on this dataset, though `ε=0.30 → 43.4 %` is high enough to be a soft warning (recorded but not raised as a HIGH finding).

### Methodology note

An earlier draft of this report used 100 *uniform random* probes in `[0, 1]` and recorded an LSTM flip rate of 1 %. That number was honest but uninformative — random noise sits outside the training distribution and the network correctly emits low-confidence predictions on it that ART finds little gradient signal to attack. Switching to in-distribution probes is what made the underlying brittleness visible.

### Fix proposal

Apply adversarial training: re-train the LSTM on a mixture of clean samples and FGSM-perturbed copies at the same ε regime (e.g. 0.1–0.3). The IBM ART library exposes this directly:

```python
from art.defences.trainer import AdversarialTrainer
trainer = AdversarialTrainer(classifier, attacks=FastGradientMethod(classifier, eps=0.2))
trainer.fit(x_train, y_train, nb_epochs=10)
```

After re-training, re-run this sweep; the goal is to push every ε row below 30 % flip rate (a soft "robust enough" target for NIDS deployment).

## `deserialization` — 0 finding(s)

_Tool status: `ok`. Duration: 318ms._

No issues found.

## `leakage` — 0 finding(s)

_Tool status: `ok`. Duration: 3185ms._

No issues found. The previous draft of this report flagged two leakage findings (label-proxy and preprocessing-before-split); both were honest static-analysis false positives that the agent now correctly suppresses:

- `df.drop(columns=['difficulty_level'])` cancels the label-proxy finding on the column-list literal that declares it.
- `le.fit(['DoS', 'Normal', 'Probe', 'R2L', 'U2R'])` is recognised as registering classes against a literal string list, not a data-dependent fit, so it doesn't trigger `preprocessing-before-split`.

Both behaviours have regression tests in `tests/checks/test_leakage.py`.

## `secrets` — 0 finding(s)

_Tool status: `ok`. Duration: 0ms._

No issues found.

## `scenario` — 0 finding(s)

_Tool status: `ok`. Duration: 0ms._

No multi-finding threat chains triggered. v1 fired two scenarios at CRITICAL severity (supply-chain-to-rce, label-leakage-to-inflated-metrics); v2 cleared both by removing the deserialisation calls and the label proxy.
