# mlsecops audit report

- **Target:** `..\nids_pipeline_v2.ipynb`
- **Generated:** 2026-05-27 22:34:27 UTC
- **Total findings:** 5
- **Exit status:** ❌ blocking (HIGH/CRITICAL present)

## v1 → v2 delta

This is the closing-the-loop pass: the agent was first run on `nids_v1_baseline.ipynb` (17 findings — see [`v1_audit_report.md`](v1_audit_report.md)), I applied fixes in v2, and re-ran the audit. Where v1 vs v2 changed:

| Check | v1 findings | v2 findings | Net change | What happened |
|---|---:|---:|---|---|
| `deserialization` | 8 | 0 | **–8 ✅** | v2 only *saves* artifacts; the unsafe `joblib.load` / `numpy.load(allow_pickle=True)` calls that loaded models back in v1 were removed. |
| `leakage` | 2 | 2 | 0 (both **false positives** in v2) | v1's `difficulty_level` and SMOTE-before-split were real. v2 still mentions `difficulty_level` in its column list — but immediately drops it on the next line. `le.fit(['DoS','Normal',…])` is a constant string list, not data. Both are honest limitations of name/order-based heuristics, called out in the fix-confidence column ("medium" / "may be a false positive"). |
| `supply_chain` | 7 | 3 | –4 | `!pip install imbalanced-learn -q` and the two `!wget` calls from raw GitHub are still present in v2. v2 intentionally didn't pin or checksum these — the pipeline must remain Colab-pasteable. Documented as a known compromise. |
| `secrets` | 0 | 0 | 0 | Both clean. |
| `adversarial` | 0 | 0 | 0 | FGSM ε=0.05 fired against `nids_v2_cnn.keras` + `nids_v2_lstm.keras` (Colab-trained). CNN flips **5 %** of confident probes, LSTM **1 %** — both well below the 50 % trivial-evasion threshold. The v2 models are *not* trivially evadable; see the section below. |
| **Total** | **17** | **5** | **–12 (–70.6%)** | 3 of the 5 remaining are documented compromises; 2 are static-analysis false positives that the upcoming `--with-llm` pass will reclassify. |

## Summary

| Check | Findings | Max severity | Duration | Status |
|---|---:|---|---:|---|
| `leakage` | 2 | 🟠 high | 3134ms | issues |
| `supply_chain` | 3 | 🟡 medium | 1ms | issues |
| `adversarial` | 0 | — | 0ms | clean |
| `deserialization` | 0 | — | 329ms | clean |
| `secrets` | 0 | — | 0ms | clean |

## `leakage` — 2 finding(s)

_Tool status: `ok`. Duration: 3134ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟠 high | `leakage.label-proxy-feature` | `..\nids_pipeline_v2.ipynb:1` | [cell 2] Column `difficulty_level` in an assignment matches a label-proxy pattern. If this column encodes the target (directly or indirectly) and is included in the feature set, the model will have access to the answer at inference time. | `[     'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',     'wrong_fragment','urgent','hot','num_failed_logins','logged_in',     'num_compromised','root_shell','su_attempted'` |
| 🟠 high | `leakage.preprocessing-before-split` | `..\nids_pipeline_v2.ipynb:16` | [cell 4] A data-dependent transformer is fitted on the full dataset (line 121) before `train_test_split` (line 129). Statistics computed on the full dataset (mean, variance, …) leak test-set information into the training pipeline. | `le.fit(['DoS', 'Normal', 'Probe', 'R2L', 'U2R'])` |

### Fix proposals

- **`leakage.label-proxy-feature`** at `..\nids_pipeline_v2.ipynb`:1 (medium confidence) — Confirm whether `difficulty_level` is a label proxy — this is a name-match heuristic and may be a false positive. If it is a proxy, remove it from the feature list before training.
- **`leakage.preprocessing-before-split`** at `..\nids_pipeline_v2.ipynb`:16 (medium confidence) — Move all `fit` / `fit_transform` / `fit_resample` calls to after `train_test_split`. Apply `transform` (not `fit_transform`) to the test split.

## `supply_chain` — 3 finding(s)

_Tool status: `ok`. Duration: 1ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟡 medium | `supply_chain.unpinned-pip-install` | `..\nids_pipeline_v2.ipynb:3` | `!pip install imbalanced-learn` has no version pin (cell 2). Re-runs may install a different version and silently break the pipeline. | `!pip install imbalanced-learn -q` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_pipeline_v2.ipynb:1` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 2). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_pipeline_v2.ipynb:2` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 2). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt` |

### Fix proposals

- **`supply_chain.unpinned-pip-install`** at `..\nids_pipeline_v2.ipynb`:3 (high confidence) — Pin `imbalanced-learn` to a known-good version: `!pip install imbalanced-learn==X.Y.Z` and record it in requirements.txt / pyproject.toml.
- **`supply_chain.untrusted-wget-source`** at `..\nids_pipeline_v2.ipynb`:1 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.
- **`supply_chain.untrusted-wget-source`** at `..\nids_pipeline_v2.ipynb`:2 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.

## `adversarial` — 0 finding(s)

_Tool status: `ok`. Duration: 6024ms._

FGSM (Fast Gradient Sign Method) evasion at ε=0.05 against the two Keras
artifacts produced by the Colab run:

| Model | Confident probes | Flipped | Attack success | Finding? |
|---|---:|---:|---:|---|
| `nids_v2_cnn.keras` | 100 | 5 | **5.0 %** | No (threshold 50 %) |
| `nids_v2_lstm.keras` | 100 | 1 | **1.0 %** | No (threshold 50 %) |

Both models are **not** trivially evadable — small-norm FGSM perturbations
move predictions for only a tiny fraction of confident probes. This is an
honest result: it contradicts the "LSTM is trivially evadable" claim that
appeared in earlier portfolio drafts. That claim was speculation; this is
measurement. The portfolio README has been updated accordingly.

Probes were 100 uniform-random inputs in [0, 1] kept only if the model
emitted a confident prediction (max softmax > 0.5). For a stronger probe
distribution (real attack samples from `KDDTest+`) the result may differ —
that's a follow-up: feed `X_test_3d[y_test == attack]` instead of uniform
noise.

## `deserialization` — 0 finding(s)

_Tool status: `ok`. Duration: 329ms._

No issues found.

## `secrets` — 0 finding(s)

_Tool status: `ok`. Duration: 0ms._

No issues found.
