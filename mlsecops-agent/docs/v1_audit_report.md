# mlsecops audit report

- **Target:** `..\nids_v1_baseline.ipynb`
- **Generated:** 2026-05-26 01:21:57 UTC
- **Total findings:** 17
- **Exit status:** ❌ blocking (HIGH/CRITICAL present)

## Summary

| Check | Findings | Max severity | Duration | Status |
|---|---:|---|---:|---|
| `deserialization` | 8 | 🟠 high | 1006ms | issues |
| `leakage` | 2 | 🟠 high | 4010ms | issues |
| `supply_chain` | 7 | 🟡 medium | 3ms | issues |
| `adversarial` | 0 | — | 0ms | clean |
| `secrets` | 0 | — | 1ms | clean |

## `deserialization` — 8 finding(s)

_Tool status: `ok`. Duration: 1006ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟠 high | `deserialization.unsafe-joblib-load` | `..\nids_v1_baseline.ipynb:573` | `joblib.load` uses pickle internally and will execute arbitrary code when loading a maliciously crafted file. Replace with a safe format (e.g. safetensors, JSON, ONNX) or verify the file's integrity with a cryptographic hash before loading. | `joblib.load('label_encoder.pkl')` |
| 🟠 high | `deserialization.unsafe-joblib-load` | `..\nids_v1_baseline.ipynb:589` | `joblib.load` uses pickle internally and will execute arbitrary code when loading a maliciously crafted file. Replace with a safe format (e.g. safetensors, JSON, ONNX) or verify the file's integrity with a cryptographic hash before loading. | `joblib.load('label_encoder.pkl')` |
| 🟠 high | `deserialization.unsafe-joblib-load` | `..\nids_v1_baseline.ipynb:894` | `joblib.load` uses pickle internally and will execute arbitrary code when loading a maliciously crafted file. Replace with a safe format (e.g. safetensors, JSON, ONNX) or verify the file's integrity with a cryptographic hash before loading. | `joblib.load('label_encoder.pkl')` |
| 🟠 high | `deserialization.unsafe-joblib-load` | `..\nids_v1_baseline.ipynb:908` | `joblib.load` uses pickle internally and will execute arbitrary code when loading a maliciously crafted file. Replace with a safe format (e.g. safetensors, JSON, ONNX) or verify the file's integrity with a cryptographic hash before loading. | `joblib.load('label_encoder.pkl')` |
| 🟡 medium | `deserialization.unsafe-numpy-load` | `..\nids_v1_baseline.ipynb:572` | `numpy.load(..., allow_pickle=True)` enables pickle deserialisation in numpy arrays. The default is `False` for this reason. Save arrays in a non-pickle format (`.npy` without object arrays, `.npz`, or HDF5) so `allow_pickle` is not needed. | `np.load('feature_cols.npy', allow_pickle=True)` |
| 🟡 medium | `deserialization.unsafe-numpy-load` | `..\nids_v1_baseline.ipynb:588` | `numpy.load(..., allow_pickle=True)` enables pickle deserialisation in numpy arrays. The default is `False` for this reason. Save arrays in a non-pickle format (`.npy` without object arrays, `.npz`, or HDF5) so `allow_pickle` is not needed. | `np.load('feature_cols.npy', allow_pickle=True)` |
| 🟡 medium | `deserialization.unsafe-numpy-load` | `..\nids_v1_baseline.ipynb:893` | `numpy.load(..., allow_pickle=True)` enables pickle deserialisation in numpy arrays. The default is `False` for this reason. Save arrays in a non-pickle format (`.npy` without object arrays, `.npz`, or HDF5) so `allow_pickle` is not needed. | `np.load('feature_cols.npy', allow_pickle=True)` |
| 🟡 medium | `deserialization.unsafe-numpy-load` | `..\nids_v1_baseline.ipynb:907` | `numpy.load(..., allow_pickle=True)` enables pickle deserialisation in numpy arrays. The default is `False` for this reason. Save arrays in a non-pickle format (`.npy` without object arrays, `.npz`, or HDF5) so `allow_pickle` is not needed. | `np.load('feature_cols.npy', allow_pickle=True)` |

### Fix proposals

- **`deserialization.unsafe-joblib-load`** at `..\nids_v1_baseline.ipynb`:573 (high confidence) — Replace `joblib.load` with a safe serialisation format such as `safetensors` or save/load model weights to JSON/ONNX. If you must use joblib, pin the exact file hash in your pipeline and verify it before `load`.
- **`deserialization.unsafe-joblib-load`** at `..\nids_v1_baseline.ipynb`:589 (high confidence) — Replace `joblib.load` with a safe serialisation format such as `safetensors` or save/load model weights to JSON/ONNX. If you must use joblib, pin the exact file hash in your pipeline and verify it before `load`.
- **`deserialization.unsafe-joblib-load`** at `..\nids_v1_baseline.ipynb`:894 (high confidence) — Replace `joblib.load` with a safe serialisation format such as `safetensors` or save/load model weights to JSON/ONNX. If you must use joblib, pin the exact file hash in your pipeline and verify it before `load`.
- **`deserialization.unsafe-joblib-load`** at `..\nids_v1_baseline.ipynb`:908 (high confidence) — Replace `joblib.load` with a safe serialisation format such as `safetensors` or save/load model weights to JSON/ONNX. If you must use joblib, pin the exact file hash in your pipeline and verify it before `load`.
- **`deserialization.unsafe-numpy-load`** at `..\nids_v1_baseline.ipynb`:572 (high confidence) — Remove `allow_pickle=True` and resave the array without object dtype. If the array contains objects you control, switch to a typed format or use `numpy.savez` with a schema you verify.
- **`deserialization.unsafe-numpy-load`** at `..\nids_v1_baseline.ipynb`:588 (high confidence) — Remove `allow_pickle=True` and resave the array without object dtype. If the array contains objects you control, switch to a typed format or use `numpy.savez` with a schema you verify.
- **`deserialization.unsafe-numpy-load`** at `..\nids_v1_baseline.ipynb`:893 (high confidence) — Remove `allow_pickle=True` and resave the array without object dtype. If the array contains objects you control, switch to a typed format or use `numpy.savez` with a schema you verify.
- **`deserialization.unsafe-numpy-load`** at `..\nids_v1_baseline.ipynb`:907 (high confidence) — Remove `allow_pickle=True` and resave the array without object dtype. If the array contains objects you control, switch to a typed format or use `numpy.savez` with a schema you verify.

## `leakage` — 2 finding(s)

_Tool status: `ok`. Duration: 4010ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟠 high | `leakage.label-proxy-feature` | `..\nids_v1_baseline.ipynb:1` | [cell 2] Column `difficulty_level` in an assignment matches a label-proxy pattern. If this column encodes the target (directly or indirectly) and is included in the feature set, the model will have access to the answer at inference time. | `[     'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',     'wrong_fragment','urgent','hot','num_failed_logins','logged_in',     'num_compromised','root_shell','su_attempted'` |
| 🟠 high | `leakage.label-proxy-feature` | `..\nids_v1_baseline.ipynb:13` | [cell 13] Column `difficulty_level` in an assignment matches a label-proxy pattern. If this column encodes the target (directly or indirectly) and is included in the feature set, the model will have access to the answer at inference time. | `[     'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',     'wrong_fragment','urgent','hot','num_failed_logins','logged_in',     'num_compromised','root_shell','su_attempted'` |

### Fix proposals

- **`leakage.label-proxy-feature`** at `..\nids_v1_baseline.ipynb`:1 (medium confidence) — Confirm whether `difficulty_level` is a label proxy — this is a name-match heuristic and may be a false positive. If it is a proxy, remove it from the feature list before training.
- **`leakage.label-proxy-feature`** at `..\nids_v1_baseline.ipynb`:13 (medium confidence) — Confirm whether `difficulty_level` is a label proxy — this is a name-match heuristic and may be a false positive. If it is a proxy, remove it from the feature list before training.

## `supply_chain` — 7 finding(s)

_Tool status: `ok`. Duration: 3ms._

| Severity | Rule | Location | Message | Evidence |
|---|---|---|---|---|
| 🟡 medium | `supply_chain.unpinned-pip-install` | `..\nids_v1_baseline.ipynb:1` | `!pip install openai` has no version pin (cell 28). Re-runs may install a different version and silently break the pipeline. | `!pip install openai -q` |
| 🟡 medium | `supply_chain.unpinned-pip-install` | `..\nids_v1_baseline.ipynb:3` | `!pip install imbalanced-learn` has no version pin (cell 1). Re-runs may install a different version and silently break the pipeline. | `!pip install imbalanced-learn -q` |
| 🟡 medium | `supply_chain.unpinned-pip-install` | `..\nids_v1_baseline.ipynb:4` | `!pip install imbalanced-learn` has no version pin (cell 13). Re-runs may install a different version and silently break the pipeline. | `!pip install imbalanced-learn -q` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_v1_baseline.ipynb:1` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 1). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_v1_baseline.ipynb:2` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 1). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_v1_baseline.ipynb:2` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 13). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt` |
| 🟡 medium | `supply_chain.untrusted-wget-source` | `..\nids_v1_baseline.ipynb:3` | `!wget` downloads content with no checksum verification anywhere in the notebook (cell 13). If the upstream source changes, your pipeline runs on different bytes. | `!wget -q https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt` |

### Fix proposals

- **`supply_chain.unpinned-pip-install`** at `..\nids_v1_baseline.ipynb`:1 (high confidence) — Pin `openai` to a known-good version: `!pip install openai==X.Y.Z` and record it in requirements.txt / pyproject.toml.
- **`supply_chain.unpinned-pip-install`** at `..\nids_v1_baseline.ipynb`:3 (high confidence) — Pin `imbalanced-learn` to a known-good version: `!pip install imbalanced-learn==X.Y.Z` and record it in requirements.txt / pyproject.toml.
- **`supply_chain.unpinned-pip-install`** at `..\nids_v1_baseline.ipynb`:4 (high confidence) — Pin `imbalanced-learn` to a known-good version: `!pip install imbalanced-learn==X.Y.Z` and record it in requirements.txt / pyproject.toml.
- **`supply_chain.untrusted-wget-source`** at `..\nids_v1_baseline.ipynb`:1 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.
- **`supply_chain.untrusted-wget-source`** at `..\nids_v1_baseline.ipynb`:2 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.
- **`supply_chain.untrusted-wget-source`** at `..\nids_v1_baseline.ipynb`:2 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.
- **`supply_chain.untrusted-wget-source`** at `..\nids_v1_baseline.ipynb`:3 (medium confidence) — After the `wget`, verify the file: `!sha256sum <file>` and assert against an expected digest.

## `adversarial` — 0 finding(s)

_Tool status: `ok`. Duration: 0ms._

No issues found.

## `secrets` — 0 finding(s)

_Tool status: `ok`. Duration: 1ms._

No issues found.
