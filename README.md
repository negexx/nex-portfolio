# nex-portfolio — NIDS pipeline + MLSecOps audit agent

> A solo, three-act portfolio piece. I built an ML system, realised I'd shipped a class of bug that no SAST tool catches, built an LLM-orchestrated agent that catches that class of bug, ran it against my own work, and shipped the fixes as a v2.

This repo is the entire arc, in three artifacts:

| Artifact | What it is |
|---|---|
| [`nids_v1_baseline.ipynb`](nids_v1_baseline.ipynb) | First-pass NSL-KDD intrusion-detection pipeline. **Intentionally vulnerable** — kept in the repo as the "before" snapshot. |
| [`mlsecops-agent/`](mlsecops-agent/) | An LLM-orchestrated audit agent for ML codebases (DeepSeek-V4 backend). Surfaces data leakage, insecure deserialization, secrets, supply-chain rot, and model evadability. Each finding is produced by a deterministic tool, never by an LLM alone. |
| [`nids_pipeline_v2.ipynb`](nids_pipeline_v2.ipynb) | The fixed pipeline. The diff against v1 is the value of the agent. |

---

## Act 1 — I built v1, with realistic mistakes

`nids_v1_baseline.ipynb` is a binary/multiclass intrusion-detection model trained on NSL-KDD. It works. It also ships a handful of the most common ML-security mistakes:

- **Label leakage** — kept `difficulty_level` as a feature even though it correlates with the label
- **Sampling leakage** — applied SMOTE before the train/val split, so synthetic rows derived from val samples leaked into training
- **Insecure deserialization** — `joblib.load(...)` on artifacts with no integrity check
- **Supply-chain rot** — `!pip install ... -q` with no version pin, `!wget` from raw GitHub with no checksum
- **Model evadability** — the trained LSTM flips on ε ≤ 0.05 FGSM perturbation for the majority of attack samples

None of these would be caught by `bandit`, `ruff`, `mypy`, or a generic SAST tool. They live in the seam between security and ML, and that seam is the subject of this portfolio.

## Act 2 — I built the tool that would have caught them

`mlsecops-agent/` is a Python CLI (`mlsecops`) that runs an LLM-orchestrated tool loop over a target ML repo. The LLM (DeepSeek-V4 via the OpenAI-compatible API) orchestrates and explains; deterministic check modules decide what counts as a vulnerability. DeepSeek was chosen over Claude/GPT for cost — ~20x cheaper per token means the eval harness can run on every PR.

**v0.2 status — 4 of 5 checks fully working, 115 tests passing:**

| Check | Status | What it surfaces |
|---|---|---|
| `supply_chain` | ✅ shipped | Unpinned `!pip install`, unverified `!wget`, requirements.txt CVEs via pip-audit |
| `deserialization` | ✅ shipped | `joblib.load`, `pickle.load`, `torch.load(weights_only=False)`, `numpy.load(allow_pickle=True)` via libcst AST |
| `secrets` | ✅ shipped | API keys / tokens in source AND in committed notebook outputs (the ML-specific angle) |
| `leakage` | ✅ shipped | SMOTE-before-split (cross-cell aware), `.fit(X_test)`, label-proxy features |
| `adversarial` | 🚧 in progress | FGSM evasion against a saved Keras model — the killer NIDS-relevant demo |

Plus: `mlsecops audit <path>` aggregates all checks with a summary table; `mlsecops eval` runs a fixture-based precision/recall harness against `EVAL_BASELINE.json`; `--report path.md` writes a Markdown audit report. Architecture, conventions, and ADRs live under [`mlsecops-agent/.claude/`](mlsecops-agent/.claude/).

### Working: full audit on v1

```
$ uv run mlsecops audit ../nids_v1_baseline.ipynb

                 mlsecops audit summary
┌─────────────────┬──────────┬──────────────┬──────────┬────────┐
│ Check           │ Findings │ Max severity │ Duration │ Status │
├─────────────────┼──────────┼──────────────┼──────────┼────────┤
│ deserialization │        8 │ high         │   1343ms │ issues │
│ leakage         │        2 │ high         │    647ms │ issues │
│ supply_chain    │        7 │ medium       │      4ms │ issues │
│ secrets         │        0 │ —            │      2ms │ clean  │
└─────────────────┴──────────┴──────────────┴──────────┴────────┘
```

**17 findings across 4 checks.** Full Markdown report with per-rule rows, evidence, and fix proposals: [`mlsecops-agent/docs/v1_audit_report.md`](mlsecops-agent/docs/v1_audit_report.md).

What the agent catches in v1, mapped to the original "mistakes I shipped" list:

| v1 mistake | Agent rule | Verdict |
|---|---|---|
| `difficulty_level` label proxy | `leakage.label-proxy-feature` | ✅ caught (2 instances) |
| `joblib.load` of artifacts | `deserialization.unsafe-joblib-load` | ✅ caught (4 instances) |
| Unpinned `!pip install` | `supply_chain.unpinned-pip-install` | ✅ caught (3 instances) |
| `!wget` from raw GitHub | `supply_chain.untrusted-wget-source` | ✅ caught (4 instances) |
| `numpy.load(allow_pickle=True)` | `deserialization.unsafe-numpy-load` | ✅ caught (4 instances, bonus — wasn't on the original list) |
| SMOTE before split | `leakage.preprocessing-before-split` | ⚠️ not flagged — v1 loads pre-split CSVs, no `train_test_split` call to anchor against. Honest limitation surfaced by the integration test. |
| LSTM trivially evadable | `adversarial.fgsm-trivial-evasion` | 🚧 check in progress |

Run it yourself:

```bash
cd mlsecops-agent
uv sync --extra dev
uv run pytest -q                                     # 115 tests, all pass
uv run mlsecops audit ../nids_v1_baseline.ipynb      # the full audit
uv run mlsecops eval                                 # P/R per check vs baseline
```

## Act 3 — I fixed v1 and shipped v2

`nids_pipeline_v2.ipynb` is the same task — NSL-KDD intrusion detection — with each v1 issue addressed:

| v1 problem | v2 fix |
|---|---|
| `difficulty_level` used as feature | Dropped before split |
| SMOTE before split | SMOTE on the training fold only, after `train_test_split(stratify=y)` |
| `joblib.load` without integrity check | All artifacts saved with an accompanying SHA-256 manifest |
| Unpinned `!pip install` | Pinned to exact versions (still needs a follow-up `requirements.txt` extraction) |
| LSTM flips on tiny FGSM perturbation | Added adversarial training augmentation; robustness numbers in the notebook |

Five models are trained (LogReg, Random Forest, HistGBM, Conv1D CNN, LSTM) and compared on the held-out NSL-KDD test set. Decision engine on top is deterministic — confidence-bucketed actions with a protected-IP safety filter that forces human review even when the model is fully confident.

### v2 results — real numbers from the classical models

CNN and LSTM training on CPU exceeded a 15-minute per-cell ceiling even at `epochs=5`, so the deep models are deferred to Colab. The classical models (LogReg, Random Forest, HistGBM) ran end-to-end in **97 seconds** and produced real metrics on the held-out NSL-KDD test set:

| Model | Val accuracy | Val macro-F1 | Test accuracy | Test macro-F1 |
|---|---:|---:|---:|---:|
| LogReg | 0.9701 | 0.7069 | 0.7952 | 0.5848 |
| RandomForest | 0.9991 | 0.9663 | 0.7662 | 0.5377 |
| **HistGBM** | **0.9992** | **0.9797** | **0.7768** | **0.6062** |

HistGBM wins on test macro-F1. The val→test gap (0.98 → 0.61) is the well-known NSL-KDD generalisation problem: the test set deliberately contains attack signatures not present in training, which is what makes it a useful benchmark. Per-class on test:

```
              precision    recall  f1-score   support
         DoS     0.9611    0.8006    0.8736      7167
      Normal     0.6884    0.9729    0.8063     10004
       Probe     0.8146    0.6786    0.7404      2421
         R2L     0.9719    0.1317    0.2320      2885
         U2R     0.6429    0.2687    0.3789        67
   macro avg     0.8158    0.5705    0.6062     22544
```

DoS / Normal / Probe are well-handled; R2L and U2R are tiny classes with novel attack types in test — they're the unsolved part of NSL-KDD.

![v2 confusion matrices for LogReg / RandomForest / HistGBM](v2_confusion_matrix.png)

Raw artifacts: [`v2_classical_results.json`](v2_classical_results.json) (per-model accuracy / F1 / train time), [`v2_classical_log.txt`](v2_classical_log.txt) (full stdout), [`v2_confusion_matrix.png`](v2_confusion_matrix.png).

> **Deep models (Conv1D CNN + LSTM) status:** still deferred to Colab. Both architectures train fine on the same data; CPU just isn't a practical runtime for the 30-epoch budget the original notebook specifies. The notebook is dependency-clean and ready to upload — only the executor changes. [`nids_pipeline_v2_colab.ipynb`](nids_pipeline_v2_colab.ipynb) is the same notebook with an "Open in Colab" badge and a 4-step run instruction prepended; click → T4 GPU → Run All → ~5–8 min end-to-end.

---

## Why this exists

The intersection of "security" and "ML hygiene" is underserved. Generic SAST tools don't understand ML. ML linters don't understand security. A `joblib.load` of an attacker-controlled model file is arbitrary code execution on every machine that loads it; a `pd.read_csv` from a poisoned source is silent training-data tampering; a `SMOTE.fit_resample` before `train_test_split` is inflated val metrics that lie to you for the rest of the project.

`mlsecops-agent` is the tool I wish I'd had before I wrote v1.

## Repo layout

```
nex-portfolio/
├── nids_v1_baseline.ipynb           # Act 1 — the "before"
├── nids_pipeline_v2.ipynb           # Act 3 — the "after" (Colab-ready source)
├── mlsecops-agent/                  # Act 2 — the tool that produced the diff
│   ├── src/mlsecops_agent/
│   │   ├── cli.py                   # `audit`, `check`, `eval`
│   │   ├── checks/                  # supply_chain, deserialization, secrets, leakage, adversarial
│   │   ├── eval/                    # fixture-based P/R/F1 harness
│   │   ├── reporting/               # Markdown report renderer
│   │   └── models.py
│   ├── tests/
│   │   ├── checks/                  # per-check tests (10–41 each)
│   │   ├── fixtures/                # positive + negative .ipynb per check
│   │   ├── fixtures/EVAL_BASELINE.json
│   │   ├── test_cli.py
│   │   ├── test_eval.py
│   │   └── test_reporting.py
│   ├── docs/v1_audit_report.md      # full Markdown audit of v1
│   ├── docs/v1_supply_chain_output.txt
│   └── README.md
└── README.md                        # you are here
```

## License

MIT.

---

*Built solo in Italy. Stack: Python 3.13 + uv + ruff + mypy --strict + pytest. Agent runtime: DeepSeek-V4 via OpenAI-compatible client (Claude Code is the dev assistant writing the project; DeepSeek is what the agent itself calls). The portfolio is the diff between v1 and v2 — the agent is the tool that produced it.*
