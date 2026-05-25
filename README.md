# nex-portfolio — NIDS pipeline + MLSecOps audit agent

> A solo, three-act portfolio piece. I built an ML system, realised I'd shipped a class of bug that no SAST tool catches, built a Claude-driven agent that catches that class of bug, ran it against my own work, and shipped the fixes as a v2.

This repo is the entire arc, in three artifacts:

| Artifact | What it is |
|---|---|
| [`nids_v1_baseline.ipynb`](nids_v1_baseline.ipynb) | First-pass NSL-KDD intrusion-detection pipeline. **Intentionally vulnerable** — kept in the repo as the "before" snapshot. |
| [`mlsecops-agent/`](mlsecops-agent/) | A Claude-driven audit agent for ML codebases. Surfaces data leakage, insecure deserialization, secrets, supply-chain rot, and model evadability. Each finding is produced by a deterministic tool, never by an LLM alone. |
| [`nids_pipeline_v2.ipynb`](nids_pipeline_v2.ipynb) | The fixed pipeline. The diff against v1 is the value of the agent. |

---

## Act 1 — I built v1, with realistic mistakes

`nids_v1_baseline.ipynb` is a binary/multiclass intrusion-detection model trained on NSL-KDD. It works. It also ships a handful of the most common ML-security mistakes:

- **Label leakage** — kept `difficulty_level` as a feature even though it correlates with the label
- **Sampling leakage** — applied SMOTE before the train/val split, so synthetic rows derived from val samples leaked into training
- **Insecure deserialization** — `joblib.load(...)` on artifacts with no integrity check
- **Supply-chain rot** — `!pip install ... -q` with no version pin, `!wget` from raw GitHub with no checksum
- **Model evadability** — the trained LSTM flips on ε ≤ 0.05 FGSM perturbation for the majority of attack samples

None of these would be caught by `bandit`, `ruff`, `mypy`, or a generic SAST tool. They live in the seam between security and ML, and they are the seam this portfolio is about.

## Act 2 — I built the tool that would have caught them

`mlsecops-agent/` is a Python CLI (`mlsecops`) that runs a Claude Agent SDK loop over a target ML repo. It dispatches to deterministic check modules — the LLM orchestrates and explains, but never decides what counts as a vulnerability.

**v0.1 status:** the `supply_chain` check is fully implemented end-to-end (detection, CLI, fixtures, tests). The remaining four checks (`leakage`, `deserialization`, `secrets`, `adversarial`) are scaffolded with the same shape and land next. Architecture, conventions, and ADRs live under [`mlsecops-agent/.claude/`](mlsecops-agent/.claude/).

### Working: `supply_chain` check on v1

```
$ uv run mlsecops check supply_chain ../nids_v1_baseline.ipynb

                supply_chain - 7 finding(s) in 3ms
┌────────┬───────────────────────────────────┬─────────────────────────────┐
│ Sev    │ Rule                              │ Location                    │
├────────┼───────────────────────────────────┼─────────────────────────────┤
│ medium │ supply_chain.unpinned-pip-install │ nids_v1_baseline.ipynb:3    │  # imbalanced-learn
│ medium │ supply_chain.unpinned-pip-install │ nids_v1_baseline.ipynb:4    │  # imbalanced-learn
│ medium │ supply_chain.unpinned-pip-install │ nids_v1_baseline.ipynb:1    │  # openai
│ medium │ supply_chain.untrusted-wget-source│ nids_v1_baseline.ipynb:1    │  # KDDTrain+.txt
│ medium │ supply_chain.untrusted-wget-source│ nids_v1_baseline.ipynb:2    │  # KDDTest+.txt
│ medium │ supply_chain.untrusted-wget-source│ nids_v1_baseline.ipynb:2    │  # KDDTrain+.txt
│ medium │ supply_chain.untrusted-wget-source│ nids_v1_baseline.ipynb:3    │  # KDDTest+.txt
└────────┴───────────────────────────────────┴─────────────────────────────┘
```

Three unpinned installs, four downloads with no checksum. Full table with fix proposals: [`mlsecops-agent/docs/v1_supply_chain_output.txt`](mlsecops-agent/docs/v1_supply_chain_output.txt).

The check is real code, not a stub:

```bash
cd mlsecops-agent
uv sync --extra dev
uv run pytest tests/checks/test_supply_chain.py -v   # 10 tests, all pass
uv run mlsecops check supply_chain ../nids_v1_baseline.ipynb
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

> **Status of v2 numbers in this README:** the notebook is fully written and dependency-clean. End-to-end execution is a ~30-min job (TensorFlow CNN + LSTM, 30 epochs each) that lives in Colab for now; an executed copy with real macro-F1 and confusion-matrix PNGs is committed as [`.v2_run/nids_pipeline_v2.executed.ipynb`](.v2_run/nids_pipeline_v2.executed.ipynb) when the run finishes locally.

---

## Why this exists

The intersection of "security" and "ML hygiene" is underserved. Generic SAST tools don't understand ML. ML linters don't understand security. A `joblib.load` of an attacker-controlled model file is arbitrary code execution on every machine that loads it; a `pd.read_csv` from a poisoned source is silent training-data tampering; a `SMOTE.fit_resample` before `train_test_split` is inflated val metrics that lie to you for the rest of the project.

`mlsecops-agent` is the tool I wish I'd had before I wrote v1.

## Repo layout

```
nex-portfolio/
├── nids_v1_baseline.ipynb        # Act 1 — the "before"
├── nids_pipeline_v2.ipynb        # Act 3 — the "after"
├── mlsecops-agent/               # Act 2 — the tool that produced the diff
│   ├── src/mlsecops_agent/
│   │   ├── cli.py                # `mlsecops check supply_chain <path>`
│   │   ├── checks/supply_chain.py
│   │   └── models.py
│   ├── tests/
│   │   ├── checks/test_supply_chain.py
│   │   └── fixtures/supply_chain/{positive,negative}_*.ipynb
│   ├── docs/v1_supply_chain_output.txt
│   └── README.md
└── README.md                     # you are here
```

## License

MIT.

---

*Built solo in Italy. Stack: Python 3.13 + uv + ruff + mypy --strict + pytest. Agent runtime: Claude Agent SDK. The portfolio is the diff between v1 and v2 — the agent is the tool that produced it.*
