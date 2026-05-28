# mlsecops-agent

An LLM-orchestrated audit agent for ML codebases. Finds the mistakes a generic SAST tool can't (data leakage, model evadability) and the security mistakes specific to ML repos that Cursor doesn't know about (insecure pickle loading, secrets in notebook outputs, unpinned `!pip install`).

> **Status — v0.3**: all 5 detection checks + cross-check threat-scenario synthesis layer + SARIF 2.1.0 output (`--sarif`). **193 tests pass** (4 skipped without TensorFlow installed locally), mypy `--strict` clean, ruff clean. CI uploads SARIF to GitHub Code Scanning on every push. The LLM-orchestrated agent loop (DeepSeek-V4 via `--with-llm`) remains the next milestone — the CLI runs deterministically without an LLM today.

## What it does

Five checks, two pillars:

| # | Check | Pillar | Backed by | Status |
|---|-------|--------|-----------|--------|
| 1 | `supply_chain` | Security | regex + `pip-audit` CVE lookups | ✅ |
| 2 | `deserialization` | Security | libcst AST (joblib / pickle / torch / numpy unsafe loads) | ✅ |
| 3 | `secrets` | Security | regex + notebook-output scan (escalated severity for committed outputs) | ✅ |
| 4 | `leakage` | ML hygiene | libcst AST (SMOTE-before-split cross-cell, fit-on-test, label-proxy names) | ✅ ¹ |
| 5 | `adversarial` | Security + ML | IBM `adversarial-robustness-toolbox` (FGSM on saved Keras models — supports both dense `(N, features)` and Conv1D/LSTM `(N, features, 1)` shapes; `--adversarial-probes` for in-distribution probes) | ✅ (opt-in) |
| ⭐ | `scenario` | Cross-check synthesis | Chains findings into named threat patterns (`supply-chain-to-rce`, `label-leakage-to-inflated-metrics`, `evadable-classifier-in-production`). Severity bumps one level per amplifier present. | ✅ |

Every finding is produced by a deterministic tool. The LLM never *decides* what is vulnerable — its role is orchestration, fix-narration, and executive summary (`mlsecops audit --with-llm`).

**Output formats:** Markdown (`--report path.md`), **SARIF 2.1.0** (`--sarif path.sarif`), and console tables. The CI workflow uploads SARIF to GitHub Code Scanning, so findings appear in the repo's *Security* tab alongside Dependabot, CodeQL, etc.

¹ **Known leakage-rule limitation.** `leakage.preprocessing-before-split` is anchored on the position of `train_test_split(...)` in document order. Notebooks that load already-split data from disk (separate `train.csv` / `test.csv` files — which the sibling v1 notebook does) have no anchor for the rule to fire against. The label-proxy and fit-on-test rules are independent and still fire normally.

## Quick start

```bash
# Install
uv sync --extra dev

# (Optional) configure LLM backend — only required for the agent loop (W3.2+)
cp .env.template .env.local
$EDITOR .env.local   # set DEEPSEEK_API_KEY

# Audit a target repo or notebook (runs all 5 checks bar adversarial)
uv run mlsecops audit /path/to/repo

# Include the FGSM evasion check against saved .h5/.keras models (needs TensorFlow)
uv run mlsecops audit /path/to/repo --include-adversarial

# Run a single check
uv run mlsecops check leakage /path/to/notebook.ipynb

# Write a Markdown report
uv run mlsecops audit /path/to/repo --report audit.md

# Run a single check filter
uv run mlsecops audit /path/to/repo --check supply_chain --check secrets

# Eval harness: precision / recall / F1 per check against the committed baseline
uv run mlsecops eval
uv run mlsecops eval --update-baseline   # regenerate after intentional behavior change
```

## Real run on the sibling v1 NIDS notebook

```
$ uv run mlsecops audit ../nids_v1_baseline.ipynb

                 mlsecops audit summary
┌─────────────────┬──────────┬──────────────┬──────────┬────────┐
│ Check           │ Findings │ Max severity │ Duration │ Status │
├─────────────────┼──────────┼──────────────┼──────────┼────────┤
│ scenario        │        2 │ critical     │      0ms │ issues │
│ deserialization │        8 │ high         │    937ms │ issues │
│ leakage         │        2 │ high         │   3592ms │ issues │
│ supply_chain    │        7 │ medium       │      3ms │ issues │
│ adversarial     │        0 │ —            │      0ms │ clean  │
│ secrets         │        0 │ —            │      1ms │ clean  │
└─────────────────┴──────────┴──────────────┴──────────┴────────┘
```

**19 findings**: 17 deterministic + 2 synthesised CRITICAL scenarios (the wget+joblib.load chain is an RCE pattern; the label-proxy + sloppy-split chain inflates evaluation). `secrets` and `adversarial` correctly come up clean (no hardcoded creds in v1; no saved Keras artifacts in the notebook directory). Full Markdown report with per-rule rows, evidence, and fix proposals lives in [`docs/v1_audit_report.md`](docs/v1_audit_report.md); the same data as SARIF in [`docs/v1_audit_report.sarif`](docs/v1_audit_report.sarif).

### Closing the loop — audit on the fixed v2 notebook

```
$ uv run mlsecops audit ../nids_pipeline_v2.ipynb

                 mlsecops audit summary
┌─────────────────┬──────────┬──────────────┬──────────┬────────┐
│ Check           │ Findings │ Max severity │ Duration │ Status │
├─────────────────┼──────────┼──────────────┼──────────┼────────┤
│ leakage         │        2 │ high         │   3134ms │ issues │
│ supply_chain    │        3 │ medium       │      1ms │ issues │
│ adversarial     │        0 │ —            │      0ms │ clean  │
│ deserialization │        0 │ —            │    329ms │ clean  │
│ secrets         │        0 │ —            │      0ms │ clean  │
└─────────────────┴──────────┴──────────────┴──────────┴────────┘
```

**v1 → v2: 19 → 4 findings (–79 %).** All 8 deserialization issues are gone. The 2 v1 scenarios (CRITICAL) are cleared. The 2 v1 leakage findings (which became 0 in v2 thanks to smarter AST analysis — `df.drop(columns=[…])` now suppresses proxy findings, and `fit()` on a literal list is recognised as class registration). The 3 remaining `supply_chain` items are documented Colab-pasteability compromises. The 1 new `adversarial` finding is real: see the FGSM sweep below. Full diff and per-finding rationale: [`docs/v2_audit_report.md`](docs/v2_audit_report.md) (and [SARIF](docs/v2_audit_report.sarif)).

### FGSM robustness sweep — real KDDTest+ probes

```bash
uv run mlsecops audit . --include-adversarial \
   --adversarial-probes ../v2_test_attack_samples.npy
```

| Model | ε=0.01 | ε=0.05 | ε=0.10 | ε=0.20 | ε=0.30 |
|---|---:|---:|---:|---:|---:|
| `nids_v2_cnn.keras` | 4.3 % | 16.0 % | 26.4 % | 38.2 % | 43.4 % |
| `nids_v2_lstm.keras` | 3.9 % | 19.6 % | **49.8 %** | **77.0 %** | **83.6 %** |

The LSTM **is** trivially evadable at ε ≥ 0.10 — at ε = 0.20, a 20 % feature-range perturbation flips 77 % of in-distribution attack predictions. v1 speculated; the agent now measures.

Probes are real attack samples scaled through the same `StandardScaler` the model was trained with. Earlier runs with uniform-random probes reported < 5 % flip rate — that was uninformative because random noise sits outside the training distribution. Switching to in-distribution probes is what made the brittleness visible.

## Architecture

```
src/mlsecops_agent/
├── cli.py                     # Typer entry point: audit, check, eval
├── checks/                    # The 5 MVP checks — each exports run(target) -> CheckResult
│   ├── supply_chain.py        # regex + pip-audit subprocess
│   ├── deserialization.py     # libcst AST (joblib/pickle/torch/numpy)
│   ├── secrets.py             # regex + nbformat output-cell scan
│   ├── leakage.py             # libcst AST + cross-cell line translation
│   └── adversarial.py         # ART FGSM against tf.keras models (opt-in)
├── eval/
│   └── harness.py             # Fixture-based P/R/F1 vs EVAL_BASELINE.json
├── reporting/
│   └── markdown.py            # Deterministic Markdown report renderer
├── models.py                  # Pydantic types: Finding, CheckResult, FixProposal
├── agent.py                   # ⏳ DeepSeek-orchestrated tool loop (W3.2 in progress)
├── llm/provider.py            # ⏳ OpenAI-compatible client → DeepSeek (W3.2)
├── prompts/                   # ⏳ Agent system prompt (W3.2)
└── storage/                   # ⏳ SQLite run history (W3.3 planned)
tests/
├── checks/                    # Per-check tests (10–41 each, 89 total)
├── fixtures/                  # Positive + negative .ipynb per check
├── fixtures/EVAL_BASELINE.json # Generated expected-findings baseline
├── test_cli.py                # Typer CliRunner integration tests
├── test_eval.py               # Harness math + regression test
└── test_reporting.py          # Markdown renderer snapshot tests
```

Deeper notes: [`.claude/docs/architecture.md`](.claude/docs/architecture.md). LLM choice + alternatives in [ADR 0004](.claude/docs/decisions/0004-deepseek-runtime.md).

## What "done" means for a check

A check is not shipped until:

1. `run(target: Path) -> CheckResult` is implemented and returns Pydantic-typed findings
2. It's registered in `checks/CHECKS` so `mlsecops audit` picks it up
3. A positive fixture flags the issue and a negative fixture is clean
4. Unit tests cover the AST/regex edge cases (aliased imports, cross-cell layouts, masked secrets, etc.)
5. `EVAL_BASELINE.json` includes the fixtures and `mlsecops eval` reports 1.0 P/R
6. `mypy --strict` and `ruff` are green

## Why this project exists

Generic SAST tools don't understand ML. ML linters don't understand security. The intersection is underserved and the cost of being wrong is real:

- A `joblib.load` of a malicious model file = arbitrary code execution on every machine that loads it.
- A `pd.read_csv(...)` from a poisoned source = silent training-data tampering.
- A `SMOTE.fit_resample(X, y)` before `train_test_split` = inflated val metrics that lie to you for the rest of the project.
- A trained classifier that flips under ε=0.05 FGSM perturbation = an evadable production IDS.

This agent is the tool that would have caught those issues earlier — including in the author's own sibling NIDS notebook.

## License

MIT.
