# mlsecops-agent

A Claude-driven audit agent for ML codebases. Finds the mistakes a generic SAST tool can't (data leakage, model evadability) and the security mistakes specific to ML repos that Cursor doesn't know about (insecure pickle loading, secrets in notebook outputs, unpinned `!pip install`).

> **Status:** v0.1 in development. The scaffold is in place; check implementations land over the next ~3 weeks.

## What it does

Five checks, two pillars:

| # | Check | Pillar | Backed by |
|---|-------|--------|-----------|
| 1 | `leakage` | ML hygiene | Custom AST + libcst |
| 2 | `deserialization` | Security | `bandit` + custom rules |
| 3 | `secrets` | Security | `detect-secrets` + `trufflehog` + `nbformat` |
| 4 | `supply_chain` | Security | `pip-audit` + `safety` |
| 5 | `adversarial` | Security + ML | IBM `adversarial-robustness-toolbox` |

Every finding is produced by a deterministic tool. The agent orchestrates: route → run → interpret → propose fix → verify. The LLM never *decides* what is vulnerable.

## Quick start

```bash
# Install
uv sync

# Configure
cp .env.example .env.local
$EDITOR .env.local  # add ANTHROPIC_API_KEY at minimum

# Audit a target repo
uv run mlsecops audit /path/to/repo

# Run a single check
uv run mlsecops check leakage /path/to/notebook.ipynb

# Run the eval harness against fixtures
uv run mlsecops eval
```

## Example: auditing a sibling project

This repo lives alongside an NSL-KDD NIDS notebook (`../Untitled9.ipynb`) that was built with realistic ML-hygiene and security mistakes. The agent's eval baseline includes this notebook as a fixture; expected findings:

- `leakage.label-proxy-feature` — `difficulty_level` kept as a feature
- `leakage.preprocessing-before-split` — SMOTE applied before train/val split
- `deserialization.untrusted-joblib-load` — `joblib.load(...)` of artifacts with no integrity check
- `supply_chain.unpinned-pip-install` — `!pip install imbalanced-learn -q` (no version)
- `supply_chain.untrusted-wget-source` — `!wget` from raw GitHub with no checksum
- `adversarial.fgsm-trivial-evasion` — trained LSTM flipped by ε ≤ 0.05 perturbation on ≥ 80% of attack samples

The fixed version (`../nids_pipeline_v2.ipynb`) is the negative control: the agent should *not* flag the same issues.

## Architecture

See `.claude/docs/architecture.md` for the full map. One-paragraph summary:

CLI (Typer) → Agent loop (Claude Agent SDK) → Check modules (deterministic) → Tool wrappers (bandit, pip-audit, ART, etc.) → SQLite for run history + Langfuse for tracing. Target ML code runs inside a sandbox (Vercel Sandbox or e2b), never in the agent's host process.

## Why this project exists

Generic SAST tools don't understand ML. ML linters don't understand security. The intersection is underserved and the cost of being wrong is real:

- A `joblib.load` of a malicious model file = arbitrary code execution on every machine that loads it.
- A `pd.read_csv(...)` from a poisoned source = silent training-data tampering.
- A `SMOTE.fit_resample(X, y)` before `train_test_split` = inflated val metrics that lie to you for the rest of the project.

This agent is the tool that would have caught those issues earlier — including in the author's own sibling NIDS notebook.

## Project layout

```
mlsecops-agent/
├── .claude/                       # AI workspace (Claude Code)
├── src/mlsecops_agent/
│   ├── cli.py                     # Typer entry point
│   ├── agent.py                   # Claude Agent SDK loop
│   ├── checks/                    # 5 MVP checks
│   ├── tools/                     # External CLI wrappers
│   ├── storage/                   # SQLite repository
│   ├── reporting/                 # Markdown + JSON renderers
│   ├── sandbox.py                 # Sandbox client
│   ├── models.py                  # Pydantic types
│   └── prompts/                   # System + per-check prompts
├── tests/
│   ├── checks/                    # Per-check unit tests
│   └── fixtures/                  # Positive + negative scenarios
├── pyproject.toml                 # uv-managed, Python 3.13
└── README.md
```

## License

MIT.
