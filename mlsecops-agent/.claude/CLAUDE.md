# mlsecops-agent

> Project memory for Claude Code. Loaded automatically into every session.
> Keep this file under ~200 lines — it's always in context.

## What this project is

An MLSecOps audit agent for ML codebases (Python notebooks + scripts). It runs a Claude-driven tool loop that audits a target repo for **two pillars**:

1. **ML hygiene** — data leakage, train/test contamination, missing baselines, class-imbalance handling
2. **Security** — insecure deserialization (`pickle`/`joblib`/`torch.load`), secrets in notebooks, supply-chain CVEs, adversarial robustness of saved models

Every finding must be produced by a deterministic tool (not LLM vibes). The agent's job is orchestration: route → run → interpret → propose fix → verify the issue is gone.

**MVP scope (5 checks, ~3 weeks):**

1. Data leakage detector (custom AST + LLM judgment)
2. Pickle/joblib unsafe deserialization (`bandit` + custom rules)
3. Secrets + notebook output scanner (`detect-secrets` + `trufflehog` + `nbformat`)
4. Supply-chain (unpinned deps + CVEs) (`pip-audit` + `safety`)
5. Adversarial robustness on trained model (IBM `adversarial-robustness-toolbox` / FGSM)

**Reference eval target:** `../Untitled9.ipynb` (the v1 NIDS notebook). The agent should find: `difficulty_level` leakage, SMOTE-before-split, `joblib.load` without integrity check, unpinned `!pip install`, and trivial adversarial evasion of the trained LSTM.

## Stack

- **Language:** Python 3.13
- **Agent runtime:** Claude Agent SDK (Python) — model: Sonnet 4.6 default, Opus 4.7 for plan + leakage reasoning
- **Model gateway:** Vercel AI Gateway (provider fallback + observability)
- **Sandbox:** Vercel Sandbox (Firecracker microVMs) for running target ML code safely
- **Package manager:** `uv` (not pip, not poetry)
- **CLI:** `typer` (entry point: `mlsecops`)
- **Validation:** `pydantic` v2
- **Storage:** SQLite via stdlib `sqlite3` — run history, findings, eval scores
- **Observability:** Langfuse Python SDK
- **Tests:** `pytest` + `pytest-cov`
- **Lint/format:** `ruff` (replaces flake8/black/isort)
- **Type check:** `mypy --strict`
- **Tool layer (called by the agent):** `bandit`, `detect-secrets`, `trufflehog`, `pip-audit`, `safety`, `nbformat`, `presidio-analyzer`, `adversarial-robustness-toolbox`, `semgrep`

## How to run things

| Task | Command |
|------|---------|
| Install deps | `uv sync` |
| Run the agent on a target repo | `uv run mlsecops audit <path>` |
| Run a single check | `uv run mlsecops check <name> <path>` |
| Typecheck | `uv run mypy src/` |
| Test | `uv run pytest` |
| Test with coverage | `uv run pytest --cov=mlsecops_agent --cov-report=term-missing` |
| Lint | `uv run ruff check .` |
| Format | `uv run ruff format .` |
| Eval against fixtures | `uv run mlsecops eval` |

## Architecture at a glance

```
src/mlsecops_agent/
├── cli.py                 # Typer entry point
├── agent.py               # Claude Agent SDK loop, tool dispatch
├── prompts/               # System + check-specific prompts
├── checks/                # The 5 MVP checks — each is a self-contained module
│   ├── leakage.py
│   ├── deserialization.py
│   ├── secrets.py
│   ├── supply_chain.py
│   └── adversarial.py
├── tools/                 # Wrappers around external CLIs (bandit, pip-audit, etc.)
├── storage/               # SQLite schema + repository
├── reporting/             # Markdown + JSON report renderers
└── models.py              # Pydantic types: Finding, Check, RunContext, FixProposal
tests/
├── checks/                # Unit tests per check
└── fixtures/              # Intentionally-vulnerable notebooks + scripts
```

Deeper notes: `.claude/docs/architecture.md`. Non-obvious decisions: `.claude/docs/decisions/`.

## Conventions

- Match existing patterns before introducing new ones
- Latest stable packages, no version pins unless required (this project depends on rapidly evolving security tools — pinning hides CVE fixes)
- Every check returns a `list[Finding]`. Never raise for "issue found" — raise only for tool failures
- No `Any`. No `# type: ignore`. Fix the type
- Pydantic models for every IPC boundary (tool input/output, agent state, report payloads)
- Conventional commits: `feat: fix: chore: refactor: docs: test:`
- One concept per file. If `checks/leakage.py` grows past ~300 lines, split

See `.claude/docs/conventions.md` for the full list.

## Model dispatch

Pick the cheapest model that reliably handles the task. Escalate only on evidence of difficulty.

| Task | Model |
|------|-------|
| Tool-call orchestration, simple edits, log triage | Haiku 4.5 |
| Check implementation, feature work, debugging, reviews (DEFAULT) | Sonnet 4.6 |
| Leakage reasoning, adversarial-attack design, architecture, security-critical | Opus 4.7 |

**Escalate** when: a check needs nuanced ML reasoning (is this *really* leakage?), an adversarial attack needs creative perturbation strategy, or the agent loop hits a hard ambiguity.

**Downgrade** back to Sonnet once a check's logic is settled — running the check is mechanical.

Never default to Opus for routine implementation. Never drive the audit loop with Haiku.

## What "done" means

Before claiming work is complete:

1. `uv run mypy src/` passes — no `Any`, no ignores
2. `uv run pytest` passes — every new check has a fixture-based test
3. `uv run ruff check .` passes
4. New check has at least one true-positive fixture (vulnerable code it should flag) and one true-negative (safe code it should not flag)
5. End-to-end: agent run on `../Untitled9.ipynb` produces the expected findings for the relevant check

## Don't

- Don't `pickle.load`, `joblib.load`, or `torch.load` *anything* in this project's runtime — we're the ones telling people not to. Use `weights_only=True` or load schemas via JSON/safetensors
- Don't commit `.env*` — API keys for Anthropic, Langfuse, gateway go in `.env.local`
- Don't run target ML code outside Vercel Sandbox / e2b. Target code is untrusted by definition
- Don't add an LLM call where a deterministic tool exists. Tools are the evidence; the LLM only interprets
- Don't ship a check without a fixture pair (positive + negative). Untested checks are worse than missing ones — false confidence
- Don't push to `main` directly — PRs only

## External references

- NSL-KDD eval target (sibling project): `../Untitled9.ipynb` (v1, intentionally vulnerable) and `../nids_pipeline_v2.ipynb` (v2, fixed)
- Claude Agent SDK Python docs: <https://docs.anthropic.com/en/api/agent-sdk>
- Vercel AI Gateway: <https://vercel.com/docs/ai-gateway>
- IBM Adversarial Robustness Toolbox: <https://adversarial-robustness-toolbox.readthedocs.io>
- NSL-KDD dataset source: <https://github.com/defcom17/NSL_KDD>

---

*This file is the project's persistent memory. Keep it accurate. Stale instructions are worse than missing ones.*
