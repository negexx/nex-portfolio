# Architecture — mlsecops-agent

> A map for AI agents and humans. Update when the shape of the system changes, not for every leaf-level edit.

## One-paragraph overview

`mlsecops-agent` is a Python CLI that audits ML codebases (notebooks + scripts) for two classes of issue: ML-hygiene mistakes (data leakage, contamination, missing baselines) and security mistakes (insecure deserialization, secrets, supply-chain CVEs, model evadability). The agent is a Claude-driven tool loop: it explores the target repo, dispatches deterministic checks, interprets the results, proposes fixes, and writes a structured report. Every finding is backed by a real tool — the LLM orchestrates and explains, it never *decides* what's vulnerable.

## System diagram

```
       ┌─────────────────────────────────────────────────────┐
       │                  mlsecops CLI (Typer)               │
       │   audit │ check │ eval │ report                      │
       └────────────────────────┬────────────────────────────┘
                                │
                                ▼
       ┌─────────────────────────────────────────────────────┐
       │            Agent loop (Claude Agent SDK)            │
       │  plan → tool call → interpret → fix → verify        │
       │  model: Sonnet 4.6 default, Opus 4.7 for hard judg. │
       └──────┬────────────────────────────────┬─────────────┘
              │                                │
              ▼                                ▼
   ┌──────────────────────┐         ┌──────────────────────┐
   │  Check modules       │         │  Tool wrappers       │
   │  (deterministic)     │  call   │  bandit, pip-audit,  │
   │  leakage             │ ◄────── │  detect-secrets,     │
   │  deserialization     │         │  trufflehog, ART,    │
   │  secrets             │         │  nbformat, semgrep   │
   │  supply_chain        │         └──────────┬───────────┘
   │  adversarial         │                    │
   └────────┬─────────────┘                    │
            │                                  │
            ▼                                  ▼
   ┌──────────────────────┐         ┌──────────────────────┐
   │  Sandbox             │         │  Storage (SQLite)    │
   │  Vercel Sandbox /    │         │  runs, findings,     │
   │  e2b — target ML     │         │  fix_proposals,      │
   │  code runs HERE      │         │  eval_results        │
   │  (never in host)     │         └──────────────────────┘
   └──────────────────────┘
                                    ┌──────────────────────┐
                                    │  Langfuse            │
                                    │  traces, costs       │
                                    └──────────────────────┘
```

## Major modules

| Module | Path | Purpose |
|--------|------|---------|
| CLI | `src/mlsecops_agent/cli.py` | Typer entry point. Routes `audit`/`check`/`eval`/`report`. |
| Agent loop | `src/mlsecops_agent/agent.py` | Claude Agent SDK tool dispatch, approval gates, event log. |
| Checks | `src/mlsecops_agent/checks/` | 5 MVP checks. Each exports `run(ctx) -> list[Finding]`. |
| Tools | `src/mlsecops_agent/tools/` | Subprocess wrappers around external CLIs. Pydantic-validated outputs. |
| Sandbox | `src/mlsecops_agent/sandbox.py` | Vercel Sandbox / e2b client. Anything that runs target code goes through here. |
| Storage | `src/mlsecops_agent/storage/` | SQLite schema + repository pattern. |
| Reporting | `src/mlsecops_agent/reporting/` | Markdown + JSON report renderers. |
| Models | `src/mlsecops_agent/models.py` | Pydantic types: `Finding`, `FixProposal`, `RunContext`, `CheckResult`. |
| Prompts | `src/mlsecops_agent/prompts/` | System prompt + per-check explainer prompts. |

## Data flow — `mlsecops audit <path>` happy path

1. CLI parses `<path>`, materializes a `RunContext` (target path, run id, sandbox handle, db session).
2. Agent loop starts. System prompt establishes role, lists available tools, points to the run id.
3. Agent calls `list_files(path)` to map the target. Routes by file type (`.ipynb`, `.py`, `requirements.txt`, `pyproject.toml`, `*.pkl`, `*.h5`).
4. For each check in MVP, agent calls `run_check(name, ctx)`. Check executes deterministically, returns `list[Finding]`.
5. Each `Finding` is persisted via `storage/findings.py::insert`.
6. For high-severity findings, agent calls `propose_fix(finding)` which returns a `FixProposal` (diff or replacement snippet).
7. **Approval gate** — fix proposals are surfaced to the user via stdout. Apply only on explicit `--apply` flag or interactive confirm.
8. Agent calls `render_report(run_id)` → markdown summary + JSON for downstream tooling.

## External dependencies

| Service | Purpose | Failure mode |
|---------|---------|--------------|
| Anthropic API (via Vercel AI Gateway) | LLM calls for agent loop, fix proposals | Gateway falls back to direct Anthropic on outage. Audit can complete without LLM if `--no-explain` is set — findings still produced, just no narrative. |
| Vercel Sandbox / e2b | Run target ML code (adversarial check, model load test) | Adversarial check skips with a `tool_unavailable` finding-status. Other checks unaffected. |
| Langfuse | Trace + cost observability | Best-effort. Silent failure if unreachable. |
| External CLIs (`bandit`, `pip-audit`, `detect-secrets`, etc.) | The actual detection work | Missing tool → check returns a `tool_missing` status finding. Don't fail the whole audit. |

## Cross-cutting concerns

- **Auth:** API keys via `.env.local` (gitignored). `ANTHROPIC_API_KEY`, `AI_GATEWAY_KEY`, `LANGFUSE_PUBLIC_KEY`, `LANGFUSE_SECRET_KEY`, `VERCEL_SANDBOX_TOKEN`.
- **Logging:** structlog → stdout (human) + Langfuse (machine). One trace per `audit` invocation. Each tool call is a span.
- **Error reporting:** exceptions in checks become `Finding(severity="error", category="tool_failure")` — never crash the audit. The agent decides whether to continue.
- **Feature flags:** none yet. If a 6th check is experimental, gate it on a CLI flag (`--include adversarial-v2`), not env.

## What this doc is NOT

- Not an exhaustive file list — that's discoverable via `tree`.
- Not the spec for each check — those live in `docs/checks/<name>.md`.
- Not a tutorial — see the project `README.md` for getting started.
