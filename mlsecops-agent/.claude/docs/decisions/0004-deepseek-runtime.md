# ADR 0004 — DeepSeek as the LLM runtime

**Status:** Accepted (2026-05-26).
**Supersedes:** the "Claude Agent SDK" entry in [ADR 0002 — Python stack](0002-python-stack.md).

## Context

The agent loop calls an LLM for three purposes:

1. **Orchestration** — picking which check to run next, batching, retries.
2. **Interpretation** — turning raw tool output into a Finding's `message` and a coherent fix narrative.
3. **Judgement** on AST-flagged ambiguous cases (mainly the `leakage` check: "is this `.fit(X_train)` *after* the split, or is this another `train_test_split` further up the file?").

None of these tasks need frontier-class reasoning. The check modules are deterministic; the LLM is plumbing on top.

The eval harness re-runs every check against every fixture on every PR. With Claude Sonnet 4.6 at roughly $3/M input + $15/M output, that's a meaningful per-PR cost for a side project, and it scales with fixture count. The cost will dominate compute as the agent grows.

## Decision

The agent runtime calls **DeepSeek V4** via its OpenAI-compatible API:

| Tier | Model | Use |
|---|---|---|
| Default | `deepseek-v4-flash` | Orchestration, fix narration, finding interpretation. |
| Escalation | `deepseek-v4-pro` | Leakage AST-judgement, adversarial strategy. |

Both via the `openai` Python SDK with `base_url="https://api.deepseek.com/v1"`. Provider is swappable by setting `DEEPSEEK_BASE_URL` — pointing at OpenRouter or a local OpenAI-compatible stub works without code changes.

**Concrete pricing (May 2026):**
- V4-Flash: $0.14 / $0.28 per M tokens (in / out)
- V4-Pro: $0.435 / $0.87 (promo), $1.74 / $3.48 (post-promo)

For comparison, Sonnet 4.6 is roughly $3 / $15 — V4-Flash is ~20x cheaper input, ~50x cheaper output.

## Consequences

**Positive**
- Eval harness can run on every PR without cost discussion.
- Cache-hit pricing (sub-cent per M tokens) makes idempotent re-runs nearly free.
- Provider abstraction is a single env var — vendor lock-in stays low.
- Project narrative gains a layer: "Claude built the tool that runs on DeepSeek." Honest about the dev/runtime split.

**Negative**
- Tool-use support on DeepSeek's API is newer than Anthropic's — needs explicit testing in the agent loop, with the fallback being "compose the prompt as a structured JSON-output request" if function calling proves flaky.
- Loss of Anthropic's prompt-caching ergonomics. DeepSeek's cache is automatic for identical prefixes ≥ 1024 tokens, which fits the system-prompt + tool-spec preamble pattern well, but verify on integration.
- DeepSeek's data-handling: route only public/synthetic fixtures through it during eval; for real customer code audits, gate behind a `--llm` flag with an explicit consent prompt.

**Neutral**
- Claude Code (the assistant writing this codebase) remains the dev-side tool. CLAUDE.md model dispatch table for Claude Code is independent of this decision.

## Alternatives considered

- **Sonnet 4.6 / Haiku 4.5** — best tool-use ergonomics, prompt-cache infra, but the cost-per-eval is the reason for this ADR.
- **GPT-5 / GPT-5-Mini** — comparable to Sonnet in price, no cost advantage over DeepSeek.
- **Local Llama-3.3-70B via Ollama** — zero per-token cost, but tool-use fidelity drops meaningfully and the eval becomes user-machine-dependent.
- **OpenRouter as primary** — adds a margin on top of DeepSeek's direct price. Kept as fallback via `DEEPSEEK_BASE_URL` env var, not the default.

## Open questions

- Does DeepSeek's function-calling implementation handle parallel tool calls (multi-check dispatch in one turn)? Verify in W3.
- Langfuse + DeepSeek integration — Langfuse has generic OpenAI SDK tracing, but verify spans render correctly.
