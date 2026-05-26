# ADR 0005 — Sandbox isolation for target ML code

**Status:** Proposed (2026-05-26). Stub interface lives in `src/mlsecops_agent/sandbox.py`; live backend deferred to a future release.

## Context

Four of the five MVP checks (`supply_chain`, `secrets`, `deserialization`, `leakage`) are static — they read source bytes and never execute target code. They are safe to run in-process.

The fifth check (`adversarial`) is different. It needs to:

1. Load a saved Keras model file from the target directory (`.h5` or `.keras`).
2. Construct a probe dataset.
3. Run a FGSM attack against the live model.

Step 1 is the problem. `tf.keras.models.load_model` deserialises arbitrary code from the artifact. If the audited repo is one the operator trusts (their own ML pipeline), this is fine. If it is anything else — a customer's repo, a pull request, an unknown notebook — loading it in-process is **exactly** the vulnerability the agent warns about under `deserialization.unsafe-joblib-load`.

The current MVP guards this with an opt-in flag (`--include-adversarial`) and documents the trust requirement, but that is a circular defence: the tool exists precisely because operators *don't* know whether artifacts are safe.

## Decision

The `Sandbox` abstraction in `src/mlsecops_agent/sandbox.py` defines a contract that every check needing arbitrary execution will go through. The MVP stub raises `SandboxNotConfigured` so the audit fails loudly rather than silently executing in-process. A live backend is required before the project accepts targets that are not the operator's own code.

Two candidate backends were evaluated:

| Backend | Pros | Cons |
|---|---|---|
| **Vercel Sandbox** (Firecracker microVMs) | Single-vendor with the AI Gateway; per-run isolation; fast cold-start (<2s) | Newer offering; tighter quotas; runtime-only (no persistent storage by design) |
| **e2b.dev** | Mature Python-first SDK; persistent project workspaces; good local-dev story | Separate vendor + billing; slower cold-start (~5s) |

Both expose roughly the same shape: create a session, upload files, run a command, read stdout. `Sandbox.from_env()` reads `VERCEL_TOKEN` or `E2B_API_KEY` and dispatches accordingly. The implementation lands as a separate ADR when one backend is chosen for v1.0.

## Consequences

**Positive**
- Threat model becomes consistent: the agent never loads attacker-controlled artifacts in its own host process.
- Forces the operator to make a deliberate choice (sandbox provider + cost) before running checks that need execution. No silent insecure defaults.
- Contract-first means tests can mock the `Sandbox` interface today; switching live backends later is a single-file change.

**Negative**
- `--include-adversarial` becomes practically unavailable until a backend ships. This is the right tradeoff — better an unavailable check than an unsafe one.
- Sandbox latency adds ~2-5s per check that needs execution. Acceptable given how rarely the adversarial check runs (opt-in, model-specific).
- Vendor lock-in is real; pinning to one backend in v1.0 will be revisited.

## Open questions

- Does Vercel Sandbox's filesystem cap (tens of MB at time of writing) accommodate typical ML artifact sizes (a 500MB BERT checkpoint is plausible)? If not, e2b wins by default.
- Streaming logs back from the sandbox: should `SandboxSession.iter_results` be an async generator? The agent loop is sync today; making sandbox calls async cascades through `provider.chat()`.
- Per-finding cost attribution: each sandbox call has a cost. Should the eval harness include sandbox cost in its baseline?
