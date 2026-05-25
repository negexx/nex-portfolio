# ADR 0003 — MVP scope: five checks, one eval target

**Status:** Accepted
**Date:** 2026-05-26

## Context

The space of "things you could check in an ML codebase" is open-ended. Shipping all of them produces a tool that does nothing well. Shipping one produces a feature, not a project. The right MVP scope is the smallest set that demonstrates both pillars (ML hygiene + security) and produces non-trivial findings on a real target.

## Decision

MVP = five checks, evaluated against `../Untitled9.ipynb` (the v1 NIDS notebook intentionally containing known bugs) plus a fixture suite under `tests/fixtures/`:

1. **`leakage`** — data leakage (label proxies, fit-before-split, SMOTE-before-split, scaler fit on test). ML pillar.
2. **`deserialization`** — `pickle.load`, `joblib.load`, `torch.load(weights_only=False)` of untrusted artifacts. Security pillar.
3. **`secrets`** — secrets in notebook cells + notebook *outputs* (data rows, API responses cached in `.ipynb`). Security pillar.
4. **`supply_chain`** — unpinned `pip install`, `requirements.txt` entries with no version constraint, known CVEs via `pip-audit` / `safety`. Security pillar.
5. **`adversarial`** — load the trained model in the sandbox, run FGSM (or a black-box baseline), report evasion success rate. Security + ML pillar, ties directly to NIDS.

Anything beyond these five is out of scope for v0.1.

## Alternatives considered

- **Three checks (just security):** rejected — wouldn't differentiate from generic Python SAST. The ML-hygiene pillar is what makes this novel.
- **Ten checks (cover everything):** rejected — would dilute quality and stretch shipping past the 3-week budget. Each check needs fixtures, fix proposals, eval baseline; that work doesn't compress.
- **Two checks (one per pillar):** rejected — too sparse to demonstrate the agent's value as an orchestrator. Five gives the agent enough routing decisions to be interesting.

## Consequences

- **Positive:** Clear definition of done. Eval baseline is achievable. Every check can be deep instead of shallow.
- **Positive:** `../Untitled9.ipynb` makes a real eval target — agent will produce concrete findings on real code, not just synthetic fixtures.
- **Negative:** Notebook-output PII (presidio) is out of scope for v0.1 even though it's cheap to add. Resist the temptation.
- **Neutral:** PR-bot deployment, GitHub App, web UI — all explicitly deferred to v0.2+. CLI only for v0.1.

## How to revisit

After v0.1 ships and the eval is stable, revisit with metrics: which check produces the most user-actionable findings? Which has the worst false-positive rate? Use that to prioritize the v0.2 backlog (presidio for PII, semgrep custom rules, model-card completeness, dataset-card completeness, …).
