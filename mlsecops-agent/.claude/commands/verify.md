---
name: verify
description: Run the project's verification gate (typecheck + tests + lint + eval) and report results. Required before claiming work is complete.
argument-hint: "[--eval to also run the end-to-end fixture eval]"
---

# /verify — Pre-completion gate

Run the standard verification commands for **mlsecops-agent** and report results honestly.

## Commands to run (in this order)

1. **Typecheck:** `uv run mypy src/`
2. **Tests:** `uv run pytest -x`
3. **Lint:** `uv run ruff check .`
4. **Format check:** `uv run ruff format --check .`

Run them sequentially — a typecheck failure usually invalidates the test results, so don't waste time running tests if step 1 fails. Report each one's exit status before moving on.

If `--eval` is passed:

5. **Fixture eval:** `uv run mlsecops eval` — runs every check against `tests/fixtures/` and asserts the expected findings (and only those) are produced. This is the real bar: did we move the eval score?

## Output format

```
✓ Typecheck — passed (4s)
✓ Tests   — 32 passed, 0 failed (12s)
✗ Lint    — 2 errors in src/mlsecops_agent/checks/leakage.py
   <paste relevant snippets>

Next: fix lint errors before claiming this task done.
```

## Rules

- Don't paper over failures. A red is a red.
- Don't claim "passed" without showing the output. Evidence before assertions.
- If a fixture test is flaky, investigate root cause — *especially* the adversarial-robustness check, which depends on RNG. Seed it and assert ranges, not exact numbers.
- A new check is not "done" until it has both positive and negative fixtures and both assertions pass.

## When verification fails

Surface the actual error verbatim. Don't summarize away the useful detail. For mypy, paste the full diagnostic with line numbers — the user needs the real output to debug.
