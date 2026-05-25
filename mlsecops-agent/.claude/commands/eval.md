---
name: eval
description: Run the fixture-based eval harness and report precision/recall per check. The headline metric for any change to mlsecops-agent.
argument-hint: "[check_name to run a single check's eval]"
---

# /eval — Run the fixture eval

The eval is the source of truth for whether a change improved or regressed the agent. Code that passes tests but moves the eval the wrong way is broken in the way that actually matters.

## Steps

1. **Run the eval harness:** `uv run mlsecops eval $ARGUMENTS`
2. Compare the result against the baseline in `tests/fixtures/EVAL_BASELINE.json`.
3. Report per-check precision and recall, plus a diff vs. baseline.

## Output format

```
== Eval results ==
Check                  TP   FP   FN  Precision  Recall   F1   Δ vs baseline
leakage                 8    0    1     1.000   0.889  0.941   +0.020 ▲
deserialization         5    0    0     1.000   1.000  1.000    0.000
secrets                 6    1    0     0.857   1.000  0.923   -0.040 ▼ ⚠
supply_chain            4    0    0     1.000   1.000  1.000    0.000
adversarial             3    0    1     1.000   0.750  0.857    0.000

Macro F1: 0.944  (baseline 0.948)  Δ -0.004

⚠ Regressions:
  - secrets: tests/fixtures/secrets/safe_dotenv_reference.ipynb flagged
    as positive (false positive). New rule "anything that contains
    'API_KEY'" is too broad.
```

## Rules

- Don't update the baseline silently. If the user accepts a new baseline, that's a deliberate decision and goes in its own commit: `chore: bump eval baseline — <reason>`.
- Investigate every regression before continuing other work. A regression is a real signal, not noise.
- The adversarial check is the only one allowed any RNG sensitivity — its F1 is reported as a 95% CI over 10 seeds, not a point estimate.
