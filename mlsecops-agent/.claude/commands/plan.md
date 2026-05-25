---
name: plan
description: Produce an implementation plan before touching code. Required for any change spanning 3+ files or introducing a new check/tool integration.
argument-hint: "<feature or task description>"
---

# /plan — Implementation planning

You are about to plan work on **mlsecops-agent**. The user's intent: `$ARGUMENTS`

Produce a plan, not code. The plan should be the kind of thing a competent teammate could pick up and execute without re-asking the same questions.

## Output format

```markdown
## Goal
<one sentence — what changes after this is done>

## Context I checked
- <files/folders you read, with a one-line takeaway>
- <existing checks/tools to model the new one on>
- <related ADRs in .claude/docs/decisions/>

## Approach
<2-3 paragraphs explaining the strategy and why this over alternatives>

## Steps
1. <concrete step, file paths included>
2. <next step>
...

## Fixtures + tests
- Positive fixture (vulnerable code the check must flag): `tests/fixtures/...`
- Negative fixture (safe code the check must not flag): `tests/fixtures/...`
- Unit tests: `tests/checks/test_<name>.py` — assert finding ids, severities, line ranges

## Risks / Open questions
- <anything you're unsure about — flag for the user>
```

## Rules

- Read before planning. Don't propose changes to files you haven't read.
- For a new check: study the closest existing check and copy its shape. Don't invent a new module layout.
- Every check needs a positive *and* negative fixture. If you can't write both, the check isn't well-defined.
- If the check requires running target ML code, the plan must specify that it runs inside the sandbox — never in the agent's host process.
- End with a one-line "ready to execute?" and stop. Don't start coding.

## When to escalate the model

If the plan involves:
- Whether something *counts* as data leakage (ML judgment call)
- A new adversarial attack strategy
- Changes to the agent loop, tool dispatch, or storage schema
- Anything that touches how findings are scored / ranked

…note that this work warrants Opus 4.7, and surface that recommendation before continuing.
