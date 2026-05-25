---
name: ship
description: Open a PR for the current branch after running verification + eval. Drafts a clean conventional-commit-style PR title and body.
argument-hint: "[--draft]"
---

# /ship — Open a pull request

Ship the current branch as a PR. The user expects this command to do the boring parts (verify, eval, push, draft PR body) so they can review and hit merge.

## Steps

1. **Sanity check** — confirm we're not on `main` and there are commits ahead of `origin/main`. If on `main`, refuse and tell the user to branch first.

2. **Run /verify --eval** — typecheck + tests + lint + fixture eval must all pass. If anything fails, stop and report. For a new check, the eval delta (which fixtures it now flags, which it stopped missing) is the headline of the PR.

3. **Push** — `git push -u origin HEAD` (only if branch isn't already tracking remote).

4. **Draft PR title and body** based on the commits between `main` and `HEAD`:
   - Title: conventional-commit style, ≤70 chars
   - Body: Summary (bullets), Eval delta, Test plan (checklist), any flagged risks

5. **Create PR** with `gh pr create` — pass `--draft` if the flag is set.

6. **Report the URL.**

## PR body template

```markdown
## Summary
- <what changed, 1-3 bullets>
- <why>

## Eval delta
- Before: <fixtures flagged> / <total fixtures> — macro-precision X, recall Y
- After:  <fixtures flagged> / <total fixtures> — macro-precision X, recall Y
- New true positives: <list>
- New false positives: <list — should be empty>

## Test plan
- [ ] Run `uv run mlsecops audit ../Untitled9.ipynb` and confirm finding set unchanged for unrelated checks
- [ ] <edge case to check>

## Notes
<anything reviewers should pay attention to — new tool dependencies, sandbox config changes, schema migrations>
```

## Rules

- Never push directly to `main`.
- Never force-push unless the user asked.
- If verification or eval fails, do NOT push or open the PR — fix first.
- New tool dependency? Call it out in Notes with a one-line justification (size, license, supply-chain check).
- Schema changes to `storage/`? Include the migration SQL in the PR body.
