# Conventions — mlsecops-agent

> The rules an agent should match before introducing new patterns. If something here is wrong or outdated, fix the doc — don't quietly diverge in code.

## Code style

- `ruff` is the source of truth. Run `uv run ruff format` and `uv run ruff check` before committing.
- Files end with a newline. No trailing whitespace.
- Line length: 100 (matches `ruff` default in this project's `pyproject.toml`).
- One concept per file. If a file does two unrelated things, split it.

## Naming

- Files / modules: `snake_case.py`
- Classes: `PascalCase`
- Functions / variables: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE` only for true constants (not config you might tweak)
- Pydantic models: `PascalCase`, suffix `In` / `Out` for request/response payloads when the distinction matters

## Python

- Target version: `3.13`. Use modern syntax: `match`, `|` for unions, `Self`, `type` aliases.
- `from __future__ import annotations` at the top of every module — keeps runtime light and matches `ruff` defaults.
- No `Any`. No `# type: ignore`. No `cast()` without a comment explaining why.
- Prefer `Protocol` over ABCs. Prefer composition over inheritance.
- Standard library first. Don't add a dep when `pathlib` / `dataclasses` / `enum` / `itertools` will do.

## Type hints

- Every public function has a fully-typed signature.
- Return types are mandatory, even for `-> None`.
- Use `pydantic.BaseModel` for any data that crosses a process or I/O boundary (tool calls, file parsing, DB rows, agent state).
- `mypy --strict` is the floor.

## Imports

- Order (enforced by `ruff`): stdlib → third-party → first-party → relative — separated by blank lines.
- No wildcard imports.
- No deep relative imports (`..foo.bar`) — use absolute imports from `mlsecops_agent`.

## Errors

- Define exception hierarchy in `models.py`: `MLSecOpsError` → `CheckError`, `ToolError`, `SandboxError`.
- Throw `Exception` subclasses with a useful message, never bare strings.
- Catch narrowly. `try` blocks wrap the smallest unit that can actually fail.
- Never swallow exceptions silently — log and rethrow, or convert to a `Finding` with `severity="error"`.

## Tests

- One concept per test. Multiple `assert` statements are fine if they test the same idea.
- Test names describe behavior: `test_flags_smote_before_split()`, not `test_smote_check()`.
- Use real dependencies where cheap (in-memory SQLite, real subprocess to `bandit` with a tiny fixture file). Mock only at the network boundary (Anthropic API, Langfuse).
- Every check has at least one positive fixture AND one negative fixture under `tests/fixtures/<check>/`. The eval harness consumes the same fixtures.
- Don't test implementation details. `test_flags_smote_before_split` asserts the *finding shape*, not which AST node the visitor walked first.

## Findings

- Every `Finding` has: `id` (stable string, never reused), `check`, `severity` (one of `info`/`low`/`medium`/`high`/`critical`), `category`, `file`, `line_start`, `line_end`, `message`, `evidence` (raw tool output excerpt), and optional `fix` (`FixProposal`).
- Severity rules: arbitrary code execution (pickle, eval) → `critical`. Secret in git history → `high`. Unpinned dep without CVE → `low`. Data leakage → `high` (it silently invalidates the model).
- `id` format: `<check>.<kebab-rule>` (e.g. `deserialization.untrusted-joblib-load`, `leakage.fit-before-split`).

## Commits

Conventional Commits:
- `feat:` new check, new tool integration, new CLI command
- `fix:` bug in a check (e.g. false positive)
- `chore:` housekeeping (deps, config, baseline bumps)
- `refactor:` no behavior change
- `docs:` documentation only
- `test:` test-only changes (including new fixtures)
- `eval:` baseline updates (separate from the change that motivated them)

Subject ≤72 chars, imperative ("add" not "added"), no trailing period.

## Comments

Default: no comments. Names and types should carry the meaning.

Write a comment when:
- There's a non-obvious *why* (constraint, workaround, surprising invariant)
- The code does something that would look like a bug to a careful reader
- Wrapping an external CLI's quirks (e.g. "bandit returns exit 1 on findings, not on failure — don't `check=True`")

Don't write a comment for:
- What the code does (the code does it)
- Who added it or why (`git blame` does that)
- Future plans ("TODO: refactor this later" — open an issue instead)

## Security (for *our own* code)

- Never `pickle.load` / `joblib.load`. If we must load a `.pkl` for a target audit, do it inside the sandbox.
- Never `subprocess(shell=True)`. Always pass `list[str]` arguments.
- Never `eval` / `exec` on target code or LLM output.
- All external CLI args are constructed from validated Pydantic models — never string-formatted from user input.
- LLM outputs are treated as untrusted strings. JSON parsing goes through Pydantic.
