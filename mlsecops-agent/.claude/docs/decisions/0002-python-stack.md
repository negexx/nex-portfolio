# ADR 0002 — Python stack for the audit agent

**Status:** Accepted
**Date:** 2026-05-26

## Context

The agent edits / analyses Python ML codebases (notebooks + scripts). Choosing the implementation language is the first load-bearing decision because it constrains the tool layer (AST manipulation, security CLIs, ML library introspection).

Two realistic candidates: TypeScript or Python.

## Decision

**Python 3.13**, managed with `uv`. Agent loop on Claude Agent SDK (Python). CLI on Typer. Pydantic v2 for all boundary types. SQLite stdlib for storage. Ruff + mypy --strict for quality gates.

## Alternatives considered

- **TypeScript + Claude Agent SDK (TS):** rejected because the target codebases are Python and the best AST / security tooling for Python is Python-native (`ast`, `libcst`, `bandit`, `pip-audit`, `detect-secrets`, `presidio`, `nbformat`, IBM ART). A TS agent would shell out to Python for every interesting operation. Skip the middleman.
- **Python + LangGraph:** rejected because the agent loop is simple (read, dispatch tool, interpret, decide). LangGraph's abstraction tax exceeds its benefit at this scale; the Claude Agent SDK already provides the tool-call loop + MCP support directly.
- **Python + raw `anthropic` SDK:** considered. Difference vs. Agent SDK is whether to roll the loop ourselves. Agent SDK wins because hooks, permission gates, and event logging are pre-built — and they're exactly the parts of an agent that are easy to get wrong.

## Consequences

- **Positive:** First-class access to `libcst`, `bandit`, `nbformat`, `pip-audit`, ART. Dogfood opportunity (we can audit our own code). One language across agent loop, checks, fixtures, tests.
- **Positive:** `uv` makes CLI distribution painless (`uv tool install mlsecops-agent`), sidestepping Python's traditional packaging mess.
- **Negative:** Python's async story is rougher than Node's; the agent loop will need careful structuring around `asyncio` for sandbox calls and Langfuse spans.
- **Neutral:** Job market for "AI engineer" still skews Python-default, which helps portfolio fit. Solo-founder positioning is unaffected.

## How to revisit

If we ever need to ship the agent as an npm-installable dev tool (e.g. for JS/TS repo audits), revisit with a new ADR proposing a TS rewrite of the loop with Python invoked as a sandboxed subprocess for Python-specific checks.
