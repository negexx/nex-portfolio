"""Eval harness — fixture-based precision/recall per check."""

from __future__ import annotations

from .harness import EvalReport, ReportRow, run_eval, write_baseline

__all__ = ["EvalReport", "ReportRow", "run_eval", "write_baseline"]
