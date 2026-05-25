"""Markdown report renderer.

Turns a ``list[CheckResult]`` into a single Markdown document with:

- A summary header (target, timestamp, total findings, exit status hint)
- A summary table (one row per check, sorted highest-severity first)
- Per-check sections, each with a severity-grouped table of findings + the
  fix proposal when one is attached

The output is deterministic — same input always produces byte-identical bytes
so it's safe to diff committed reports across runs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..models import CheckResult, Finding, Severity

if TYPE_CHECKING:
    from pathlib import Path

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.INFO: "🔵 info",
    Severity.LOW: "🟦 low",
    Severity.MEDIUM: "🟡 medium",
    Severity.HIGH: "🟠 high",
    Severity.CRITICAL: "🔴 critical",
}


def _max_severity(result: CheckResult) -> Severity:
    return max(
        (f.severity for f in result.findings),
        key=lambda s: _SEVERITY_RANK[s],
        default=Severity.INFO,
    )


def _escape_pipe(text: str) -> str:
    """Make a string safe for a Markdown table cell. Collapses newlines."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _render_finding_row(f: Finding) -> str:
    location = str(f.file)
    if f.line_start is not None:
        location = f"{location}:{f.line_start}"
    return (
        f"| {_SEVERITY_BADGE[f.severity]} "
        f"| `{f.id}` "
        f"| `{_escape_pipe(location)}` "
        f"| {_escape_pipe(f.message)} "
        f"| `{_escape_pipe(f.evidence)}` |"
    )


def _render_check_section(result: CheckResult) -> list[str]:
    lines: list[str] = [
        "",
        f"## `{result.check.value}` — {len(result.findings)} finding(s)",
        "",
        f"_Tool status: `{result.tool_status}`. Duration: {result.duration_ms}ms._",
        "",
    ]

    if not result.findings:
        lines.append("No issues found.")
        return lines

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (-_SEVERITY_RANK[f.severity], f.id, str(f.file), f.line_start or 0),
    )

    lines.append("| Severity | Rule | Location | Message | Evidence |")
    lines.append("|---|---|---|---|---|")
    for f in sorted_findings:
        lines.append(_render_finding_row(f))

    fixes = [(f, f.fix) for f in sorted_findings if f.fix is not None]
    if fixes:
        lines.append("")
        lines.append("### Fix proposals")
        lines.append("")
        for f, fix in fixes:
            lines.append(
                f"- **`{f.id}`** at `{f.file}`"
                + (f":{f.line_start}" if f.line_start is not None else "")
                + f" ({fix.confidence} confidence) — {fix.summary}"
            )

    return lines


def _render_summary_table(results: list[CheckResult]) -> list[str]:
    lines: list[str] = [
        "## Summary",
        "",
        "| Check | Findings | Max severity | Duration | Status |",
        "|---|---:|---|---:|---|",
    ]

    ordered = sorted(
        results,
        key=lambda r: (-_SEVERITY_RANK[_max_severity(r)], r.check.value),
    )

    for r in ordered:
        if r.findings:
            sev = _SEVERITY_BADGE[_max_severity(r)]
            status = "issues"
        elif r.tool_status != "ok":
            sev = "—"
            status = r.tool_status
        else:
            sev = "—"
            status = "clean"
        lines.append(
            f"| `{r.check.value}` | {len(r.findings)} | {sev} | {r.duration_ms}ms | {status} |"
        )

    return lines


def render_markdown(
    results: list[CheckResult],
    *,
    target: Path | str,
    generated_at: datetime | None = None,
) -> str:
    """Render a list of CheckResults to a single Markdown report string.

    ``generated_at`` is parameterised so callers can pin it (eval harness,
    snapshot tests). Defaults to UTC now.
    """
    when = generated_at or datetime.now(UTC)
    total = sum(len(r.findings) for r in results)
    has_blocker = any(
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        for r in results
        for f in r.findings
    )

    parts: list[str] = [
        "# mlsecops audit report",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {when.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- **Total findings:** {total}",
        (
            "- **Exit status:** "
            + ("❌ blocking (HIGH/CRITICAL present)" if has_blocker else "✅ non-blocking")
        ),
        "",
    ]
    parts.extend(_render_summary_table(results))

    for r in sorted(results, key=lambda r: (-_SEVERITY_RANK[_max_severity(r)], r.check.value)):
        parts.extend(_render_check_section(r))

    parts.append("")  # trailing newline
    return "\n".join(parts)
