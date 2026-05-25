"""Typer entry point.

Currently wired commands:

- ``mlsecops check <name> <path>`` — run a single check.
- ``mlsecops audit <path>`` — run every registered check, aggregate findings.

``eval`` lands with the fixture-eval harness (W2.3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .checks import CHECKS
from .eval import run_eval, write_baseline
from .models import CheckName, CheckResult, Severity
from .reporting import render_markdown

app = typer.Typer(
    name="mlsecops",
    help="Audit ML codebases for hygiene and security issues.",
    no_args_is_help=True,
)

_console = Console()

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _render(result: CheckResult) -> None:
    title = (
        f"[bold]{result.check.value}[/bold] - "
        f"{len(result.findings)} finding(s) in {result.duration_ms}ms"
    )
    if not result.findings:
        _console.print(f"{title}\n[green]No issues found.[/green]")
        return

    table = Table(title=title, show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("Message")
    table.add_column("Evidence", overflow="fold")

    for f in result.findings:
        location = str(f.file)
        if f.line_start is not None:
            location = f"{location}:{f.line_start}"
        table.add_row(
            f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f.id,
            location,
            f.message,
            f.evidence,
        )

    _console.print(table)


def _render_summary(results: list[CheckResult]) -> None:
    """One-row-per-check summary table, sorted highest-severity first."""
    table = Table(title="[bold]mlsecops audit summary[/bold]", show_lines=False)
    table.add_column("Check", no_wrap=True)
    table.add_column("Findings", justify="right")
    table.add_column("Max severity", no_wrap=True)
    table.add_column("Duration", justify="right")
    table.add_column("Status", no_wrap=True)

    def _max_sev(r: CheckResult) -> Severity:
        return max(
            (f.severity for f in r.findings),
            key=lambda s: _SEVERITY_RANK[s],
            default=Severity.INFO,
        )

    ordered = sorted(
        results,
        key=lambda r: (-_SEVERITY_RANK[_max_sev(r)], r.check.value),
    )

    for r in ordered:
        if r.findings:
            sev = _max_sev(r)
            sev_cell = f"[{_SEVERITY_STYLE[sev]}]{sev.value}[/]"
            status_cell = "[red]issues[/red]"
        elif r.tool_status != "ok":
            sev_cell = "-"
            status_cell = f"[yellow]{r.tool_status}[/]"
        else:
            sev_cell = "-"
            status_cell = "[green]clean[/]"

        table.add_row(
            r.check.value,
            str(len(r.findings)),
            sev_cell,
            f"{r.duration_ms}ms",
            status_cell,
        )

    _console.print(table)


def _resolve_checks(filters: list[str]) -> list[CheckName]:
    """Validate --check filters and return ordered list of CheckNames to run."""
    if not filters:
        return list(CHECKS.keys())

    selected: list[CheckName] = []
    valid = ", ".join(c.value for c in CheckName)
    for name in filters:
        try:
            check_name = CheckName(name)
        except ValueError as exc:
            raise typer.BadParameter(
                f"unknown check '{name}'. Valid: {valid}"
            ) from exc
        if check_name not in CHECKS:
            raise typer.BadParameter(
                f"check '{name}' is declared but not yet implemented."
            )
        if check_name not in selected:
            selected.append(check_name)
    return selected


@app.command()
def audit(
    path: str,
    only: Annotated[
        list[str] | None,
        typer.Option(
            "--check",
            "-c",
            help="Restrict to one or more checks. Repeat the flag to add more.",
        ),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report",
            "-r",
            help="Write a Markdown report of the run to this path.",
            dir_okay=False,
            file_okay=True,
            writable=True,
        ),
    ] = None,
) -> None:
    """Run every registered check against a target repo or file."""
    target = Path(path)
    if not target.exists():
        raise typer.BadParameter(f"target path does not exist: {path}")

    selected = _resolve_checks(only or [])
    if not selected:
        _console.print("[yellow]no checks are currently registered.[/yellow]")
        raise typer.Exit(code=0)

    results: list[CheckResult] = []
    for check_name in selected:
        runner = CHECKS[check_name]
        results.append(runner(target))

    _render_summary(results)
    for r in results:
        if r.findings:
            _console.print()
            _render(r)

    if report is not None:
        report.write_text(render_markdown(results, target=target), encoding="utf-8")
        _console.print(f"\n[dim]Markdown report written to[/dim] [bold]{report}[/bold]")

    if any(
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        for r in results
        for f in r.findings
    ):
        raise typer.Exit(code=1)


@app.command()
def check(name: str, path: str) -> None:
    """Run a single check against a target repo or file."""
    try:
        check_name = CheckName(name)
    except ValueError as exc:
        valid = ", ".join(c.value for c in CheckName)
        raise typer.BadParameter(f"unknown check '{name}'. Valid: {valid}") from exc

    runner = CHECKS.get(check_name)
    if runner is None:
        raise typer.BadParameter(
            f"check '{name}' is declared but not yet implemented in v0.1."
        )

    target = Path(path)
    if not target.exists():
        raise typer.BadParameter(f"target path does not exist: {path}")

    result = runner(target)
    _render(result)

    if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings):
        raise typer.Exit(code=1)


@app.command(name="eval")
def eval_cmd(
    fixtures_root: Annotated[
        Path,
        typer.Option(
            "--fixtures",
            help="Directory containing per-check fixture subdirectories.",
            exists=True,
            file_okay=False,
            dir_okay=True,
        ),
    ] = Path("tests/fixtures"),
    baseline: Annotated[
        Path,
        typer.Option(
            "--baseline",
            help="Path to EVAL_BASELINE.json.",
        ),
    ] = Path("tests/fixtures/EVAL_BASELINE.json"),
    update_baseline: Annotated[
        bool,
        typer.Option(
            "--update-baseline",
            help="Regenerate the baseline by re-running every check on every fixture.",
        ),
    ] = False,
    min_recall: Annotated[
        float,
        typer.Option(
            "--min-recall",
            help="Per-check recall floor; any check below this exits 1.",
            min=0.0,
            max=1.0,
        ),
    ] = 1.0,
) -> None:
    """Run the fixture eval harness and report precision/recall per check."""
    if update_baseline:
        result = write_baseline(fixtures_root, baseline)
        _console.print(
            f"[green]Wrote baseline[/green] with {len(result.fixtures)} fixture entries to "
            f"[bold]{baseline}[/bold]."
        )
        return

    report = run_eval(fixtures_root, baseline)

    table = Table(title="[bold]mlsecops eval[/bold]", show_lines=False)
    table.add_column("Check", no_wrap=True)
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")

    for row in report.rows:
        recall_style = "green" if row.recall >= min_recall else "red"
        table.add_row(
            row.check.value,
            str(row.true_positives),
            str(row.false_positives),
            str(row.false_negatives),
            f"{row.precision:.3f}",
            f"[{recall_style}]{row.recall:.3f}[/]",
            f"{row.f1:.3f}",
        )

    _console.print(table)

    if report.missing_baseline:
        _console.print(
            f"\n[yellow]{len(report.missing_baseline)} fixture(s) have no baseline entry "
            f"— rerun with --update-baseline to record them:[/yellow]"
        )
        for path in report.missing_baseline:
            _console.print(f"  - {path}")

    failing = [r for r in report.rows if r.recall < min_recall]
    if failing:
        names = ", ".join(r.check.value for r in failing)
        _console.print(
            f"\n[red]Recall below {min_recall} for: {names}[/red]"
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
