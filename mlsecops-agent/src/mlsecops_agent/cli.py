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
from .models import CheckName, CheckResult, Severity

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


@app.command()
def eval() -> None:
    """Run the fixture eval harness and report precision/recall per check."""
    raise NotImplementedError("eval() — implement once tests/fixtures/EVAL_BASELINE.json exists")


if __name__ == "__main__":
    app()
