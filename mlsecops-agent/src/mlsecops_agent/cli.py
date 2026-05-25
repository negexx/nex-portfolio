"""Typer entry point.

Currently wired commands:

- ``mlsecops check <name> <path>`` — run a single check (only ``supply_chain``
  is implemented in v0.1).

``audit`` and ``eval`` will land alongside the agent loop and eval harness.
"""

from __future__ import annotations

from pathlib import Path

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


@app.command()
def audit(path: str) -> None:
    """Run the full audit (all enabled checks) against a target repo."""
    raise NotImplementedError("audit() — implement in agent.py")


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
