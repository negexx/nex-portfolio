"""Typer entry point.

Currently wired commands:

- ``mlsecops check <name> <path>`` — run a single check.
- ``mlsecops audit <path>`` — run every registered check, aggregate findings.
  Pass ``--with-llm`` to drive the run through the DeepSeek-orchestrated agent
  loop instead of the deterministic per-check fan-out.

``eval`` lands with the fixture-eval harness (W2.3).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .agent import AuditTranscript, run_audit_with_agent
from .checks import CHECKS
from .eval import run_eval, write_baseline
from .llm import LLMProvider, LLMProviderError, MockLLMProvider
from .models import CheckName, CheckResult, Finding, Severity
from .reporting import render_markdown
from .storage import Repository

# Module-level seam so tests can swap in a MockLLMProvider without touching env.
# A non-None value here takes precedence over building a real LLMProvider.
_LLM_PROVIDER_OVERRIDE: LLMProvider | MockLLMProvider | None = None


def set_llm_provider_override(provider: LLMProvider | MockLLMProvider | None) -> None:
    """Inject (or clear) the provider used by ``audit --with-llm``.

    Intended for tests — production code instantiates ``LLMProvider()`` from
    environment variables.
    """
    global _LLM_PROVIDER_OVERRIDE
    _LLM_PROVIDER_OVERRIDE = provider


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
            raise typer.BadParameter(f"unknown check '{name}'. Valid: {valid}") from exc
        if check_name not in CHECKS:
            raise typer.BadParameter(f"check '{name}' is declared but not yet implemented.")
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
    include_adversarial: Annotated[
        bool,
        typer.Option(
            "--include-adversarial",
            help=(
                "Opt in to the adversarial check. Loads saved Keras models in the "
                "target dir and runs FGSM evasion attacks. Requires TensorFlow + ART."
            ),
        ),
    ] = False,
    with_llm: Annotated[
        bool,
        typer.Option(
            "--with-llm",
            help=(
                "Drive the audit through the DeepSeek-orchestrated agent loop. "
                "Requires DEEPSEEK_API_KEY in the environment unless a provider "
                "override has been set (tests only)."
            ),
        ),
    ] = False,
    persist: Annotated[
        Path | None,
        typer.Option(
            "--persist",
            help=(
                "Persist this run + findings to a SQLite DB at the given path. "
                "View past runs with `mlsecops history list/show`."
            ),
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

    if with_llm:
        _run_audit_with_llm(target, persist=persist, report=report)
        return

    selected = _resolve_checks(only or [])
    if not selected:
        _console.print("[yellow]no checks are currently registered.[/yellow]")
        raise typer.Exit(code=0)

    results: list[CheckResult] = []
    for check_name in selected:
        runner = CHECKS[check_name]
        if check_name is CheckName.ADVERSARIAL:
            results.append(runner(target, include_adversarial=include_adversarial))
        else:
            results.append(runner(target))

    _render_summary(results)
    for r in results:
        if r.findings:
            _console.print()
            _render(r)

    if report is not None:
        report.write_text(render_markdown(results, target=target), encoding="utf-8")
        _console.print(f"\n[dim]Markdown report written to[/dim] [bold]{report}[/bold]")

    if persist is not None:
        repo = Repository(persist)
        run_id = repo.record_run(target=str(target), results=results, invocation="cli")
        _console.print(f"[dim]Persisted run[/dim] [bold]{run_id}[/bold] [dim]to[/dim] {persist}")

    if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for r in results for f in r.findings):
        raise typer.Exit(code=1)


history_app = typer.Typer(name="history", help="View persisted audit runs.", no_args_is_help=True)
app.add_typer(history_app, name="history")


@history_app.command("list")
def history_list(
    db: Annotated[
        Path,
        typer.Argument(help="Path to the SQLite DB written by `audit --persist`."),
    ],
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, max=200)] = 20,
) -> None:
    """List the most recent audit runs in this DB."""
    if not db.exists():
        raise typer.BadParameter(f"db not found: {db}")
    repo = Repository(db)
    rows = repo.list_runs(limit=limit)
    if not rows:
        _console.print("[yellow]no runs recorded yet.[/yellow]")
        return
    table = Table(title="[bold]mlsecops history[/bold]", show_lines=False)
    table.add_column("Run ID", no_wrap=True)
    table.add_column("Started", no_wrap=True)
    table.add_column("Target", overflow="fold")
    table.add_column("Findings", justify="right")
    table.add_column("Max sev", no_wrap=True)
    table.add_column("Invocation", no_wrap=True)
    for row in rows:
        max_sev = row.get("max_severity") or "-"
        sev_value = str(max_sev) if max_sev != "-" else max_sev
        sev_cell = (
            f"[{_SEVERITY_STYLE.get(Severity(sev_value), 'dim')}]{sev_value}[/]"
            if sev_value in {s.value for s in Severity}
            else sev_value
        )
        table.add_row(
            str(row["run_id"])[:12],
            str(row["started_at"]),
            str(row["target"]),
            str(row["total_findings"]),
            sev_cell,
            str(row["invocation"]),
        )
    _console.print(table)


@history_app.command("show")
def history_show(
    db: Annotated[Path, typer.Argument(help="Path to the SQLite DB.")],
    run_id: Annotated[str, typer.Argument(help="Run ID (or unique prefix).")],
) -> None:
    """Show full findings for one persisted run."""
    if not db.exists():
        raise typer.BadParameter(f"db not found: {db}")
    repo = Repository(db)
    # Allow prefix match for convenience.
    runs = [r for r in repo.list_runs(limit=200) if str(r["run_id"]).startswith(run_id)]
    if not runs:
        raise typer.BadParameter(f"no run matches '{run_id}'")
    if len(runs) > 1:
        ids = ", ".join(str(r["run_id"])[:12] for r in runs)
        raise typer.BadParameter(f"prefix '{run_id}' matches multiple runs: {ids}")
    full_id = str(runs[0]["run_id"])
    findings = repo.findings_for_run(full_id)

    _console.print(f"[bold]Run {full_id}[/bold] — {len(findings)} finding(s)")
    if not findings:
        return

    table = Table(show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", no_wrap=True)
    table.add_column("Message")
    for f in findings:
        loc = str(f.file)
        if f.line_start is not None:
            loc = f"{loc}:{f.line_start}"
        table.add_row(
            f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]",
            f.id,
            loc,
            f.message,
        )
    _console.print(table)


def _resolve_llm_provider() -> LLMProvider | MockLLMProvider:
    if _LLM_PROVIDER_OVERRIDE is not None:
        return _LLM_PROVIDER_OVERRIDE
    if not os.environ.get("DEEPSEEK_API_KEY"):
        _console.print(
            "[red]DEEPSEEK_API_KEY is not set.[/red] "
            "Copy `.env.example` to `.env.local` and add your key, "
            "or export it in your shell."
        )
        raise typer.Exit(code=1)
    return LLMProvider()


def _render_transcript(transcript: AuditTranscript) -> None:
    _console.rule("[bold]LLM executive summary[/bold]")
    if transcript.final_summary:
        _console.print(transcript.final_summary)
    else:
        hit_cap = transcript.hit_iteration_cap
        _console.print(
            "[yellow]Agent stopped without producing a final summary "
            f"(iterations={transcript.iterations}, hit_cap={hit_cap}).[/yellow]"
        )

    deterministic = list(_results_from_transcript(transcript))
    if deterministic:
        _console.print()
        _render_summary(deterministic)
        for r in deterministic:
            if r.findings:
                _console.print()
                _render(r)

    if transcript.fix_proposals:
        _console.print()
        _console.rule("[bold]LLM-authored fix narratives[/bold]")
        for proposal in transcript.fix_proposals:
            location = proposal.file
            if proposal.line_start is not None:
                location = f"{location}:{proposal.line_start}"
            _console.print(
                f"- [bold]{proposal.rule_id}[/bold] at [dim]{location}[/dim]\n"
                f"  {proposal.narrative}"
            )


def _results_from_transcript(transcript: AuditTranscript) -> list[CheckResult]:
    """Reconstruct CheckResult-like rows from the transcript's findings.

    The agent stores raw Findings rather than CheckResults so the summary
    table needs us to bucket them by check. ``duration_ms`` is reported as 0
    here because the per-check timing already lives in the markdown report
    rendered alongside; reusing the summary table is the value, not the time.
    """
    by_check: dict[CheckName, list[Finding]] = {c: [] for c in CheckName}
    for f in transcript.findings:
        by_check.setdefault(f.check, []).append(f)
    return [
        CheckResult(check=check, findings=findings, tool_status="ok", duration_ms=0)
        for check, findings in by_check.items()
        if findings
    ]


def _run_audit_with_llm(
    target: Path,
    *,
    persist: Path | None = None,
    report: Path | None = None,
) -> None:
    provider = _resolve_llm_provider()
    try:
        transcript = run_audit_with_agent(target, provider=provider)
    except LLMProviderError as exc:
        _console.print(f"[red]LLM provider error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render_transcript(transcript)

    deterministic = list(_results_from_transcript(transcript))

    if report is not None:
        report.write_text(render_markdown(deterministic, target=target), encoding="utf-8")
        _console.print(f"\n[dim]Markdown report written to[/dim] [bold]{report}[/bold]")

    if persist is not None:
        repo = Repository(persist)
        run_id = repo.record_run(
            target=str(target),
            results=deterministic,
            invocation="agent",
            extra={"iterations": str(transcript.iterations)},
        )
        _console.print(f"[dim]Persisted run[/dim] [bold]{run_id}[/bold] [dim]to[/dim] {persist}")

    if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in transcript.findings):
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
        raise typer.BadParameter(f"check '{name}' is declared but not yet implemented in v0.1.")

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
        _console.print(f"\n[red]Recall below {min_recall} for: {names}[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
