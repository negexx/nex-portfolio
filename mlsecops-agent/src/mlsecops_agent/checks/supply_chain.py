"""Supply-chain check.

Surfaces three classes of issue:

- ``supply_chain.unpinned-pip-install`` — ``!pip install <pkg>`` (or ``%pip install``)
  with no version pin. Notebook installs are the worst offender because they re-resolve
  on every fresh runtime, silently picking up breaking upstream changes.

- ``supply_chain.untrusted-wget-source`` — ``!wget <url>`` / ``!curl <url>`` with no
  visible checksum verification. Common in notebooks for "download the dataset" — a
  classic supply-chain weak spot when the URL is mutable (raw GitHub, S3, gist).

- ``supply_chain.unpinned-requirement`` — lines in a ``requirements.txt`` (or
  ``requirements*.txt``) without an exact version pin.

Detection is pure-Python so the check has zero external runtime dependencies.
``pip-audit`` integration (CVE database lookups) is a planned follow-up; it activates
when the target ships a ``requirements.txt`` or ``pyproject.toml``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from ..models import CheckName, CheckResult, Finding, FixProposal, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

# A package spec is "pinned" when it includes one of these operators OR a direct
# reference (git+, http, file://, local path). We're permissive — we only want
# to flag the obvious "give me the latest of whatever" case.
_PINNED_PATTERNS = (
    "==", "===", "~=", ">=", "<=", ">", "<", "@", "git+", "http://", "https://",
)

# Strip leading shell flags so `-q my-pkg` is parsed as just `my-pkg`.
_PIP_FLAG_RE = re.compile(r"^(-{1,2}[A-Za-z][\w-]*)(=\S+)?$")

# Notebook cell line that invokes pip install via the IPython escape.
_PIP_LINE_RE = re.compile(
    r"^[ \t]*[!%]pip(?:[ \t]+(?:install|--quiet|-q))+[ \t]+(?P<rest>.+?)[ \t]*$",
    re.MULTILINE,
)

# Notebook cell line that downloads a file from the network.
_WGET_LINE_RE = re.compile(
    r"^[ \t]*![ \t]*(?P<tool>wget|curl)\b[ \t]*(?P<rest>.+?)[ \t]*$",
    re.MULTILINE,
)

# Tokens we'd accept as evidence that someone is verifying the download.
_CHECKSUM_HINTS = ("sha256", "sha512", "md5sum", "shasum", "sha256sum", "hashlib")


def _split_pip_args(rest: str) -> list[str]:
    """Return the package specs from a pip install command line, ignoring flags."""
    parts: list[str] = []
    for raw in rest.split():
        if raw.startswith("#"):  # inline comment
            break
        if _PIP_FLAG_RE.match(raw):
            continue
        parts.append(raw)
    return parts


def _is_pinned(spec: str) -> bool:
    return any(token in spec for token in _PINNED_PATTERNS)


def _line_of(source: str, match_start: int) -> int:
    """1-indexed line number of a regex match within a cell's source."""
    return source.count("\n", 0, match_start) + 1


def _iter_notebook_cells(path: Path) -> Iterable[tuple[int, str]]:
    """Yield ``(cell_index, source)`` for every code cell in a notebook.

    We parse the notebook as plain JSON rather than going through ``nbformat`` —
    we don't need validation, we just need the cell sources, and avoiding the
    dep keeps the check trivially fast and typed end-to-end.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    cells = data.get("cells", [])
    if not isinstance(cells, list):
        return
    for idx, cell in enumerate(cells):
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        if isinstance(source, list):
            source = "".join(s for s in source if isinstance(s, str))
        elif not isinstance(source, str):
            continue
        yield idx, source


def _scan_notebook(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    all_sources: list[str] = []

    for idx, src in _iter_notebook_cells(path):
        all_sources.append(src)
        for m in _PIP_LINE_RE.finditer(src):
            rest = m.group("rest")
            for spec in _split_pip_args(rest):
                if _is_pinned(spec):
                    continue
                line = _line_of(src, m.start())
                findings.append(
                    Finding(
                        id="supply_chain.unpinned-pip-install",
                        check=CheckName.SUPPLY_CHAIN,
                        severity=Severity.MEDIUM,
                        category="dependency-pinning",
                        file=path,
                        line_start=line,
                        line_end=line,
                        message=(
                            f"`!pip install {spec}` has no version pin "
                            f"(cell {idx}). Re-runs may install a different "
                            "version and silently break the pipeline."
                        ),
                        evidence=m.group(0).strip(),
                        fix=FixProposal(
                            summary=(
                                f"Pin `{spec}` to a known-good version: "
                                f"`!pip install {spec}==X.Y.Z` and record it in "
                                "requirements.txt / pyproject.toml."
                            ),
                            confidence="high",
                        ),
                    )
                )

    # Second pass: !wget / !curl. We need the *whole* notebook to check for a
    # nearby checksum, so we look across all collected sources.
    combined = "\n".join(all_sources)
    has_checksum = any(hint in combined for hint in _CHECKSUM_HINTS)

    for idx, src in _iter_notebook_cells(path):
        for m in _WGET_LINE_RE.finditer(src):
            if has_checksum:
                continue
            tool = m.group("tool")
            line = _line_of(src, m.start())
            findings.append(
                Finding(
                    id="supply_chain.untrusted-wget-source",
                    check=CheckName.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    category="download-integrity",
                    file=path,
                    line_start=line,
                    line_end=line,
                    message=(
                        f"`!{tool}` downloads content with no checksum verification "
                        f"anywhere in the notebook (cell {idx}). If the upstream "
                        "source changes, your pipeline runs on different bytes."
                    ),
                    evidence=m.group(0).strip(),
                    fix=FixProposal(
                        summary=(
                            f"After the `{tool}`, verify the file: "
                            "`!sha256sum <file>` and assert against an expected digest."
                        ),
                        confidence="medium",
                    ),
                )
            )

    return findings


def _scan_requirements(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if _is_pinned(line):
            continue
        findings.append(
            Finding(
                id="supply_chain.unpinned-requirement",
                check=CheckName.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                category="dependency-pinning",
                file=path,
                line_start=lineno,
                line_end=lineno,
                message=(
                    f"`{line}` in {path.name} has no version pin. "
                    "Lockfile/exact-pin so rebuilds are reproducible."
                ),
                evidence=raw,
                fix=FixProposal(
                    summary=f"Pin to a tested version: `{line}==X.Y.Z`.",
                    confidence="high",
                ),
            )
        )
    return findings


_PIP_AUDIT_TIMEOUT_S = 60


def _pip_audit_binary() -> str | None:
    """Resolve pip-audit's invocation. Prefer the binary, fall back to module form."""
    direct = shutil.which("pip-audit")
    if direct:
        return direct
    # Module form is the resilient fallback — pip-audit ships as a project dep.
    return None


def _scan_requirements_for_cves(path: Path) -> list[Finding]:
    """Run `pip-audit -r <path>` and emit one Finding per advisory.

    Silently no-ops if pip-audit is unavailable, errors, or times out — the
    deterministic pinning rule already ran and we don't want to fail the
    whole check on a CVE-database hiccup.
    """
    binary = _pip_audit_binary()
    cmd: list[str]
    if binary:
        cmd = [binary, "--requirement", str(path), "--format", "json", "--progress-spinner", "off"]
    else:
        cmd = [
            "python", "-m", "pip_audit",
            "--requirement", str(path),
            "--format", "json",
            "--progress-spinner", "off",
        ]

    try:
        completed = subprocess.run(  # noqa: S603 — args are constructed from a known binary + Path
            cmd,
            capture_output=True,
            text=True,
            timeout=_PIP_AUDIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if not completed.stdout.strip():
        return []

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []

    dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else []
    findings: list[Finding] = []
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "<unknown>")
        version = dep.get("version", "<unknown>")
        vulns = dep.get("vulns", []) or []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vid = vuln.get("id", "UNKNOWN")
            fix_versions = vuln.get("fix_versions", []) or []
            description = (vuln.get("description") or "").strip() or (
                "see advisory for details."
            )
            findings.append(
                Finding(
                    id="supply_chain.known-cve",
                    check=CheckName.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    category="known-vulnerability",
                    file=path,
                    line_start=None,
                    line_end=None,
                    message=(
                        f"`{name}=={version}` is affected by {vid}: "
                        f"{description[:200]}"
                    ),
                    evidence=f"{name}=={version} -> {vid}",
                    fix=FixProposal(
                        summary=(
                            f"Upgrade `{name}` to {', '.join(fix_versions) or 'a patched release'}."
                        ),
                        confidence="high",
                    ),
                )
            )
    return findings


def _iter_targets(path: Path) -> Iterable[Path]:
    """Yield files to scan for the given target path."""
    if path.is_file():
        yield path
        return
    for pattern in ("**/*.ipynb", "**/requirements*.txt"):
        yield from path.glob(pattern)


def run(target: Path) -> CheckResult:
    """Run the supply-chain check against a file or directory.

    The agent's RunContext is intentionally not required here — this check is
    self-contained and pure-Python so it can be invoked from the CLI directly,
    from the agent loop, or from tests.
    """
    started = time.perf_counter()
    findings: list[Finding] = []

    for target_file in _iter_targets(target):
        try:
            if target_file.suffix == ".ipynb":
                findings.extend(_scan_notebook(target_file))
            elif target_file.name.startswith("requirements") and target_file.suffix == ".txt":
                findings.extend(_scan_requirements(target_file))
                findings.extend(_scan_requirements_for_cves(target_file))
        except (OSError, json.JSONDecodeError):
            continue

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        check=CheckName.SUPPLY_CHAIN,
        findings=findings,
        tool_status="ok",
        duration_ms=elapsed_ms,
    )
