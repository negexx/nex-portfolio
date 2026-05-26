"""Semgrep-based rule runner for ML hygiene patterns.

Invokes ``semgrep scan --config <rules_yml> --json <target>`` as a subprocess
and maps each result to a :class:`~mlsecops_agent.models.Finding` under the
LEAKAGE check namespace.

The runner is a *supplementary* source for :mod:`leakage` — it augments the
libcst AST checks rather than replacing them. Callers are responsible for
deduplicating across both sources.

Graceful degradation: if the semgrep binary is missing, times out, or exits
with a non-zero code for reasons other than "findings found", the function
returns an empty list rather than propagating an exception. This mirrors the
pip-audit pattern in :mod:`supply_chain`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..models import CheckName, Finding, FixProposal, Severity

# Path to the bundled YAML rules relative to *this* file.
# importlib.resources is overkill for a sibling directory within the same
# package — a plain __file__-relative path is simpler and equally reliable.
_RULES_PATH = Path(__file__).parent.parent / "rules" / "ml-hygiene.yml"

_SEMGREP_TIMEOUT_S = 60

# semgrep exit codes: 0 = clean, 1 = findings found, 2+ = error.
# We treat both 0 and 1 as "ran successfully"; the findings list tells the truth.
_SEMGREP_OK_EXIT_CODES = frozenset({0, 1})

# When semgrep is invoked with a local YAML file (rather than a registry id),
# it prefixes rule ids with the file path components joined by dots, e.g.
# "src.mlsecops_agent.rules.ml-hygiene.fit-on-test-arg".  Our rule ids always
# start with this namespace token so we can use it as a split point.
_RULE_NAMESPACE = "ml-hygiene."

# Mapping from semgrep severity strings to our Severity enum.
_SEVERITY_MAP: dict[str, Severity] = {
    "INFO": Severity.INFO,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

# Fix summaries keyed by rule id — extracted here so the parsing logic stays flat.
_FIX_SUMMARIES: dict[str, str] = {
    "ml-hygiene.fit-on-test-arg": (
        "Replace `.fit(X_test)` with `.transform(X_test)`. "
        "Only fit on the training split; apply transform to validation and test splits."
    ),
    "ml-hygiene.fit-transform-on-test-arg": (
        "Replace `.fit_transform(X_test)` with `.transform(X_test)`. "
        "Only fit on the training split; apply transform to validation and test splits."
    ),
    "ml-hygiene.train-test-split-with-shuffle-false": (
        "For time-series splits this may be intentional — add a comment explaining why. "
        "Otherwise, remove `shuffle=False` or add `stratify=y` to preserve class proportions."
    ),
}


def _semgrep_binary() -> str | None:
    """Return the path to the semgrep binary, or None if not installed."""
    return shutil.which("semgrep")


def run_semgrep(target: Path) -> list[Finding]:
    """Invoke semgrep and return a list of Findings.

    Returns an empty list when:
    - semgrep binary is not found on PATH
    - semgrep times out
    - semgrep exits with an unexpected error code
    - the JSON output is malformed

    Never raises.
    """
    binary = _semgrep_binary()
    if binary is None:
        return []

    cmd = [
        binary,
        "scan",
        "--config", str(_RULES_PATH),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        str(target),
    ]

    try:
        completed = subprocess.run(  # noqa: S603 — args built from known binary + validated Path
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_SEMGREP_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if completed.returncode not in _SEMGREP_OK_EXIT_CODES:
        return []

    if not completed.stdout.strip():
        return []

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []

    return _parse_semgrep_output(payload)


def _normalize_rule_id(raw_id: str) -> str:
    """Strip the path prefix semgrep adds when a local YAML file is used as config.

    semgrep turns ``--config path/to/ml-hygiene.yml`` into ids like
    ``path.to.ml-hygiene.fit-on-test-arg``.  We strip everything before the
    first occurrence of ``_RULE_NAMESPACE`` so the id matches the YAML ``id:``
    field exactly.
    """
    idx = raw_id.find(_RULE_NAMESPACE)
    return raw_id[idx:] if idx >= 0 else raw_id


def _parse_semgrep_output(payload: object) -> list[Finding]:
    """Parse a semgrep JSON payload dict and return Findings.

    The semgrep JSON schema (--json) is:
    {
      "results": [
        {
          "check_id": "ml-hygiene.fit-on-test-arg",
          "path": "some/file.py",
          "start": {"line": 10, "col": 4},
          "end": {"line": 10, "col": 30},
          "extra": {
            "lines": "  scaler.fit(X_test)",
            "message": "...",
            "severity": "ERROR"
          }
        }
      ]
    }
    """
    if not isinstance(payload, dict):
        return []

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for item in results:
        finding = _parse_result(item)
        if finding is not None:
            findings.append(finding)

    return findings


def _parse_result(item: object) -> Finding | None:
    """Parse a single semgrep result dict into a Finding, or return None on bad shape."""
    if not isinstance(item, dict):
        return None

    check_id = item.get("check_id")
    path_str = item.get("path")
    start = item.get("start")
    end = item.get("end")
    extra = item.get("extra")

    if not isinstance(check_id, str):
        return None
    check_id = _normalize_rule_id(check_id)
    if not isinstance(path_str, str):
        return None
    if not isinstance(start, dict) or not isinstance(end, dict):
        return None
    if not isinstance(extra, dict):
        return None

    line_start = start.get("line")
    line_end = end.get("line")
    if not isinstance(line_start, int) or not isinstance(line_end, int):
        return None

    evidence = extra.get("lines", "")
    if not isinstance(evidence, str):
        evidence = ""

    raw_severity = extra.get("severity", "WARNING")
    severity = _SEVERITY_MAP.get(
        raw_severity if isinstance(raw_severity, str) else "WARNING",
        Severity.MEDIUM,
    )

    message = extra.get("message", "")
    if not isinstance(message, str):
        message = check_id

    fix_summary = _FIX_SUMMARIES.get(
        check_id,
        "Review the flagged pattern and consult the rule description for remediation guidance.",
    )

    return Finding(
        id=check_id,
        check=CheckName.LEAKAGE,
        severity=severity,
        category="data-leakage",
        file=Path(path_str),
        line_start=line_start,
        line_end=line_end,
        message=message.strip(),
        evidence=evidence.strip(),
        fix=FixProposal(
            summary=fix_summary,
            confidence="medium",
        ),
    )
