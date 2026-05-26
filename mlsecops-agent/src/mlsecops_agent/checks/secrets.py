"""Secrets check.

Detects two classes of credential exposure that generic SAST tools miss for
ML codebases:

1. Hardcoded high-confidence secrets in source (both ``.py`` files and
   ``.ipynb`` code cells) — matched against a curated set of regex patterns.

2. Secrets that leaked into notebook *outputs* — ML practitioners commonly
   print env-var values, API responses, or DataFrame rows that contain
   credentials, then commit the rendered output.  Same patterns, but findings
   are escalated one severity tier and tagged ``secrets.leaked-in-notebook-output``
   because the secret is now committed to git.

v0.1 uses a pure-regex approach rather than shelling out to ``detect-secrets``
or ``trufflehog``.  Those wrappers are a planned follow-up; the regex layer is
simpler, faster, and avoids the subprocess overhead for the common case.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING

from ..models import CheckName, CheckResult, Finding, FixProposal, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

# Each entry: (rule_id_suffix, compiled_pattern, source_severity).
# Output-cell findings always escalate one tier (HIGH → CRITICAL; MEDIUM → HIGH).
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "openai-api-key",
        re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        Severity.HIGH,
    ),
    (
        "anthropic-api-key",
        re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        Severity.HIGH,
    ),
    (
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
    ),
    (
        "huggingface-token",
        re.compile(r"hf_[A-Za-z0-9]{20,}"),
        Severity.HIGH,
    ),
    (
        "github-token",
        re.compile(r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})"),
        Severity.CRITICAL,
    ),
    (
        "slack-token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        Severity.HIGH,
    ),
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "url-with-credentials",
        # Matches https?://user:password@host — password is the part between
        # the colon and the @ sign (must be non-empty and contain no spaces).
        re.compile(r"https?://[^/\s:@]+:[^/\s@]+@"),
        Severity.HIGH,
    ),
]

# Map suffix → (pattern, severity) for O(1) lookup in parametrize tests.
PATTERN_MAP: dict[str, tuple[re.Pattern[str], Severity]] = {
    suffix: (pat, sev) for suffix, pat, sev in _PATTERNS
}


def _escalate(sev: Severity) -> Severity:
    """Escalate severity by one tier (HIGH → CRITICAL; anything else → CRITICAL)."""
    if sev is Severity.HIGH:
        return Severity.CRITICAL
    if sev is Severity.MEDIUM:
        return Severity.HIGH
    # LOW → MEDIUM; INFO → LOW; CRITICAL stays CRITICAL
    _order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = _order.index(sev)
    return _order[min(idx + 1, len(_order) - 1)]


def _mask(secret: str) -> str:
    """Return a masked representation — first 6 chars + '...' + last 4 chars.

    When the matched string is too short to safely show 10 chars, show only
    first 4 + '...' so the evidence field never contains the full secret.
    """
    if len(secret) <= 10:
        return secret[:4] + "..."
    return secret[:6] + "..." + secret[-4:]


def _line_of(text: str, match_start: int) -> int:
    """1-indexed line number of a character offset within a string."""
    return text.count("\n", 0, match_start) + 1


# ---------------------------------------------------------------------------
# Source scanning (code cells + .py files)
# ---------------------------------------------------------------------------


def _scan_text_for_secrets(
    text: str,
    path: Path,
    line_offset: int = 0,
    *,
    in_output: bool,
) -> list[Finding]:
    """Scan *text* for all known patterns and return findings.

    *line_offset* is added to every computed line number so callers that
    accumulate cell sources can report accurate notebook line numbers.
    *in_output* triggers severity escalation and uses the output rule id.
    """
    findings: list[Finding] = []
    for suffix, pattern, base_severity in _PATTERNS:
        for m in pattern.finditer(text):
            matched = m.group(0)
            line = _line_of(text, m.start()) + line_offset

            if in_output:
                rule_id = "secrets.leaked-in-notebook-output"
                severity = _escalate(base_severity)
                message = (
                    f"Pattern `secrets.{suffix}` matched in a committed notebook output. "
                    "The secret is stored in the notebook's JSON and will be visible in "
                    "git history. Clear all outputs (`nbconvert --clear-output`) and rotate "
                    "the credential immediately."
                )
                fix_summary = (
                    "Run `jupyter nbconvert --clear-output <notebook>` (or use "
                    "`nbstripout`) to remove all outputs before committing. "
                    "Rotate the exposed credential — assume it is compromised."
                )
            else:
                rule_id = f"secrets.{suffix}"
                severity = base_severity
                message = (
                    f"Hardcoded secret matching `secrets.{suffix}` found in source. "
                    "Commit history preserves this value forever. "
                    "Move the credential to an environment variable or a secrets manager "
                    "and rotate it immediately."
                )
                fix_summary = (
                    'Replace the literal with `os.getenv("<VAR_NAME>")`. '
                    "Rotate the exposed credential — assume it is compromised. "
                    "Add a pre-commit hook (e.g. `detect-secrets`) to prevent recurrence."
                )

            findings.append(
                Finding(
                    id=rule_id,
                    check=CheckName.SECRETS,
                    severity=severity,
                    category="credential-exposure",
                    file=path,
                    line_start=line,
                    line_end=line,
                    message=message,
                    evidence=_mask(matched),
                    fix=FixProposal(
                        summary=fix_summary,
                        confidence="high",
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Notebook parsing helpers
# ---------------------------------------------------------------------------


def _iter_notebook_cells(
    data: dict[str, object],
) -> Iterable[tuple[str, list[object]]]:
    """Yield ``(source_text, outputs_list)`` for every code cell in *data*."""
    cells = data.get("cells", [])
    if not isinstance(cells, list):
        return
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        raw = cell.get("source", "")
        if isinstance(raw, list):
            source = "".join(s for s in raw if isinstance(s, str))
        elif isinstance(raw, str):
            source = raw
        else:
            continue
        outputs: list[object] = []
        raw_outputs = cell.get("outputs", [])
        if isinstance(raw_outputs, list):
            outputs = raw_outputs
        yield source, outputs


def _extract_output_texts(outputs: list[object]) -> list[str]:
    """Collect all text content from a cell's output list.

    Handles ``stream`` outputs (``text`` key) and ``display_data`` /
    ``execute_result`` outputs (``data["text/plain"]``, ``data["text/html"]``).
    """
    texts: list[str] = []
    for output in outputs:
        if not isinstance(output, dict):
            continue
        # Stream output: {"output_type": "stream", "text": [...]}
        raw = output.get("text", "")
        if isinstance(raw, list):
            texts.append("".join(s for s in raw if isinstance(s, str)))
        elif isinstance(raw, str) and raw:
            texts.append(raw)
        # Rich output: {"data": {"text/plain": ..., "text/html": ...}}
        data = output.get("data", {})
        if isinstance(data, dict):
            for mime in ("text/plain", "text/html"):
                val = data.get(mime, "")
                if isinstance(val, list):
                    texts.append("".join(s for s in val if isinstance(s, str)))
                elif isinstance(val, str) and val:
                    texts.append(val)
    return texts


def _scan_notebook(path: Path) -> list[Finding]:
    data: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []

    for source, outputs in _iter_notebook_cells(data):
        # Source-code pass
        if source:
            findings.extend(_scan_text_for_secrets(source, path, in_output=False))
        # Output pass (same patterns, escalated severity, different rule id)
        for out_text in _extract_output_texts(outputs):
            if out_text:
                findings.extend(_scan_text_for_secrets(out_text, path, in_output=True))

    return findings


def _scan_py(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    return _scan_text_for_secrets(source, path, in_output=False)


# ---------------------------------------------------------------------------
# Target iterator + public entry point
# ---------------------------------------------------------------------------


def _iter_targets(path: Path) -> Iterable[Path]:
    """Yield ``.py`` and ``.ipynb`` files under *path* (or *path* itself)."""
    if path.is_file():
        yield path
        return
    for pattern in ("**/*.py", "**/*.ipynb"):
        yield from path.glob(pattern)


def run(target: Path) -> CheckResult:
    """Run the secrets check against a file or directory.

    Returns a :class:`~mlsecops_agent.models.CheckResult` whose ``findings``
    list is empty when no secrets are detected.
    """
    started = time.perf_counter()
    findings: list[Finding] = []

    for target_file in _iter_targets(target):
        try:
            if target_file.suffix == ".ipynb":
                findings.extend(_scan_notebook(target_file))
            elif target_file.suffix == ".py":
                findings.extend(_scan_py(target_file))
        except (OSError, json.JSONDecodeError):
            continue

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        check=CheckName.SECRETS,
        findings=findings,
        tool_status="ok",
        duration_ms=elapsed_ms,
    )
