"""SARIF 2.1.0 renderer for mlsecops findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS-standardised
JSON schema for static analysis output. GitHub Code Scanning, Azure DevOps,
JetBrains, and most enterprise security platforms consume it natively, so
emitting SARIF lets the agent integrate without bespoke plumbing.

Output is deterministic: the same ``list[CheckResult]`` always produces
byte-identical bytes (no clock-dependent fields except an explicit
``invocations.endTimeUtc``, which can be pinned by the caller if needed).

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ..models import CheckResult, Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

# SARIF distinguishes the human-facing `level` (error/warning/note/none) from
# the machine-facing `security-severity` score (0.0 - 10.0, GitHub convention).
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "2.0",
    Severity.LOW: "3.5",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}

_TOOL_NAME = "mlsecops-agent"
_TOOL_URI = "https://github.com/negexx/nex-portfolio"


# ---------------------------------------------------------------------------
# Rule descriptor extraction
# ---------------------------------------------------------------------------


def _rule_descriptors(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Deduplicate rules across findings and emit one ``reportingDescriptor`` each.

    SARIF requires every unique rule id to appear in ``tool.driver.rules`` so
    consumers can show rule metadata once and reference it by index from each
    result.
    """
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.id in seen:
            continue
        seen[f.id] = {
            "id": f.id,
            "name": _camel(f.id),
            "shortDescription": {"text": f.category},
            "fullDescription": {
                "text": (
                    f"Detects {f.id}. "
                    "Produced by a deterministic mlsecops-agent check; "
                    "interpret severity using the security-severity property."
                )
            },
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[f.severity],
                "tags": ["security", "ml", f.check.value],
            },
        }
    return sorted(seen.values(), key=lambda r: r["id"])


def _camel(rule_id: str) -> str:
    """Convert ``leakage.label-proxy-feature`` to ``LeakageLabelProxyFeature``.

    SARIF's ``name`` is conventionally a PascalCase short identifier; the dotted
    rule id stays in ``id`` for stable referencing.
    """
    parts = rule_id.replace("-", ".").split(".")
    return "".join(p.capitalize() for p in parts if p)


# ---------------------------------------------------------------------------
# Result mapping
# ---------------------------------------------------------------------------


def _location(finding: Finding, target_root: Path | None) -> dict[str, Any]:
    """Build the SARIF physicalLocation block for a finding.

    The URI is relativised against *target_root* when possible so the report
    is portable across machines (absolute Windows paths are not consumable by
    GitHub Code Scanning).
    """
    path = finding.file
    uri: str
    if target_root is not None:
        try:
            uri = path.resolve().relative_to(target_root.resolve()).as_posix()
        except ValueError:
            uri = path.as_posix()
    else:
        uri = path.as_posix()

    region: dict[str, Any] = {}
    if finding.line_start is not None:
        region["startLine"] = finding.line_start
    if finding.line_end is not None:
        region["endLine"] = finding.line_end
    if finding.evidence:
        region["snippet"] = {"text": finding.evidence[:400]}

    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _result(finding: Finding, target_root: Path | None) -> dict[str, Any]:
    """Build a single SARIF ``result`` object from a Finding."""
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [_location(finding, target_root)],
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "category": finding.category,
            "check": finding.check.value,
        },
    }
    if finding.fix is not None:
        result["fixes"] = [
            {
                "description": {"text": finding.fix.summary},
                "properties": {"confidence": finding.fix.confidence},
            }
        ]
    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def render_sarif(
    results: Iterable[CheckResult],
    *,
    target_root: Path | None = None,
    tool_version: str = "0.2.0",
) -> str:
    """Render a list of CheckResults as a SARIF 2.1.0 JSON document.

    *target_root* — if supplied, finding file paths are relativised against it
    so the report is portable. Pass the same directory the audit ran against.

    *tool_version* — embedded as ``tool.driver.semanticVersion`` so consumers
    can correlate findings with a specific agent build.
    """
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)

    doc: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "informationUri": _TOOL_URI,
                        "semanticVersion": tool_version,
                        "rules": _rule_descriptors(findings),
                    }
                },
                "results": [_result(f, target_root) for f in findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {
                                "descriptor": {"id": f"{r.check.value}.status"},
                                "level": "note",
                                "message": {
                                    "text": (
                                        f"check={r.check.value} "
                                        f"status={r.tool_status} "
                                        f"duration_ms={r.duration_ms}"
                                    )
                                },
                            }
                            for r in results
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False)
