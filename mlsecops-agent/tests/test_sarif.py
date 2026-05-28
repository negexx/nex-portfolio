"""Tests for the SARIF 2.1.0 renderer.

The renderer must be deterministic, schema-valid (top-level keys + per-result
shape), and round-trip cleanly through ``json.loads``.
"""

from __future__ import annotations

import json
from pathlib import Path

from mlsecops_agent.models import (
    CheckName,
    CheckResult,
    Finding,
    FixProposal,
    Severity,
)
from mlsecops_agent.reporting import render_sarif


def _finding(
    rule_id: str = "deserialization.unsafe-joblib-load",
    check: CheckName = CheckName.DESERIALIZATION,
    severity: Severity = Severity.HIGH,
    file: Path | None = None,
    line_start: int = 42,
    line_end: int = 42,
) -> Finding:
    return Finding(
        id=rule_id,
        check=check,
        severity=severity,
        category="insecure-deserialization",
        file=file or Path("notebook.ipynb"),
        line_start=line_start,
        line_end=line_end,
        message="`joblib.load` of an untrusted artifact is RCE-equivalent.",
        evidence="joblib.load('model.pkl')",
        fix=FixProposal(
            summary="Use safetensors or verify a SHA-256 manifest before loading.",
            confidence="high",
        ),
    )


def test_render_produces_sarif_2_1_envelope() -> None:
    result = CheckResult(check=CheckName.DESERIALIZATION, findings=[_finding()], duration_ms=10)
    doc = json.loads(render_sarif([result]))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list)
    assert len(doc["runs"]) == 1


def test_each_unique_rule_appears_once_in_driver_rules() -> None:
    f1 = _finding(rule_id="deserialization.unsafe-joblib-load")
    f2 = _finding(rule_id="deserialization.unsafe-joblib-load", line_start=99)
    f3 = _finding(rule_id="leakage.label-proxy-feature", check=CheckName.LEAKAGE)
    result = CheckResult(
        check=CheckName.DESERIALIZATION,
        findings=[f1, f2, f3],
        duration_ms=10,
    )
    doc = json.loads(render_sarif([result]))
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(set(rule_ids)), "rules must be deduplicated"
    assert "deserialization.unsafe-joblib-load" in rule_ids
    assert "leakage.label-proxy-feature" in rule_ids


def test_severity_maps_to_sarif_level_and_security_severity() -> None:
    high = _finding(severity=Severity.HIGH)
    medium = _finding(severity=Severity.MEDIUM, rule_id="supply_chain.unpinned-pip-install")
    info = _finding(severity=Severity.INFO, rule_id="info.demo")
    result = CheckResult(
        check=CheckName.SUPPLY_CHAIN, findings=[high, medium, info], duration_ms=5
    )
    doc = json.loads(render_sarif([result]))
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}

    assert results["deserialization.unsafe-joblib-load"]["level"] == "error"
    assert results["supply_chain.unpinned-pip-install"]["level"] == "warning"
    assert results["info.demo"]["level"] == "note"

    # security-severity (GitHub convention) on each result
    assert (
        results["deserialization.unsafe-joblib-load"]["properties"]["security-severity"] == "7.5"
    )
    assert results["info.demo"]["properties"]["security-severity"] == "2.0"


def test_file_paths_are_relativised_against_target_root(tmp_path: Path) -> None:
    nb = tmp_path / "sub" / "notebook.ipynb"
    nb.parent.mkdir(parents=True)
    nb.write_text("{}", encoding="utf-8")
    f = _finding(file=nb)
    result = CheckResult(check=CheckName.DESERIALIZATION, findings=[f], duration_ms=1)
    doc = json.loads(render_sarif([result], target_root=tmp_path))

    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "sub/notebook.ipynb", f"expected posix relative uri; got {uri!r}"


def test_fix_proposal_serialised_into_result_fixes() -> None:
    f = _finding()
    result = CheckResult(check=CheckName.DESERIALIZATION, findings=[f], duration_ms=1)
    doc = json.loads(render_sarif([result]))
    fixes = doc["runs"][0]["results"][0]["fixes"]
    assert len(fixes) == 1
    assert "safetensors" in fixes[0]["description"]["text"]
    assert fixes[0]["properties"]["confidence"] == "high"


def test_render_is_deterministic() -> None:
    f1 = _finding()
    f2 = _finding(rule_id="leakage.fit-on-test", check=CheckName.LEAKAGE)
    result = CheckResult(
        check=CheckName.DESERIALIZATION, findings=[f1, f2], duration_ms=10
    )
    a = render_sarif([result])
    b = render_sarif([result])
    assert a == b, "same input must produce byte-identical output"


def test_empty_results_produces_valid_envelope() -> None:
    doc = json.loads(render_sarif([]))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
