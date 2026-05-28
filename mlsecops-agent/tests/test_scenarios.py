"""Tests for the cross-check scenario synthesis layer."""

from __future__ import annotations

from pathlib import Path

from mlsecops_agent.models import CheckName, Finding, Severity
from mlsecops_agent.scenarios import synthesise_scenarios


def _f(rule_id: str, check: CheckName, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=rule_id,
        check=check,
        severity=severity,
        category="test",
        file=Path("notebook.ipynb"),
        line_start=1,
        line_end=1,
        message=rule_id,
        evidence=rule_id,
    )


# ---------------------------------------------------------------------------
# supply-chain-to-rce scenario
# ---------------------------------------------------------------------------


def test_supply_chain_to_rce_fires_on_full_chain() -> None:
    findings = [
        _f("supply_chain.untrusted-wget-source", CheckName.SUPPLY_CHAIN, Severity.MEDIUM),
        _f("deserialization.unsafe-joblib-load", CheckName.DESERIALIZATION),
    ]
    out = synthesise_scenarios(findings)
    ids = [f.id for f in out]
    assert "scenario.supply-chain-to-rce" in ids


def test_supply_chain_to_rce_does_not_fire_with_only_wget() -> None:
    findings = [_f("supply_chain.untrusted-wget-source", CheckName.SUPPLY_CHAIN, Severity.MEDIUM)]
    out = synthesise_scenarios(findings)
    assert out == []


def test_supply_chain_to_rce_does_not_fire_with_only_joblib() -> None:
    findings = [_f("deserialization.unsafe-joblib-load", CheckName.DESERIALIZATION)]
    out = synthesise_scenarios(findings)
    assert out == []


def test_supply_chain_to_rce_severity_bumps_with_amplifiers() -> None:
    findings = [
        _f("supply_chain.untrusted-wget-source", CheckName.SUPPLY_CHAIN, Severity.MEDIUM),
        _f("deserialization.unsafe-joblib-load", CheckName.DESERIALIZATION),
        # amplifiers
        _f("supply_chain.unpinned-pip-install", CheckName.SUPPLY_CHAIN, Severity.MEDIUM),
        _f("deserialization.unsafe-pickle-load", CheckName.DESERIALIZATION),
    ]
    out = synthesise_scenarios(findings)
    rce = next(f for f in out if f.id == "scenario.supply-chain-to-rce")
    # Baseline HIGH + 2 amplifiers = CRITICAL
    assert rce.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# label-leakage-to-inflated-metrics scenario
# ---------------------------------------------------------------------------


def test_label_leakage_scenario_requires_only_one_finding() -> None:
    findings = [_f("leakage.label-proxy-feature", CheckName.LEAKAGE)]
    out = synthesise_scenarios(findings)
    ids = [f.id for f in out]
    assert "scenario.label-leakage-to-inflated-metrics" in ids


def test_label_leakage_amplified_by_split_violations() -> None:
    findings = [
        _f("leakage.label-proxy-feature", CheckName.LEAKAGE),
        _f("leakage.preprocessing-before-split", CheckName.LEAKAGE),
        _f("leakage.fit-on-test", CheckName.LEAKAGE, Severity.CRITICAL),
    ]
    out = synthesise_scenarios(findings)
    sc = next(f for f in out if f.id == "scenario.label-leakage-to-inflated-metrics")
    assert sc.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# evadable-classifier scenario
# ---------------------------------------------------------------------------


def test_evadable_classifier_scenario_fires_on_fgsm_finding() -> None:
    findings = [_f("adversarial.fgsm-trivial-evasion", CheckName.ADVERSARIAL)]
    out = synthesise_scenarios(findings)
    ids = [f.id for f in out]
    assert "scenario.evadable-classifier-in-production" in ids


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_no_scenarios_on_clean_findings() -> None:
    assert synthesise_scenarios([]) == []


def test_scenario_finding_carries_aggregate_evidence() -> None:
    findings = [
        _f("supply_chain.untrusted-wget-source", CheckName.SUPPLY_CHAIN, Severity.MEDIUM),
        _f("deserialization.unsafe-joblib-load", CheckName.DESERIALIZATION),
    ]
    out = synthesise_scenarios(findings)
    rce = next(f for f in out if f.id == "scenario.supply-chain-to-rce")
    assert "supply_chain.untrusted-wget-source" in rce.evidence
    assert "deserialization.unsafe-joblib-load" in rce.evidence
    assert rce.check is CheckName.SCENARIO
    assert rce.fix is not None
