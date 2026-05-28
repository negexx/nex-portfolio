"""Cross-check risk-scenario synthesis.

Individual findings are useful but a real attacker chains them. This module
takes a flat ``list[Finding]`` and matches it against named threat scenarios:
each scenario is a set of *required* and optional *amplifier* finding IDs.
When all required IDs are present the scenario triggers and gets reported at
its baseline severity (raised one level for every amplifier present).

Scenarios are intentionally conservative — the rule of thumb is "a security
engineer would write this same chain on a whiteboard given the same findings."
We don't fabricate risk, only synthesise what's already evidenced.

Each scenario produces a :class:`~mlsecops_agent.models.Finding` so it flows
through the standard reporting pipeline (Markdown, SARIF) without special
casing. The scenario's ``check`` field is set to the most relevant pillar.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import CheckName, Finding, FixProposal, Severity

_SEVERITY_LADDER: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _bump(severity: Severity, steps: int) -> Severity:
    idx = _SEVERITY_LADDER.index(severity)
    return _SEVERITY_LADDER[min(idx + steps, len(_SEVERITY_LADDER) - 1)]


@dataclass(frozen=True)
class Scenario:
    """Named multi-finding threat pattern.

    *required*: every id in this set must be present in the audit's findings
    for the scenario to trigger.
    *amplifiers*: each id present adds one severity step (capped at CRITICAL).
    *check*: pillar to attribute the synthesised finding to.
    """

    id: str
    name: str
    required: frozenset[str]
    amplifiers: frozenset[str]
    baseline_severity: Severity
    check: CheckName
    narrative: str
    fix: str


_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="scenario.supply-chain-to-rce",
        name="Supply-chain compromise → arbitrary code execution",
        required=frozenset(
            {
                "supply_chain.untrusted-wget-source",
                "deserialization.unsafe-joblib-load",
            }
        ),
        amplifiers=frozenset(
            {
                "supply_chain.unpinned-pip-install",
                "deserialization.unsafe-pickle-load",
                "deserialization.unsafe-torch-load",
            }
        ),
        baseline_severity=Severity.HIGH,
        check=CheckName.SCENARIO,
        narrative=(
            "Untrusted download + unsafe deserialisation = full attack chain. "
            "An attacker who controls the wget source can ship a malicious "
            "pickle/joblib payload; the unverified load executes their code on "
            "every machine that runs the notebook. The two findings are "
            "individually 'medium' / 'high' but the *chain* is critical."
        ),
        fix=(
            "Pin the download to a checksum (SHA-256 manifest beside the URL) "
            "AND switch the load to a safe format (safetensors / ONNX / JSON). "
            "Either fix alone leaves the chain partially intact."
        ),
    ),
    Scenario(
        id="scenario.label-leakage-to-inflated-metrics",
        name="Label leakage → inflated evaluation metrics",
        required=frozenset(
            {
                "leakage.label-proxy-feature",
            }
        ),
        amplifiers=frozenset(
            {
                "leakage.preprocessing-before-split",
                "leakage.fit-on-test",
                "ml-hygiene.fit-on-test-arg",
            }
        ),
        baseline_severity=Severity.HIGH,
        check=CheckName.SCENARIO,
        narrative=(
            "Label-proxy features combined with sloppy split discipline "
            "produce evaluation metrics that look great in the notebook and "
            "collapse on deployment. Every additional finding here multiplies "
            "the gap between reported and real performance."
        ),
        fix=(
            "Drop the label proxy, move every fit/fit_transform/fit_resample "
            "to after train_test_split, and rerun evaluation. Expect a real "
            "F1 drop — that's the correct number."
        ),
    ),
    Scenario(
        id="scenario.evadable-classifier-in-production",
        name="Evadable classifier shipped as a control",
        required=frozenset(
            {
                "adversarial.fgsm-trivial-evasion",
            }
        ),
        amplifiers=frozenset(
            {
                "supply_chain.untrusted-wget-source",
                "deserialization.unsafe-joblib-load",
                "leakage.preprocessing-before-split",
            }
        ),
        baseline_severity=Severity.HIGH,
        check=CheckName.SCENARIO,
        narrative=(
            "A classifier whose predictions flip under small-norm perturbations "
            "is not a security control — it is a placebo. If the pipeline also "
            "has supply-chain or leakage issues the situation is worse: the "
            "evaluation metrics that justified shipping it were already lying."
        ),
        fix=(
            "Apply adversarial training (FGSM or PGD with eps matched to the "
            "deployment threat model), then re-run the robustness sweep. The "
            "target is < 30 % flip rate at the highest eps you care about."
        ),
    ),
)


def synthesise_scenarios(findings: list[Finding]) -> list[Finding]:
    """Match findings against known scenarios and return synthesised Findings.

    Each match emits one ``Finding`` with id ``scenario.<slug>`` and severity
    determined by baseline + amplifier count. Empty list when nothing matches.
    """
    if not findings:
        return []

    fired_ids: set[str] = {f.id for f in findings}
    matches: list[Finding] = []

    for scen in _SCENARIOS:
        if not scen.required.issubset(fired_ids):
            continue

        amplifier_hits = scen.amplifiers & fired_ids
        severity = _bump(scen.baseline_severity, len(amplifier_hits))

        # Point the scenario finding at the file of any of its required findings
        # — usually the notebook under audit — so report renderers can position it.
        anchor: Path | None = None
        for f in findings:
            if f.id in scen.required:
                anchor = f.file
                break
        if anchor is None:
            anchor = Path("<aggregate>")

        evidence_lines = sorted({f.id for f in findings if f.id in scen.required | scen.amplifiers})
        matches.append(
            Finding(
                id=scen.id,
                check=scen.check,
                severity=severity,
                category="threat-scenario",
                file=anchor,
                line_start=None,
                line_end=None,
                message=(
                    f"{scen.name}. {scen.narrative} (amplifiers triggered: {len(amplifier_hits)})"
                ),
                evidence="chained findings: " + ", ".join(evidence_lines),
                fix=FixProposal(summary=scen.fix, confidence="high"),
            )
        )

    return matches
