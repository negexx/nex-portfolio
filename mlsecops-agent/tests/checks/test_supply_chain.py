"""Tests for the supply_chain check.

Fixture pair pattern: one notebook that *must* produce findings, one that
*must not*. The same pair will feed the eval harness once it exists.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mlsecops_agent.checks import supply_chain
from mlsecops_agent.models import CheckName, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "supply_chain"


def _disable_cve(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the CVE-side subprocess from actually executing in a single test.

    pip-audit hits a live vulnerability database — non-deterministic, slow,
    and online. Tests that don't care about CVE behaviour call this; the
    CVE-specific tests below inject canned subprocess output instead.
    """
    monkeypatch.setattr(supply_chain, "_scan_requirements_for_cves", lambda _path: [])


def test_positive_fixture_flags_unpinned_pip_and_untrusted_wget() -> None:
    result = supply_chain.run(FIXTURES / "positive_unpinned_pip.ipynb")

    assert result.check is CheckName.SUPPLY_CHAIN
    assert result.tool_status == "ok"

    ids = sorted({f.id for f in result.findings})
    assert "supply_chain.unpinned-pip-install" in ids
    assert "supply_chain.untrusted-wget-source" in ids

    # Exactly one unpinned spec ("imbalanced-learn -q" → "imbalanced-learn"),
    # not the pinned numpy==1.26.4 sitting next to it.
    pip_findings = [f for f in result.findings if f.id == "supply_chain.unpinned-pip-install"]
    assert len(pip_findings) == 1
    assert "imbalanced-learn" in pip_findings[0].evidence
    assert "numpy" not in pip_findings[0].evidence

    for f in result.findings:
        assert f.severity is Severity.MEDIUM
        assert f.line_start is not None
        assert f.fix is not None


def test_negative_fixture_is_clean() -> None:
    result = supply_chain.run(FIXTURES / "negative_pinned_pip.ipynb")

    assert result.tool_status == "ok"
    assert result.findings == [], (
        "negative fixture should not produce findings; got: "
        + ", ".join(f.id for f in result.findings)
    )


def test_requirements_txt_unpinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _disable_cve(monkeypatch)
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment, should be ignored\n"
        "numpy==1.26.4\n"
        "scikit-learn\n"
        "torch>=2.0\n"
        "\n"
        "-r other-requirements.txt\n",
        encoding="utf-8",
    )

    result = supply_chain.run(tmp_path)

    ids = [f.id for f in result.findings]
    assert ids == ["supply_chain.unpinned-requirement"]
    assert "scikit-learn" in result.findings[0].evidence


def test_missing_file_produces_no_findings(tmp_path: Path) -> None:
    result = supply_chain.run(tmp_path)  # empty dir
    assert result.findings == []
    assert result.tool_status == "ok"


@pytest.mark.parametrize(
    "spec, pinned",
    [
        ("numpy==1.26.4", True),
        ("numpy", False),
        ("numpy>=1.26", True),
        ("numpy~=1.26", True),
        ("numpy @ git+https://github.com/numpy/numpy", True),
        ("git+https://github.com/x/y@abc123", True),
    ],
)
def test_is_pinned(spec: str, pinned: bool) -> None:
    assert supply_chain._is_pinned(spec) is pinned


# --- pip-audit CVE side --------------------------------------------------


def _canned_pip_audit_response() -> str:
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.6.0",
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "fix_versions": ["2.20.0"],
                            "description": "Header injection vulnerability in requests",
                        }
                    ],
                },
                {
                    "name": "numpy",
                    "version": "1.26.4",
                    "vulns": [],
                },
            ]
        }
    )


def test_pip_audit_parses_canned_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=0,
            stdout=_canned_pip_audit_response(),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.6.0\nnumpy==1.26.4\n", encoding="utf-8")

    result = supply_chain.run(tmp_path)

    cve_findings = [f for f in result.findings if f.id == "supply_chain.known-cve"]
    assert len(cve_findings) == 1
    assert "requests" in cve_findings[0].evidence
    assert "GHSA-xxxx-yyyy-zzzz" in cve_findings[0].evidence
    assert cve_findings[0].severity is Severity.HIGH
    assert cve_findings[0].fix is not None
    assert "2.20.0" in cve_findings[0].fix.summary


def test_pip_audit_missing_binary_does_not_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("pip-audit not installed")

    monkeypatch.setattr(subprocess, "run", _raise)

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.6.0\n", encoding="utf-8")

    result = supply_chain.run(tmp_path)
    assert result.tool_status == "ok"
    assert not any(f.id == "supply_chain.known-cve" for f in result.findings)


def test_pip_audit_malformed_json_returns_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=list(args), returncode=0, stdout="not json at all", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.6.0\n", encoding="utf-8")

    result = supply_chain.run(tmp_path)
    assert not any(f.id == "supply_chain.known-cve" for f in result.findings)
