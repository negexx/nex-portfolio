"""Tests for the secrets check.

Fixture pair pattern mirrors supply_chain / deserialization tests:
- positive fixture must flag >= 5 distinct rule ids
- negative fixture must produce zero findings
- output-leak fixture must produce ``secrets.leaked-in-notebook-output`` at CRITICAL
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mlsecops_agent.checks import secrets
from mlsecops_agent.models import CheckName, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "secrets"

# The real v1 notebook lives one directory above the repo root.
NIDS_V1 = Path(__file__).parent.parent.parent.parent / "nids_v1_baseline.ipynb"


# ---------------------------------------------------------------------------
# Positive fixture — hardcoded secrets in source cells
# ---------------------------------------------------------------------------


def test_positive_fixture_flags_five_or_more_distinct_rules() -> None:
    result = secrets.run(FIXTURES / "positive_hardcoded_secrets.ipynb")

    assert result.check is CheckName.SECRETS
    assert result.tool_status == "ok"

    ids = {f.id for f in result.findings}
    # Must cover at least 5 of the 8 rules
    assert len(ids) >= 5, f"Expected >= 5 distinct rule ids, got: {ids}"


def test_positive_fixture_flags_all_eight_rules() -> None:
    result = secrets.run(FIXTURES / "positive_hardcoded_secrets.ipynb")
    ids = {f.id for f in result.findings}

    expected = {
        "secrets.openai-api-key",
        "secrets.anthropic-api-key",
        "secrets.aws-access-key",
        "secrets.huggingface-token",
        "secrets.github-token",
        "secrets.slack-token",
        "secrets.private-key-block",
        "secrets.url-with-credentials",
    }
    missing = expected - ids
    assert not missing, f"Missing rule ids: {missing}"


def test_positive_fixture_severities() -> None:
    result = secrets.run(FIXTURES / "positive_hardcoded_secrets.ipynb")

    critical_ids = {
        "secrets.aws-access-key",
        "secrets.github-token",
        "secrets.private-key-block",
    }
    high_ids = {
        "secrets.openai-api-key",
        "secrets.anthropic-api-key",
        "secrets.huggingface-token",
        "secrets.slack-token",
        "secrets.url-with-credentials",
    }

    for finding in result.findings:
        if finding.id in critical_ids:
            assert finding.severity is Severity.CRITICAL, (
                f"{finding.id} should be CRITICAL, got {finding.severity}"
            )
        elif finding.id in high_ids:
            assert finding.severity is Severity.HIGH, (
                f"{finding.id} should be HIGH, got {finding.severity}"
            )


def test_positive_fixture_evidence_is_masked() -> None:
    """The full secret must never appear verbatim in the evidence field."""
    result = secrets.run(FIXTURES / "positive_hardcoded_secrets.ipynb")

    assert result.findings, "Expected findings from positive fixture"
    for f in result.findings:
        # Evidence must contain '...' (our masking sentinel)
        assert "..." in f.evidence, f"Evidence for {f.id} does not appear masked: {f.evidence!r}"


def test_positive_fixture_findings_have_required_fields() -> None:
    result = secrets.run(FIXTURES / "positive_hardcoded_secrets.ipynb")

    for finding in result.findings:
        assert finding.line_start is not None, f"{finding.id} missing line_start"
        assert finding.evidence, f"{finding.id} has empty evidence"
        assert finding.fix is not None, f"{finding.id} missing fix"
        assert finding.fix.summary, f"{finding.id} has empty fix.summary"


# ---------------------------------------------------------------------------
# Negative fixture — safe secret handling
# ---------------------------------------------------------------------------


def test_negative_fixture_is_clean() -> None:
    result = secrets.run(FIXTURES / "negative_safe_secret_handling.ipynb")

    assert result.tool_status == "ok"
    assert result.findings == [], "negative fixture should not produce findings; got: " + ", ".join(
        f.id for f in result.findings
    )


# ---------------------------------------------------------------------------
# Output-leak fixture — secret in cell output → leaked-in-notebook-output
# ---------------------------------------------------------------------------


def test_output_leak_fixture_produces_leaked_in_output_finding() -> None:
    result = secrets.run(FIXTURES / "positive_leaked_in_output.ipynb")

    assert result.tool_status == "ok"
    leaked = [f for f in result.findings if f.id == "secrets.leaked-in-notebook-output"]
    assert leaked, (
        "Expected at least one secrets.leaked-in-notebook-output finding; "
        f"got ids: {[f.id for f in result.findings]}"
    )


def test_output_leak_finding_is_critical() -> None:
    result = secrets.run(FIXTURES / "positive_leaked_in_output.ipynb")
    leaked = [f for f in result.findings if f.id == "secrets.leaked-in-notebook-output"]
    assert leaked, "No leaked-in-notebook-output findings"
    for f in leaked:
        assert f.severity is Severity.CRITICAL, (
            f"leaked-in-notebook-output should be CRITICAL, got {f.severity}"
        )


def test_output_leak_evidence_is_masked() -> None:
    result = secrets.run(FIXTURES / "positive_leaked_in_output.ipynb")
    leaked = [f for f in result.findings if f.id == "secrets.leaked-in-notebook-output"]
    assert leaked
    for f in leaked:
        assert "..." in f.evidence, f"Evidence not masked: {f.evidence!r}"


# ---------------------------------------------------------------------------
# Parametrized pattern detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "suffix, sample",
    # Defanged via string concatenation so GitHub's secret-scanner doesn't flag
    # these as committed secrets. Python evaluates each to a single contiguous
    # string at test time; the source bytes contain no scanner-matchable pattern.
    [
        ("openai-api-key", "sk" + "-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
        ("openai-api-key", "sk-proj" + "-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
        ("anthropic-api-key", "sk-ant" + "-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"),
        ("aws-access-key", "AKIA" + "IOSFODNN7EXAMPLE"),
        ("huggingface-token", "hf" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
        ("github-token", "ghp" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"),
        ("github-token", "github_pat" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"),
        ("slack-token", "xox" + "b-123456789012-ABCDEFGHIJKLMN"),
        ("private-key-block", "-----BEGIN RSA PRIVATE KEY-----"),
        ("private-key-block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ("private-key-block", "-----BEGIN PRIVATE KEY-----"),
        ("url-with-credentials", "https://user:password@host.example.com"),
    ],
)
def test_pattern_detects_known_sample(suffix: str, sample: str, tmp_path: Path) -> None:
    """Each pattern must match its canonical sample string."""
    pattern, _ = secrets.PATTERN_MAP[suffix]
    assert pattern.search(sample), f"Pattern for {suffix!r} did not match {sample!r}"


def test_url_without_password_is_not_flagged(tmp_path: Path) -> None:
    """``https://user@host`` has no password field — must not match url-with-credentials."""
    pattern, _ = secrets.PATTERN_MAP["url-with-credentials"]
    assert not pattern.search("https://user@host.example.com"), (
        "url-with-credentials should not match a URL with only a username (no password)"
    )


def test_url_with_credentials_flagged_in_py_file(tmp_path: Path) -> None:
    py = tmp_path / "config.py"
    py.write_text('DB_URL = "https://admin:s3cr3t@db.example.com/prod"\n', encoding="utf-8")
    result = secrets.run(py)
    ids = [f.id for f in result.findings]
    assert "secrets.url-with-credentials" in ids


def test_url_without_password_not_flagged_in_py_file(tmp_path: Path) -> None:
    py = tmp_path / "config.py"
    py.write_text('URL = "https://user@host.example.com"\n', encoding="utf-8")
    result = secrets.run(py)
    assert not any(f.id == "secrets.url-with-credentials" for f in result.findings)


# ---------------------------------------------------------------------------
# Inline construction tests (tmp_path)
# ---------------------------------------------------------------------------


def test_py_file_with_aws_key_is_flagged(tmp_path: Path) -> None:
    py = tmp_path / "train.py"
    py.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    result = secrets.run(py)
    assert any(f.id == "secrets.aws-access-key" for f in result.findings)
    aws_f = next(f for f in result.findings if f.id == "secrets.aws-access-key")
    assert aws_f.severity is Severity.CRITICAL
    assert "..." in aws_f.evidence
    # Full key must not be in evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_f.evidence


def test_empty_directory_produces_no_findings(tmp_path: Path) -> None:
    result = secrets.run(tmp_path)
    assert result.findings == []
    assert result.tool_status == "ok"


def test_notebook_with_output_leak_aws_key(tmp_path: Path) -> None:
    """AWS key appearing only in cell output → CRITICAL leaked-in-notebook-output."""
    nb = tmp_path / "leaked.ipynb"
    nb.write_text(
        '{"nbformat":4,"nbformat_minor":5,"metadata":{},"cells":[{'
        '"cell_type":"code","id":"c0","metadata":{},'
        '"outputs":[{"output_type":"stream","name":"stdout","text":["key=AKIAIOSFODNN7EXAMPLE\\n"]}],'
        '"source":["import os\\n","print(os.getenv(\'AWS_ACCESS_KEY_ID\'))"]}'
        "]}",
        encoding="utf-8",
    )
    result = secrets.run(nb)
    leaked = [f for f in result.findings if f.id == "secrets.leaked-in-notebook-output"]
    assert leaked, f"Expected leaked-in-notebook-output; got {[f.id for f in result.findings]}"
    assert all(f.severity is Severity.CRITICAL for f in leaked)
    # Source is clean — source-cell findings would carry secrets.aws-access-key id
    assert not any(f.id == "secrets.aws-access-key" for f in result.findings)


def test_full_secret_not_in_any_evidence(tmp_path: Path) -> None:
    """End-to-end: no finding's evidence field contains the raw matched secret."""
    nb = tmp_path / "full.ipynb"
    secret = "AKIAIOSFODNN7EXAMPLE"
    nb.write_text(
        f'{{"nbformat":4,"nbformat_minor":5,"metadata":{{}},"cells":[{{'
        f'"cell_type":"code","id":"c0","metadata":{{}},"outputs":[],'
        f'"source":["key = \\"{secret}\\""]'
        f"}}]}}",
        encoding="utf-8",
    )
    result = secrets.run(nb)
    for f in result.findings:
        assert secret not in f.evidence, (
            f"Full secret found verbatim in evidence of {f.id}: {f.evidence!r}"
        )


# ---------------------------------------------------------------------------
# v1 integration smoke test
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not NIDS_V1.exists(),
    reason="nids_v1_baseline.ipynb not present in sibling directory",
)
def test_nids_v1_check_completes_without_crash() -> None:
    """Smoke test: the check must not raise on the real v1 notebook."""
    result = secrets.run(NIDS_V1)
    assert result.tool_status == "ok"
    assert result.check is CheckName.SECRETS
    # Do not assert a specific count — v1 may or may not have secrets.
