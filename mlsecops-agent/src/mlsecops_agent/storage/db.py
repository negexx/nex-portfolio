"""SQLite run-history repository.

Schema (one file, one connection per call — sqlite3 handles concurrency for our
"one audit at a time" usage shape):

- ``runs`` — one row per ``mlsecops audit`` invocation
- ``findings`` — flattened denormalised Finding rows, joined to a run by ``run_id``
- ``fix_proposals`` — joined to a finding by ``finding_pk``; LLM-authored or
  deterministic-author narratives both land here

The migration is idempotent: ``init_db`` creates tables if missing. No
versioned migrations yet — we'll add them with the first breaking change.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..models import CheckResult, Finding

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    total_findings  INTEGER NOT NULL DEFAULT 0,
    max_severity    TEXT,
    blocking        INTEGER NOT NULL DEFAULT 0,
    invocation      TEXT NOT NULL DEFAULT 'cli',
    extra_json      TEXT
);

CREATE TABLE IF NOT EXISTS check_results (
    run_id          TEXT NOT NULL,
    check_name      TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL,
    tool_status     TEXT NOT NULL,
    findings_count  INTEGER NOT NULL,
    PRIMARY KEY (run_id, check_name),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_pk      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    check_name      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    category        TEXT NOT NULL,
    file            TEXT NOT NULL,
    line_start      INTEGER,
    line_end        INTEGER,
    message         TEXT NOT NULL,
    evidence        TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_run
    ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule
    ON findings(rule_id);

CREATE TABLE IF NOT EXISTS fix_proposals (
    fix_pk          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_pk      INTEGER NOT NULL,
    summary         TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    diff            TEXT,
    replacement     TEXT,
    author          TEXT NOT NULL DEFAULT 'deterministic',
    FOREIGN KEY (finding_pk) REFERENCES findings(finding_pk) ON DELETE CASCADE
);
"""

_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def init_db(path: Path) -> None:
    """Create tables if they don't exist. Idempotent."""
    with sqlite3.connect(path) as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Repository:
    """Thin typed wrapper around the SQLite connection."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        init_db(db_path)

    # --- write -----------------------------------------------------------

    def record_run(
        self,
        *,
        target: str,
        results: list[CheckResult],
        invocation: str = "cli",
        run_id: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        """Persist a complete audit run. Returns the run_id."""
        rid = run_id or uuid.uuid4().hex
        started = _utcnow_iso()
        finished = started  # We're called post-run; same timestamp is fine for v0.

        total = sum(len(r.findings) for r in results)
        max_sev_rank = -1
        max_sev = "info"
        blocking = 0
        for r in results:
            for f in r.findings:
                rank = _SEVERITY_RANK.get(f.severity.value, 0)
                if rank > max_sev_rank:
                    max_sev_rank = rank
                    max_sev = f.severity.value
                if f.severity.value in ("high", "critical"):
                    blocking = 1

        with _connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO runs
                (run_id, target, started_at, finished_at,
                 total_findings, max_severity, blocking, invocation, extra_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    target,
                    started,
                    finished,
                    total,
                    max_sev if total else None,
                    blocking,
                    invocation,
                    json.dumps(extra or {}),
                ),
            )
            for result in results:
                conn.execute(
                    """
                    INSERT INTO check_results
                    (run_id, check_name, duration_ms, tool_status, findings_count)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        rid,
                        result.check.value,
                        result.duration_ms,
                        result.tool_status,
                        len(result.findings),
                    ),
                )
                for finding in result.findings:
                    cur = conn.execute(
                        """
                        INSERT INTO findings
                        (run_id, rule_id, check_name, severity, category,
                         file, line_start, line_end, message, evidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            rid,
                            finding.id,
                            finding.check.value,
                            finding.severity.value,
                            finding.category,
                            str(finding.file),
                            finding.line_start,
                            finding.line_end,
                            finding.message,
                            finding.evidence,
                        ),
                    )
                    if finding.fix is not None:
                        conn.execute(
                            """
                            INSERT INTO fix_proposals
                            (finding_pk, summary, confidence, diff, replacement, author)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                cur.lastrowid,
                                finding.fix.summary,
                                finding.fix.confidence,
                                finding.fix.diff,
                                finding.fix.replacement,
                                "deterministic",
                            ),
                        )
            conn.commit()
        return rid

    # --- read ------------------------------------------------------------

    def list_runs(self, *, limit: int = 20) -> list[dict[str, object]]:
        """Most-recent-first list of runs with summary metrics."""
        with _connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT run_id, target, started_at, finished_at,
                       total_findings, max_severity, blocking, invocation
                FROM runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, object] | None:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return dict(row) if row else None

    def findings_for_run(self, run_id: str) -> list[Finding]:
        """Reconstruct Finding objects from the persisted rows."""
        from pathlib import Path

        from ..models import CheckName, FixProposal, Severity

        with _connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT f.*, p.summary AS fix_summary, p.confidence AS fix_confidence,
                       p.diff AS fix_diff, p.replacement AS fix_replacement
                FROM findings f
                LEFT JOIN fix_proposals p ON p.finding_pk = f.finding_pk
                WHERE f.run_id = ?
                ORDER BY f.finding_pk
                """,
                (run_id,),
            ).fetchall()

        findings: list[Finding] = []
        for row in rows:
            fix = None
            if row["fix_summary"] is not None:
                fix = FixProposal(
                    summary=row["fix_summary"],
                    confidence=row["fix_confidence"],
                    diff=row["fix_diff"],
                    replacement=row["fix_replacement"],
                )
            findings.append(
                Finding(
                    id=row["rule_id"],
                    check=CheckName(row["check_name"]),
                    severity=Severity(row["severity"]),
                    category=row["category"],
                    file=Path(row["file"]),
                    line_start=row["line_start"],
                    line_end=row["line_end"],
                    message=row["message"],
                    evidence=row["evidence"],
                    fix=fix,
                )
            )
        return findings

    def runs_by_rule(self, rule_id: str) -> Iterable[dict[str, object]]:
        """Cross-run view of every appearance of a specific rule."""
        with _connect(self._db_path) as conn:
            rows = conn.execute(
                """
                SELECT r.run_id, r.target, r.started_at, f.severity, f.file, f.line_start
                FROM findings f
                JOIN runs r ON r.run_id = f.run_id
                WHERE f.rule_id = ?
                ORDER BY r.started_at DESC
                """,
                (rule_id,),
            ).fetchall()
        return [dict(row) for row in rows]
