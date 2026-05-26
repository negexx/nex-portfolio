# Findings from this check are deterministic AST matches;
# W3's agent loop will add LLM-judgement to filter false positives before reporting.
"""Leakage check.

Surfaces three classes of ML hygiene issues that standard SAST tools miss:

- ``leakage.preprocessing-before-split`` — fit / fit_transform / fit_resample
  calls that occur *before* the first ``train_test_split`` in document order.
  Data-dependent transformers fitted on the full dataset leak test-set statistics
  into the model. severity HIGH.

- ``leakage.fit-on-test`` — ``scaler.fit(X_test)`` or ``model.fit(X_test, y)``
  where the first argument's name clearly refers to a test set. If the test set
  is used to fit a transformer the entire evaluation is compromised. severity
  CRITICAL.

- ``leakage.label-proxy-feature`` — column-list assignments (``features = [...]``,
  ``X = df[cols]``, ``df.drop(['label'])``...) that retain a column whose name
  matches known label-proxy patterns (``difficulty_level``, ``*_target``, etc.).
  This is a name-match heuristic and will have false positives; the fix proposal
  says so explicitly. severity HIGH.

For ``.ipynb`` files all code cells are concatenated with
``\\n# --- cell {n} ---\\n`` markers before parsing so that cross-cell sequences
(SMOTE in cell 5, split in cell 8) are caught. Line numbers in findings are
translated back to (cell_index, line_within_cell) before returning.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING

import libcst as cst
import libcst.metadata as meta

from ..models import CheckName, CheckResult, Finding, FixProposal, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path


# ---------------------------------------------------------------------------
# IPython magic line blanker (shared with deserialization check)
# ---------------------------------------------------------------------------

_MAGIC_LINE_RE = re.compile(r"^[ \t]*[%!][^\n]*", re.MULTILINE)


def _blank_magic(src: str) -> str:
    return _MAGIC_LINE_RE.sub("", src)


# ---------------------------------------------------------------------------
# Notebook helpers
# ---------------------------------------------------------------------------

#: Separator injected between cells in the synthetic module.
#: Must start with a newline so column offsets are not disturbed.
_CELL_MARKER_PREFIX = "\n# --- cell "
_CELL_MARKER_SUFFIX = " ---\n"


def _iter_notebook_code_sources(path: Path) -> list[str]:
    """Return a list of (blanked) code-cell sources from *path*."""
    data = json.loads(path.read_text(encoding="utf-8"))
    cells = data.get("cells", [])
    if not isinstance(cells, list):
        return []
    sources: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        raw = cell.get("source", "")
        if isinstance(raw, list):
            raw = "".join(s for s in raw if isinstance(s, str))
        elif not isinstance(raw, str):
            continue
        sources.append(_blank_magic(raw))
    return sources


def _build_synthetic_module(sources: list[str]) -> tuple[str, list[int]]:
    """Join cell sources with cell markers; return (synthetic_source, cell_start_lines).

    *cell_start_lines[i]* is the 1-indexed line at which cell *i*'s source begins
    inside the synthetic module (i.e. the line AFTER the cell marker).
    """
    parts: list[str] = []
    for idx, src in enumerate(sources):
        if idx == 0:
            parts.append(src)
        else:
            parts.append(f"{_CELL_MARKER_PREFIX}{idx}{_CELL_MARKER_SUFFIX}")
            parts.append(src)

    synthetic = "".join(parts)

    # Compute cell_start_lines by scanning the synthetic string byte-by-byte.
    # cell_start_lines[i] = 1-indexed line where cell i's source text begins.
    cell_start_lines: list[int] = []
    char_pos = 0
    for idx, src in enumerate(sources):
        if idx == 0:
            cell_start_lines.append(1)
            char_pos = len(src)
        else:
            marker = f"{_CELL_MARKER_PREFIX}{idx}{_CELL_MARKER_SUFFIX}"
            char_pos += len(marker)
            line = synthetic.count("\n", 0, char_pos) + 1
            cell_start_lines.append(line)
            char_pos += len(src)

    return synthetic, cell_start_lines


def _synthetic_line_to_cell_line(
    synthetic_line: int,
    cell_start_lines: list[int],
    sources: list[str],
) -> tuple[int, int]:
    """Translate a 1-indexed line in the synthetic module to (cell_index, line_within_cell).

    Returns (cell_index, 1-indexed line within that cell's source).
    """
    # Find which cell contains this line by looking at the start of the NEXT cell.
    cell_index = 0
    for i, start in enumerate(cell_start_lines):
        if synthetic_line >= start:
            cell_index = i
        else:
            break
    line_within_cell = synthetic_line - cell_start_lines[cell_index] + 1
    # Clamp to the cell's actual line count
    cell_line_count = sources[cell_index].count("\n") + 1
    line_within_cell = max(1, min(line_within_cell, cell_line_count))
    return cell_index, line_within_cell


# ---------------------------------------------------------------------------
# Rule 3: label-proxy column name patterns
# ---------------------------------------------------------------------------

# Patterns that suggest a column is a label proxy rather than a real feature.
# All matched case-insensitively against individual column name strings.
_LABEL_PROXY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^difficulty(?:_level)?$", re.IGNORECASE),
    re.compile(r".+_label$", re.IGNORECASE),
    re.compile(r".+_target$", re.IGNORECASE),
    re.compile(r"^target_.+", re.IGNORECASE),
    re.compile(r"^label_.+", re.IGNORECASE),
    re.compile(r"^outcome$", re.IGNORECASE),
    re.compile(r"^result_class$", re.IGNORECASE),
    re.compile(r"^class_id$", re.IGNORECASE),
    re.compile(r"^is_.+_fraud$", re.IGNORECASE),
    re.compile(r".+_leak$", re.IGNORECASE),
    re.compile(r"^leak_.+", re.IGNORECASE),
    re.compile(r"^cheat_.+", re.IGNORECASE),
]

def _is_label_proxy(name: str) -> bool:
    """Return True when *name* matches any label-proxy pattern."""
    return any(pat.match(name) for pat in _LABEL_PROXY_PATTERNS)


# ---------------------------------------------------------------------------
# Rule 1 + Rule 2: call-site patterns
# ---------------------------------------------------------------------------

# Qualified-name suffixes that indicate a fit / resample call we care about.
# We match against the *attribute name* directly (not full qualified names) because
# QualifiedNameProvider can't resolve arbitrary user-defined objects (e.g. `smote`).
_FIT_ATTRS: frozenset[str] = frozenset(
    {"fit", "fit_transform", "fit_resample"}
)

# train_test_split call detection — attribute OR bare name.
_SPLIT_NAMES: frozenset[str] = frozenset({"train_test_split"})

# Regex to detect test-set variable names in the first positional arg of fit().
_TEST_ARG_RE = re.compile(
    r"^(?:X_?test|_?test_?[XY]|test_features|test_data)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Raw finding (before path is attached)
# ---------------------------------------------------------------------------


class _RawFinding:
    __slots__ = (
        "category",
        "evidence",
        "fix_summary",
        "line_end",
        "line_start",
        "message",
        "rule_id",
        "severity",
    )

    def __init__(
        self,
        *,
        rule_id: str,
        severity: Severity,
        category: str,
        line_start: int,
        line_end: int,
        evidence: str,
        message: str,
        fix_summary: str,
    ) -> None:
        self.rule_id = rule_id
        self.severity = severity
        self.category = category
        self.line_start = line_start
        self.line_end = line_end
        self.evidence = evidence
        self.message = message
        self.fix_summary = fix_summary

    def to_finding(self, path: Path) -> Finding:
        return Finding(
            id=self.rule_id,
            check=CheckName.LEAKAGE,
            severity=self.severity,
            category=self.category,
            file=path,
            line_start=self.line_start,
            line_end=self.line_end,
            message=self.message,
            evidence=self.evidence,
            fix=FixProposal(
                summary=self.fix_summary,
                # W3 LLM pass will re-evaluate; medium signals "may include false positives"
                confidence="medium",
            ),
        )


# ---------------------------------------------------------------------------
# CST visitor
# ---------------------------------------------------------------------------


def _call_func_attr(node: cst.Call) -> str | None:
    """Return the attribute name if the call is ``obj.attr(...)``."""
    if isinstance(node.func, cst.Attribute):
        attr = node.func.attr
        if isinstance(attr, cst.Name):
            return attr.value
    return None


def _call_func_name(node: cst.Call) -> str | None:
    """Return the bare name if the call is ``name(...)``."""
    if isinstance(node.func, cst.Name):
        return node.func.value
    return None


def _first_pos_arg_name(node: cst.Call) -> str | None:
    """Return the Name value of the first positional argument, or None."""
    for arg in node.args:
        if arg.keyword is not None:
            continue
        if isinstance(arg.value, cst.Name):
            return arg.value.value
        return None
    return None


def _extract_string_literals(node: cst.BaseExpression) -> list[str]:
    """Recursively collect string literals from a list/tuple expression."""
    results: list[str] = []
    if isinstance(node, (cst.List, cst.Tuple)):
        for el in node.elements:
            results.extend(_extract_string_literals(el.value))
    elif isinstance(node, cst.ConcatenatedString):
        pass  # too complex for heuristic
    elif isinstance(node, cst.SimpleString):
        # Strip quotes
        val = node.evaluated_value
        if isinstance(val, str):
            results.append(val)
    elif isinstance(node, cst.FormattedString):
        pass  # f-strings ignored
    return results


class _LeakageVisitor(cst.CSTVisitor):
    """Walk a (possibly synthetic multi-cell) CST and collect leakage findings.

    The visitor does two passes implicitly via a single traversal:

    1. Every call node is categorised as either a *split call* or a *fit call*
       and recorded with its line number.
    2. After the full traversal, :py:meth:`finalize` emits Rule-1 findings by
       comparing recorded positions.
    3. Rule-2 and Rule-3 findings are emitted inline during ``visit_Call`` /
       ``visit_Assign`` / ``visit_AnnAssign``.
    """

    METADATA_DEPENDENCIES = (meta.PositionProvider,)

    def __init__(self, module: cst.Module) -> None:
        self._module = module
        self.raw_findings: list[_RawFinding] = []
        # (line_start, line_end, evidence) tuples
        self._split_lines: list[int] = []
        self._fit_calls: list[tuple[int, int, str]] = []  # (line_start, line_end, evidence)

    # ------------------------------------------------------------------
    # Call visitor — rules 1 and 2
    # ------------------------------------------------------------------

    def visit_Call(self, node: cst.Call) -> None:  # N802: required by libcst visitor protocol
        pos = self.get_metadata(meta.PositionProvider, node)
        try:
            evidence = self._module.code_for_node(node)
        except Exception:
            evidence = ""

        attr = _call_func_attr(node)
        bare = _call_func_name(node)

        # Rule 1 — split detection
        if bare in _SPLIT_NAMES or attr in _SPLIT_NAMES:
            self._split_lines.append(pos.start.line)
            return

        # Rule 1 — fit call detection (stored; emitted after full traversal)
        if attr in _FIT_ATTRS:
            self._fit_calls.append((pos.start.line, pos.end.line, evidence))

        # Rule 2 — fit on test set
        if (
            attr in {"fit", "fit_transform"}
            and (first := _first_pos_arg_name(node))
            and _TEST_ARG_RE.match(first)
        ):
            self.raw_findings.append(
                    _RawFinding(
                        rule_id="leakage.fit-on-test",
                        severity=Severity.CRITICAL,
                        category="data-leakage",
                        line_start=pos.start.line,
                        line_end=pos.end.line,
                        evidence=evidence,
                        message=(
                            f"`{attr}({first}, ...)` fits the transformer on the test set. "
                            "Any statistics computed here (mean, variance, …) are contaminated "
                            "by test-set information and will produce optimistically biased "
                            "evaluation metrics."
                        ),
                        fix_summary=(
                            f"Replace `{attr}({first})` with `transform({first})`. "
                            "Only `fit` / `fit_transform` on the training split; apply "
                            "`transform` to validation and test splits."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Assignment visitors — rule 3 (label-proxy features)
    # ------------------------------------------------------------------

    def _check_list_for_proxies(
        self,
        value_node: cst.BaseExpression,
        pos: meta.CodeRange,
        context_desc: str,
    ) -> None:
        """Emit Rule-3 findings for any label-proxy column names in a list."""
        cols = _extract_string_literals(value_node)
        proxies = [c for c in cols if _is_label_proxy(c)]
        if not proxies:
            return
        try:
            evidence = self._module.code_for_node(value_node)
        except Exception:
            evidence = ", ".join(proxies)
        for proxy in proxies:
            self.raw_findings.append(
                _RawFinding(
                    rule_id="leakage.label-proxy-feature",
                    severity=Severity.HIGH,
                    category="data-leakage",
                    line_start=pos.start.line,
                    line_end=pos.end.line,
                    evidence=evidence[:200],
                    message=(
                        f"Column `{proxy}` in {context_desc} matches a label-proxy pattern. "
                        "If this column encodes the target (directly or indirectly) and is "
                        "included in the feature set, the model will have access to the "
                        "answer at inference time."
                    ),
                    fix_summary=(
                        f"Confirm whether `{proxy}` is a label proxy — this is a "
                        "name-match heuristic and may be a false positive. "
                        "If it is a proxy, remove it from the feature list before training."
                    ),
                )
            )

    def visit_Assign(self, node: cst.Assign) -> None:  # N802: required by libcst visitor protocol
        pos = self.get_metadata(meta.PositionProvider, node)
        self._check_list_for_proxies(node.value, pos, "an assignment")

    def visit_AnnAssign(self, node: cst.AnnAssign) -> None:  # N802: libcst protocol
        if node.value is None:
            return
        pos = self.get_metadata(meta.PositionProvider, node)
        self._check_list_for_proxies(node.value, pos, "an annotated assignment")

    # ------------------------------------------------------------------
    # Post-traversal: emit Rule-1 findings
    # ------------------------------------------------------------------

    def finalize(self) -> None:
        """Emit preprocessing-before-split findings after full traversal."""
        if not self._split_lines:
            return
        earliest_split = min(self._split_lines)
        for line_start, line_end, evidence in self._fit_calls:
            if line_start < earliest_split:
                self.raw_findings.append(
                    _RawFinding(
                        rule_id="leakage.preprocessing-before-split",
                        severity=Severity.HIGH,
                        category="data-leakage",
                        line_start=line_start,
                        line_end=line_end,
                        evidence=evidence,
                        message=(
                            "A data-dependent transformer is fitted on the full dataset "
                            f"(line {line_start}) before `train_test_split` "
                            f"(line {earliest_split}). "
                            "Statistics computed on the full dataset (mean, variance, …) "
                            "leak test-set information into the training pipeline."
                        ),
                        fix_summary=(
                            "Move all `fit` / `fit_transform` / `fit_resample` calls to "
                            "after `train_test_split`. Apply `transform` (not "
                            "`fit_transform`) to the test split."
                        ),
                    )
                )


# ---------------------------------------------------------------------------
# Alias detection for train_test_split
# ---------------------------------------------------------------------------

# Handles: "from sklearn.model_selection import train_test_split as alias"
_TTS_ALIAS_RE = re.compile(
    r"from\s+\S+\s+import\s+(?:[^\n]*,\s*)*train_test_split\s+as\s+(\w+)",
    re.MULTILINE,
)


def _inject_alias_renames(source: str) -> str:
    """Rewrite aliased train_test_split calls to use the canonical name.

    Finds ``from X import train_test_split as alias`` and replaces all
    subsequent bare calls to ``alias(...)`` with ``train_test_split(...)``.
    This is a text-level transformation, not an AST one — good enough for
    the visitor's simple name check.
    """
    for m in _TTS_ALIAS_RE.finditer(source):
        alias = m.group(1)
        if alias and alias != "train_test_split":
            # Replace bare function calls to alias(...) with train_test_split(...)
            source = re.sub(
                r"\b" + re.escape(alias) + r"\s*\(",
                "train_test_split(",
                source,
            )
    return source


# ---------------------------------------------------------------------------
# Source scanner
# ---------------------------------------------------------------------------


def _scan_source(
    source: str,
    path: Path,
    *,
    cell_start_lines: list[int] | None = None,
    sources: list[str] | None = None,
) -> list[Finding]:
    """Parse *source* with libcst and return leakage findings.

    When *cell_start_lines* and *sources* are provided the line numbers in
    findings are translated from synthetic-module positions to
    (cell_index, line_within_cell) before being attached to each Finding.
    """
    source = _inject_alias_renames(source)
    try:
        module = cst.parse_module(source)
    except cst.ParserSyntaxError:
        return []

    try:
        wrapper = meta.MetadataWrapper(module)
    except Exception:
        return []

    visitor = _LeakageVisitor(module)
    try:
        wrapper.visit(visitor)
    except Exception:
        return []

    visitor.finalize()

    findings: list[Finding] = []
    for rf in visitor.raw_findings:
        if cell_start_lines is not None and sources is not None:
            cell_idx, line_in_cell = _synthetic_line_to_cell_line(
                rf.line_start, cell_start_lines, sources
            )
            rf.line_start = line_in_cell
            _, line_in_cell_end = _synthetic_line_to_cell_line(
                rf.line_end, cell_start_lines, sources
            )
            rf.line_end = line_in_cell_end
            # Annotate the message with the cell index.
            rf.message = f"[cell {cell_idx}] {rf.message}"
        findings.append(rf.to_finding(path))

    return findings


def _scan_py(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    return _scan_source(source, path)


def _scan_notebook(path: Path) -> list[Finding]:
    sources = _iter_notebook_code_sources(path)
    if not sources:
        return []
    synthetic, cell_start_lines = _build_synthetic_module(sources)
    return _scan_source(
        synthetic,
        path,
        cell_start_lines=cell_start_lines,
        sources=sources,
    )


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
    """Run the leakage check against a file or directory.

    Returns a :class:`~mlsecops_agent.models.CheckResult` whose ``findings``
    list is empty when no issues are found.
    """
    started = time.perf_counter()
    findings: list[Finding] = []

    for target_file in _iter_targets(target):
        try:
            if target_file.suffix == ".py":
                findings.extend(_scan_py(target_file))
            elif target_file.suffix == ".ipynb":
                findings.extend(_scan_notebook(target_file))
        except (OSError, json.JSONDecodeError):
            continue

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return CheckResult(
        check=CheckName.LEAKAGE,
        findings=findings,
        tool_status="ok",
        duration_ms=elapsed_ms,
    )
