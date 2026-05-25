"""Deserialization check.

Surfaces four classes of unsafe deserialization in Python files and notebook cells:

- ``deserialization.unsafe-joblib-load`` — any ``joblib.load(...)`` call.
  joblib uses pickle internally; loading from an untrusted source executes
  arbitrary code. severity HIGH.

- ``deserialization.unsafe-pickle-load`` — ``pickle.load(...)``,
  ``pickle.loads(...)``, or ``cPickle.load(...)``. The canonical deserialization
  vector for Python. severity HIGH.

- ``deserialization.unsafe-torch-load`` — ``torch.load(...)`` without
  ``weights_only=True``. PyTorch added ``weights_only`` in 1.13; omitting it
  (or setting it to ``False``) falls back to pickle. If ``weights_only=True``
  is explicitly passed the call is safe — we do NOT flag it. severity HIGH.

- ``deserialization.unsafe-numpy-load`` — ``numpy.load(...)`` with
  ``allow_pickle=True``. numpy's default is ``False`` so we only flag when the
  argument is explicitly present and set to ``True``. severity MEDIUM.

Detection uses ``libcst`` with ``QualifiedNameProvider`` so aliased imports
(``import joblib as jl; jl.load(...)``) and from-imports
(``from torch import load; load(...)``) are both resolved correctly.

For ``.ipynb`` files all code cells are concatenated before parsing so that
imports in earlier cells resolve calls in later cells — matching Python's actual
notebook execution model. IPython magic lines (``%``, ``!``) are blanked out
(replaced with empty lines) to preserve line numbers while keeping the source
parseable by libcst.
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

# IPython magic lines start with % or ! — not valid Python syntax.
# Match the whole line (excluding the trailing newline) so the replacement
# leaves exactly one blank line, preserving all subsequent line numbers.
_MAGIC_LINE_RE = re.compile(r"^[ \t]*[%!][^\n]*", re.MULTILINE)


def _blank_magic(src: str) -> str:
    """Replace IPython magic/shell lines with blank lines (line numbers preserved)."""
    return _MAGIC_LINE_RE.sub("", src)


def _has_kwarg_true(node: cst.Call, kwarg_name: str) -> bool:
    """Return True when *kwarg_name*=True is present in a call's keyword args."""
    for arg in node.args:
        if (
            isinstance(arg.keyword, cst.Name)
            and arg.keyword.value == kwarg_name
            and isinstance(arg.value, cst.Name)
            and arg.value.value == "True"
        ):
            return True
    return False


def _iter_notebook_code_sources(path: Path) -> list[str]:
    """Return a list of code cell sources from a notebook (magic lines blanked)."""
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


class _RawFinding:
    """Intermediate finding before the file path is known."""

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
            check=CheckName.DESERIALIZATION,
            severity=self.severity,
            category=self.category,
            file=path,
            line_start=self.line_start,
            line_end=self.line_end,
            message=self.message,
            evidence=self.evidence,
            fix=FixProposal(
                summary=self.fix_summary,
                confidence="high",
            ),
        )


class _UnsafeDeserializationVisitor(cst.CSTVisitor):
    """Walk a CST and collect unsafe deserialization call sites.

    Operates on a ``MetadataWrapper`` so ``QualifiedNameProvider`` is
    available — alias and from-import resolution comes for free.
    """

    METADATA_DEPENDENCIES = (meta.PositionProvider, meta.QualifiedNameProvider)

    def __init__(self, module: cst.Module) -> None:
        self._module = module
        self.raw_findings: list[_RawFinding] = []

    def visit_Call(self, node: cst.Call) -> None:  # N802: required by libcst visitor protocol
        pos = self.get_metadata(meta.PositionProvider, node)
        try:
            qualified = self.get_metadata(meta.QualifiedNameProvider, node.func)
        except Exception:
            return

        qnames = {q.name for q in qualified}
        try:
            evidence = self._module.code_for_node(node)
        except Exception:
            evidence = ""

        if "joblib.load" in qnames:
            self.raw_findings.append(
                _RawFinding(
                    rule_id="deserialization.unsafe-joblib-load",
                    severity=Severity.HIGH,
                    category="insecure-deserialization",
                    line_start=pos.start.line,
                    line_end=pos.end.line,
                    evidence=evidence,
                    message=(
                        "`joblib.load` uses pickle internally and will execute arbitrary "
                        "code when loading a maliciously crafted file. "
                        "Replace with a safe format (e.g. safetensors, JSON, ONNX) or "
                        "verify the file's integrity with a cryptographic hash before loading."
                    ),
                    fix_summary=(
                        "Replace `joblib.load` with a safe serialisation format such as "
                        "`safetensors` or save/load model weights to JSON/ONNX. "
                        "If you must use joblib, pin the exact file hash in your pipeline "
                        "and verify it before `load`."
                    ),
                )
            )

        if qnames & {"pickle.load", "pickle.loads", "cPickle.load"}:
            matched = ", ".join(sorted(qnames & {"pickle.load", "pickle.loads", "cPickle.load"}))
            self.raw_findings.append(
                _RawFinding(
                    rule_id="deserialization.unsafe-pickle-load",
                    severity=Severity.HIGH,
                    category="insecure-deserialization",
                    line_start=pos.start.line,
                    line_end=pos.end.line,
                    evidence=evidence,
                    message=(
                        f"`{matched}` executes arbitrary Python code during deserialization. "
                        "Any crafted pickle payload can achieve remote code execution. "
                        "Use `json`, `safetensors`, or ONNX instead."
                    ),
                    fix_summary=(
                        "Replace pickle with a format that cannot execute code on load: "
                        "`json` for plain data, `safetensors` for tensors, ONNX for models."
                    ),
                )
            )

        if "torch.load" in qnames and not _has_kwarg_true(node, "weights_only"):
            self.raw_findings.append(
                _RawFinding(
                    rule_id="deserialization.unsafe-torch-load",
                    severity=Severity.HIGH,
                    category="insecure-deserialization",
                    line_start=pos.start.line,
                    line_end=pos.end.line,
                    evidence=evidence,
                    message=(
                        "`torch.load` without `weights_only=True` falls back to pickle "
                        "and can execute arbitrary code. "
                        "Pass `weights_only=True` to restrict loading to tensor data."
                    ),
                    fix_summary=(
                        "Add `weights_only=True`: `torch.load(path, weights_only=True)`. "
                        "For older PyTorch (<1.13) upgrade to a patched release."
                    ),
                )
            )

        if "numpy.load" in qnames and _has_kwarg_true(node, "allow_pickle"):
            self.raw_findings.append(
                _RawFinding(
                    rule_id="deserialization.unsafe-numpy-load",
                    severity=Severity.MEDIUM,
                    category="insecure-deserialization",
                    line_start=pos.start.line,
                    line_end=pos.end.line,
                    evidence=evidence,
                    message=(
                        "`numpy.load(..., allow_pickle=True)` enables pickle deserialisation "
                        "in numpy arrays. The default is `False` for this reason. "
                        "Save arrays in a non-pickle format (`.npy` without object arrays, "
                        "`.npz`, or HDF5) so `allow_pickle` is not needed."
                    ),
                    fix_summary=(
                        "Remove `allow_pickle=True` and resave the array without object dtype. "
                        "If the array contains objects you control, switch to a typed format "
                        "or use `numpy.savez` with a schema you verify."
                    ),
                )
            )


def _scan_source(source: str, path: Path) -> list[Finding]:
    """Parse *source* with libcst and return deserialization findings.

    Returns an empty list on parse failures — broken cells should not crash
    the check; the user will see no findings for that file rather than an
    error, which is acceptable for notebook snippets with non-standard syntax.
    """
    try:
        module = cst.parse_module(source)
    except cst.ParserSyntaxError:
        return []

    try:
        wrapper = meta.MetadataWrapper(module)
    except Exception:
        return []

    visitor = _UnsafeDeserializationVisitor(module)
    try:
        wrapper.visit(visitor)
    except Exception:
        return []

    return [rf.to_finding(path) for rf in visitor.raw_findings]


def _scan_py(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    return _scan_source(source, path)


def _scan_notebook(path: Path) -> list[Finding]:
    cell_sources = _iter_notebook_code_sources(path)
    if not cell_sources:
        return []
    # Concatenate all cells with a newline separator so imports in earlier
    # cells resolve calls in later cells — matching notebook execution order.
    combined = "\n".join(cell_sources)
    return _scan_source(combined, path)


def _iter_targets(path: Path) -> Iterable[Path]:
    """Yield ``.py`` and ``.ipynb`` files under *path* (or *path* itself)."""
    if path.is_file():
        yield path
        return
    for pattern in ("**/*.py", "**/*.ipynb"):
        yield from path.glob(pattern)


def run(target: Path) -> CheckResult:
    """Run the deserialization check against a file or directory.

    Returns a :class:`~mlsecops_agent.models.CheckResult` whose ``findings``
    list is empty when no unsafe calls are found.
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
        check=CheckName.DESERIALIZATION,
        findings=findings,
        tool_status="ok",
        duration_ms=elapsed_ms,
    )
