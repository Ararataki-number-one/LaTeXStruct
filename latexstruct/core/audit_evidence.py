# -*- coding: utf-8 -*-
"""Deterministic, machine-readable evidence for AI audit submissions.

This module never calls a model.  It only reshapes host-captured run facts so
the submission builder can expose outline decisions, blockers, metrics and the
exact non-system compile closure without inventing evidence for legacy runs.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import PurePosixPath
from typing import Iterable, Mapping


OUTLINE_EVIDENCE_SCHEMA = "latexstruct-outline-evidence-v1"
REPORT_SCHEMA = "latexstruct-audit-report-v2"
METRICS_SCHEMA = "latexstruct-audit-metrics-v1"
ISSUES_SCHEMA = "latexstruct-audit-issues-v1"
TEMPLATE_MANIFEST_SCHEMA = "latexstruct-template-manifest-v1"

_SECTION_RE = re.compile(
    r"\\(?P<command>chapter|section|subsection|subsubsection)\*?\s*"
    r"\{(?P<title>[^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
    re.IGNORECASE,
)
_BIBLIOGRAPHY_RE = re.compile(r"\\begin\s*\{thebibliography\}")
_BIBITEM_RE = re.compile(r"\\bibitem(?:\s*\[[^\]]*\])?\s*\{")
_PROOF_RE = re.compile(r"\\begin\s*\{proof\}")
_FORMAL_RE = re.compile(
    r"\\begin\s*\{(?:theorem|lemma|proposition|corollary|conjecture|claim|"
    r"definition|axiom|postulate|fact|remark|observation|note|example|problem|"
    r"question|exercise)\*?\}",
    re.IGNORECASE,
)
_EQUATION_TAG_RE = re.compile(r"\\tag\s*\{([^{}]+)\}")
_NUMBER_PREFIX_RE = re.compile(r"^\s*\d+(?:\.\d+)*\.?\s+")
_LATEX_WRAPPER_RE = re.compile(r"\\(?:textbf|textit|emph|textsc|texorpdfstring)\s*\{")


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _title_key(value: object) -> str:
    """Return a conservative comparison key for PDF/TeX heading titles."""
    text = str(value or "").strip().casefold()
    text = _NUMBER_PREFIX_RE.sub("", text)
    text = text.replace(r"\(", "").replace(r"\)", "")
    text = _LATEX_WRAPPER_RE.sub("", text)
    text = text.replace("{", "").replace("}", "")
    text = re.sub(r"\\[a-zA-Z@]+\*?", "", text)
    return "".join(char for char in text if char.isalnum())


def current_tex_structure(tex: str) -> list[dict[str, object]]:
    """Extract the visible section tree used to explain outline mappings."""
    levels = {"chapter": 0, "section": 1, "subsection": 2, "subsubsection": 3}
    rows: list[dict[str, object]] = []
    for match in _SECTION_RE.finditer(str(tex or "")):
        command = match.group("command").casefold()
        title = match.group("title").strip()
        rows.append({
            "level": levels[command],
            "title": title,
            "command": f"\\{command}{{{title}}}",
            "line": str(tex).count("\n", 0, match.start()) + 1,
        })
    if _BIBLIOGRAPHY_RE.search(str(tex or "")):
        rows.append({
            "level": 0,
            "title": "References",
            "command": r"\begin{thebibliography}",
            "line": str(tex).count(
                "\n", 0, _BIBLIOGRAPHY_RE.search(str(tex)).start()
            ) + 1,
        })
    return rows


def build_outline_evidence(
    source_outline: Iterable[Mapping[str, object]] | None,
    current_tex: str,
    verification: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """Build real outline evidence, or return ``None`` when none was captured."""
    source = [dict(item) for item in (source_outline or ()) if isinstance(item, Mapping)]
    source = [item for item in source if str(item.get("title") or "").strip()]
    if not source:
        return None

    verification = verification if isinstance(verification, Mapping) else {}
    structure_gate = verification.get("ocr_structure")
    structure_gate = structure_gate if isinstance(structure_gate, Mapping) else {}
    rejected = {
        (_title_key(item.get("title")), int(item.get("page") or 0)): str(
            item.get("reason") or "host structure gate rejected this outline item"
        )
        for item in (structure_gate.get("rejected_outline") or ())
        if isinstance(item, Mapping)
    }
    current = current_tex_structure(current_tex)
    by_title: dict[str, list[dict[str, object]]] = {}
    for item in current:
        by_title.setdefault(_title_key(item.get("title")), []).append(item)

    rows: list[dict[str, object]] = []
    accepted = rejected_count = unresolved = 0
    for item in source:
        title = str(item.get("title") or "").strip()
        try:
            page = int(item.get("page") or 0)
            level = max(0, int(item.get("level") or 0))
        except (TypeError, ValueError):
            page, level = 0, 0
        row: dict[str, object] = {"level": level, "title": title, "page": page}
        reason = rejected.get((_title_key(title), page))
        if reason:
            row.update(status="REJECTED", reason=reason)
            rejected_count += 1
        else:
            matches = by_title.get(_title_key(title)) or []
            if matches:
                matched = matches.pop(0)
                row.update(
                    status="ACCEPTED",
                    matched_command=matched["command"],
                    current_line=matched["line"],
                )
                accepted += 1
            else:
                row.update(
                    status="UNRESOLVED",
                    reason="no matching current TeX heading was captured",
                )
                unresolved += 1
        rows.append(row)

    # The host structure gate is authoritative when it recorded exact counts.
    # Do not silently rewrite rows to make the numbers agree; expose any
    # discrepancy so an external auditor can see it.
    expected = structure_gate.get("expected")
    matched = structure_gate.get("matched")
    consistency = {
        "host_expected": expected,
        "host_matched": matched,
        "evidence_accepted": accepted,
        "consistent": (
            (expected is None or int(expected) == accepted + unresolved)
            and (matched is None or int(matched) == accepted)
        ),
    }
    return {
        "schema_version": OUTLINE_EVIDENCE_SCHEMA,
        "source_outline": rows,
        "accepted_count": accepted,
        "rejected_count": rejected_count,
        "unresolved_count": unresolved,
        "current_structure": current,
        "verification_consistency": consistency,
    }


def outline_evidence_errors(value: object) -> list[str]:
    """Validate that an outline artifact contains auditable, count-consistent rows."""
    if not isinstance(value, Mapping):
        return ["outline evidence is not a JSON object"]
    if value.get("schema_version") != OUTLINE_EVIDENCE_SCHEMA:
        return ["outline evidence has an unsupported or missing schema_version"]
    rows = value.get("source_outline")
    if not isinstance(rows, list) or not rows:
        return ["outline evidence contains no source_outline rows"]
    errors: list[str] = []
    counts = {"ACCEPTED": 0, "REJECTED": 0, "UNRESOLVED": 0}
    for index, row in enumerate(rows, 1):
        if not isinstance(row, Mapping):
            errors.append(f"outline row {index} is not an object")
            continue
        if not str(row.get("title") or "").strip():
            errors.append(f"outline row {index} has no title")
        status = str(row.get("status") or "").upper()
        if status not in counts:
            errors.append(f"outline row {index} has invalid status {status or 'EMPTY'}")
        else:
            counts[status] += 1
        try:
            if int(row.get("page") or 0) < 1:
                errors.append(f"outline row {index} has no positive source page")
        except (TypeError, ValueError):
            errors.append(f"outline row {index} has an invalid source page")
    declared = {
        "ACCEPTED": value.get("accepted_count"),
        "REJECTED": value.get("rejected_count"),
        "UNRESOLVED": value.get("unresolved_count"),
    }
    for status, raw_count in declared.items():
        try:
            count = int(raw_count)
        except (TypeError, ValueError):
            errors.append(f"outline {status.casefold()}_count is invalid")
            continue
        if count != counts[status]:
            errors.append(
                f"outline {status.casefold()}_count does not match source_outline rows"
            )
    consistency = value.get("verification_consistency")
    if isinstance(consistency, Mapping) and consistency.get("consistent") is False:
        errors.append("outline evidence contradicts the captured verification counts")
    return errors


def structured_blockers(
    failures: Iterable[Mapping[str, object]] | None,
    *,
    error: str = "",
) -> list[dict[str, object]]:
    """Turn host verification failures into stable, actionable objects."""
    rows: list[dict[str, object]] = []
    for index, item in enumerate(failures or (), 1):
        if not isinstance(item, Mapping):
            continue
        blocker_id = str(item.get("id") or f"verification-{index}").strip()
        summary = str(item.get("summary") or item.get("label") or "").strip()
        if not summary:
            continue
        candidate_ids = item.get("candidate_ids") or item.get("candidates") or ()
        if isinstance(candidate_ids, str):
            candidate_ids = (candidate_ids,)
        evidence = item.get("evidence") or (
            "audit/report.md",
            "audit/verification.json",
        )
        if isinstance(evidence, str):
            evidence = (evidence,)
        rows.append({
            "id": re.sub(r"[^a-z0-9-]+", "-", blocker_id.casefold()).strip("-")
            or f"verification-{index}",
            "severity": str(item.get("severity") or "P0").upper(),
            "module": str(item.get("module") or item.get("id") or "verification"),
            "summary": summary,
            "candidate_ids": [str(value) for value in candidate_ids if str(value)],
            "evidence": [str(value) for value in evidence if str(value)],
            "recommended_fix": str(
                item.get("action") or item.get("recommended_fix") or "重新运行对应机器检查"
            ),
            "acceptance": str(item.get("acceptance") or f"{blocker_id} passes"),
            "source_page": item.get("source_page") or item.get("page"),
            "source_line": item.get("source_line") or item.get("line"),
            "expected": item.get("expected") or item.get("acceptance"),
            "actual": item.get("actual") or summary,
        })
    if str(error or "").strip():
        rows.append({
            "id": "run-error",
            "severity": "P0",
            "module": "runtime",
            "summary": str(error).strip(),
            "candidate_ids": [],
            "evidence": ["audit/error.log"],
            "recommended_fix": "修复运行错误后重新执行任务",
            "acceptance": "source run reaches a non-failed terminal state",
        })
    return rows


def issues_csv_bytes(
    blockers: Iterable[Mapping[str, object]],
    decision_items: Iterable[Mapping[str, object]] | None = None,
) -> bytes:
    columns = (
        "id",
        "severity",
        "module",
        "candidate_id",
        "source_page",
        "source_line",
        "expected",
        "actual",
        "evidence",
        "recommended_fix",
        "acceptance",
    )
    rows: list[dict[str, object]] = []
    for blocker in blockers:
        candidates = blocker.get("candidate_ids") or [""]
        if isinstance(candidates, str):
            candidates = [candidates]
        for candidate in candidates or [""]:
            rows.append({
                "id": blocker.get("id") or "",
                "severity": blocker.get("severity") or "",
                "module": blocker.get("module") or "",
                "candidate_id": candidate,
                "source_page": blocker.get("source_page") or "",
                "source_line": blocker.get("source_line") or "",
                "expected": blocker.get("expected") or blocker.get("acceptance") or "",
                "actual": blocker.get("actual") or blocker.get("summary") or "",
                "evidence": ";".join(str(v) for v in blocker.get("evidence") or ()),
                "recommended_fix": blocker.get("recommended_fix") or "",
                "acceptance": blocker.get("acceptance") or "",
            })
    for index, item in enumerate(decision_items or (), 1):
        if not isinstance(item, Mapping) or str(item.get("status") or "").casefold() not in {
            "ambiguous", "pending", "failed"
        }:
            continue
        rows.append({
            "id": f"decision-{index:04d}",
            "severity": "P1",
            "module": "structure",
            "candidate_id": item.get("candidate_id") or "",
            "source_page": item.get("page") or "",
            "source_line": item.get("line") or "",
            "expected": "one final structure decision",
            "actual": item.get("reason") or item.get("status") or "",
            "evidence": "audit/decisions.json",
            "recommended_fix": "复核候选边界并重新分析",
            "acceptance": "candidate has a unique non-ambiguous decision",
        })
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def build_metrics(
    *,
    source_pdf: Mapping[str, object] | None,
    outline_evidence: Mapping[str, object] | None,
    verification: Mapping[str, object],
    current_tex: str,
) -> dict[str, object]:
    structure = verification.get("structure_decisions")
    structure = structure if isinstance(structure, Mapping) else {}
    invariants = verification.get("invariants")
    invariants = invariants if isinstance(invariants, Mapping) else {}
    body = invariants.get("body_text")
    body = body if isinstance(body, Mapping) else {}
    math_record = invariants.get("math")
    math_record = math_record if isinstance(math_record, Mapping) else {}
    source_pdf = source_pdf if isinstance(source_pdf, Mapping) else {}
    selected = source_pdf.get("selected_page_range")
    selected = selected if isinstance(selected, Mapping) else {}
    outline_evidence = outline_evidence if isinstance(outline_evidence, Mapping) else {}
    raw_compile = verification.get("compile_before")
    raw_compile = raw_compile if isinstance(raw_compile, Mapping) else {}
    current_compile = verification.get("compile_after")
    current_compile = current_compile if isinstance(current_compile, Mapping) else {}
    formal_total = int(structure.get("formal_total") or len(_FORMAL_RE.findall(current_tex)))
    formal_structured = int(structure.get("formal_wrapped") or len(_FORMAL_RE.findall(current_tex)))
    residual = list(structure.get("formal_residual_ids") or ())
    return {
        "schema_version": METRICS_SCHEMA,
        "source_pages": int(source_pdf.get("page_count") or 0),
        "selected_pages": list(selected.get("pages") or ()),
        "outline_total": len(outline_evidence.get("source_outline") or ()),
        "outline_accepted": int(outline_evidence.get("accepted_count") or 0),
        "outline_rejected": int(outline_evidence.get("rejected_count") or 0),
        "outline_unresolved": int(outline_evidence.get("unresolved_count") or 0),
        "formal_total": formal_total,
        "formal_structured": formal_structured,
        "formal_residual": len(residual),
        "formal_residual_ids": residual,
        "proof_total": len(_PROOF_RE.findall(current_tex)),
        "proof_structured": len(_PROOF_RE.findall(current_tex)),
        "equation_number_sequence": _EQUATION_TAG_RE.findall(current_tex),
        "bibliography_count": len(_BIBITEM_RE.findall(current_tex)),
        "compile_raw_status": str(raw_compile.get("preview_status") or "NOT_RUN"),
        "compile_current_status": str(current_compile.get("preview_status") or "NOT_RUN"),
        "body_text_conservation": body.get("equal") if body.get("checked", True) else None,
        "math_token_conservation": math_record.get("equal"),
        "packaging_integrity": "PENDING",
    }


def build_report_json(
    *,
    source_run_status: str,
    verification_status: str,
    stages: Mapping[str, object],
    blockers: Iterable[Mapping[str, object]],
    metrics: Mapping[str, object],
) -> dict[str, object]:
    blockers = list(blockers)
    return {
        "schema_version": REPORT_SCHEMA,
        "source_run_status": str(source_run_status),
        "verification_status": str(verification_status),
        "stages": dict(stages),
        "blocker_count": len(blockers),
        "blockers": blockers,
        "metrics": dict(metrics),
    }


def project_dependency_path(relative: str) -> str:
    """Map one portable compile input to its standard audit subdirectory."""
    path = PurePosixPath(str(relative).replace("\\", "/"))
    suffix = path.suffix.casefold()
    if suffix in {".cls", ".sty", ".def", ".cfg", ".clo", ".tex"}:
        category = "subfiles" if suffix == ".tex" else "class-style-assets"
    elif suffix in {".bib", ".bst"}:
        category = "bibliography"
    elif suffix in {".png", ".jpg", ".jpeg", ".pdf", ".eps", ".svg"}:
        category = "images"
    elif "license" in path.name.casefold() or "copying" in path.name.casefold():
        category = "LICENSES"
    else:
        category = "compile-assets"
    return (PurePosixPath("project") / category / path).as_posix()


def template_manifest(
    *,
    template_id: str,
    template_version: str | None,
    assets: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for item in assets:
        row = dict(item)
        artifact_path = str(
            row.get("artifact_path")
            or row.get("packaged_path")
            or row.get("path")
            or ""
        )
        rows.append({
            **row,
            "artifact_path": artifact_path,
            "bytes_sha256": str(
                row.get("bytes_sha256") or row.get("sha256") or ""
            ),
            "role": str(
                row.get("role") or row.get("artifact_role") or "PROJECT_FILE"
            ),
            "license_path": row.get("license_path"),
            "required_for_compile": row.get("required_for_compile") is True,
            "source": str(row.get("source") or "host-captured template asset"),
            "parent_artifact_ids": list(row.get("parent_artifact_ids") or ()),
        })
    body = {
        "schema_version": TEMPLATE_MANIFEST_SCHEMA,
        "template_id": str(template_id or "none"),
        "template_version": template_version,
        "assets": rows,
    }
    body["asset_manifest_sha256"] = template_manifest_sha256(body)
    return body


def template_manifest_sha256(value: Mapping[str, object]) -> str:
    """Recompute the stable hash over the template identity and asset rows."""
    return _canonical_sha256({
        "schema_version": value.get("schema_version"),
        "template_id": value.get("template_id"),
        "template_version": value.get("template_version"),
        "assets": value.get("assets"),
    })


def compile_input_manifest_sha256(value: Mapping[str, object]) -> str:
    """Recompute the compilecheck manifest hash without trusting its claim."""
    return _canonical_sha256({
        "schema": value.get("schema"),
        "file_count": value.get("file_count"),
        "files": value.get("files"),
    })


__all__ = [
    "build_metrics",
    "build_outline_evidence",
    "build_report_json",
    "compile_input_manifest_sha256",
    "current_tex_structure",
    "issues_csv_bytes",
    "outline_evidence_errors",
    "project_dependency_path",
    "structured_blockers",
    "template_manifest",
    "template_manifest_sha256",
]
