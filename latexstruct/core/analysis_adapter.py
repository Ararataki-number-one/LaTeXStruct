# -*- coding: utf-8 -*-
"""Freeze an existing pipeline result as an immutable v2 analysis run.

This module is intentionally an adapter, not another analysis pipeline.  It
does not call a model, compile LaTeX, reinterpret a missing check as a pass, or
mutate any source artifact.  Its only job is to bind already-produced bytes
and machine evidence to host-owned identities and commit a portable audit tree
with one same-volume rename.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .analysis_runtime import (
    AnalysisQualityRuntime,
    CandidateRecord,
    ConservationReport,
    IssueLedger,
    PatchApplication,
    decide_final_status,
)
from .analysis_schema import (
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CompileState,
    IndependentReviewPass,
    IssueProposal,
    IssueStatus,
    ModelBinding,
    PageMapEntry,
    PageRisk,
    PageStatus,
    PageUnit,
    QualityVector,
    ReviewResult,
    Severity,
    TexAnchor,
    VerificationDecision,
    VerificationEvidence,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)
from .invariants import check_invariants


_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
_SHA256_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


@dataclass(frozen=True, slots=True)
class AnalysisRunArtifacts:
    """Exact artifacts already produced by the host pipeline.

    Empty bytes/text mean that the artifact does not exist.  The adapter keeps
    that absence explicit instead of manufacturing a preview, PDF, log, or
    verification result.
    """

    source_pdf: bytes = b""
    source_tex: str = ""
    raw_ocr_tex: str = ""
    baseline_tex: str = ""
    baseline_pdf: bytes = b""
    baseline_compile_log: str = ""
    current_tex: str = ""
    current_pdf: bytes = b""
    current_compile_log: str = ""
    verification: Mapping[str, Any] = field(default_factory=dict)
    decision_items: Sequence[Mapping[str, Any]] = ()
    report_md: str = ""
    rollback_history: Sequence[Mapping[str, Any]] = ()


@dataclass(frozen=True, slots=True)
class AnalysisRunArchiveResult:
    run_id: str
    run_directory: Path
    status: AnalysisFinalStatus
    verified: bool
    failures: tuple[str, ...]
    snapshot_sha256: str
    artifact_count: int
    sha256s_relative_path: str = "audit/SHA256SUMS"
    runtime_executed: bool = False
    best_candidate_id: str = ""
    candidate_count: int = 0
    rollback_count: int = 0
    review_pass_count: int = 0
    evidence_source: str = "missing-or-legacy"


class AnalysisArchiveError(ValueError):
    """The existing run cannot be frozen without violating audit integrity."""


class _ArchiveBuilder:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.roles: dict[str, str] = {}

    @staticmethod
    def _relative_path(value: str) -> str:
        raw = str(value or "").replace("\\", "/")
        path = PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(":" in part or "\x00" in part for part in path.parts)
        ):
            raise AnalysisArchiveError(f"unsafe archive path: {value!r}")
        return path.as_posix()

    def add_bytes(self, path: str, payload: bytes, *, role: str) -> None:
        relative = self._relative_path(path)
        if relative in self.files:
            raise AnalysisArchiveError(f"duplicate archive path: {relative}")
        self.files[relative] = bytes(payload)
        self.roles[relative] = str(role)

    def add_text(self, path: str, text: str, *, role: str) -> None:
        self.add_bytes(path, str(text).encode("utf-8"), role=role)

    def add_json(self, path: str, value: object, *, role: str) -> None:
        self.add_bytes(path, _pretty_json_bytes(value), role=role)

    def add_local_sums(self, directory: str) -> None:
        prefix = self._relative_path(directory).rstrip("/") + "/"
        name = prefix + "SHA256SUMS"
        entries = {
            path[len(prefix):]: payload
            for path, payload in self.files.items()
            if path.startswith(prefix) and path != name
        }
        if not entries:
            raise AnalysisArchiveError(f"cannot hash an empty artifact directory: {directory}")
        content = "".join(
            f"{sha256_bytes(payload)}  {path}\n"
            for path, payload in sorted(entries.items())
        )
        self.add_text(name, content, role="DIRECTORY_SHA256SUMS")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {"bytes": len(payload), "sha256": sha256_bytes(payload)}
    if isinstance(value, Path):
        # Host paths are never authoritative audit content.
        return value.name
    return value


def _pretty_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            _jsonable(value), ensure_ascii=False, indent=2, sort_keys=True, default=str
        )
        + "\n"
    ).encode("utf-8")


def stable_source_page_id(source_pdf_sha256: str, page_number: int) -> str:
    """Return the host-owned page identity used by generated v2 page maps."""

    digest = str(source_pdf_sha256 or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or int(page_number) < 1:
        raise ValueError("stable page identity requires a PDF hash and positive page")
    return f"src-{digest[:12]}-p{int(page_number):06d}"


def _coerce_models(values: Sequence[ModelBinding | Mapping[str, Any]]) -> tuple[ModelBinding, ...]:
    models = []
    for value in values:
        if isinstance(value, ModelBinding):
            models.append(value)
            continue
        item = dict(value)
        item["capabilities"] = tuple(item.get("capabilities", ()))
        models.append(ModelBinding(**item))
    if not models:
        raise AnalysisArchiveError("at least one real model binding is required")
    return tuple(models)


def _coerce_page_map(
    *,
    value: Sequence[PageMapEntry | Mapping[str, Any]] | None,
    source_pdf_hash: str,
    candidate_pdf_hash: str,
    page_range: tuple[int, ...],
) -> tuple[PageMapEntry, ...]:
    if value:
        entries = []
        for raw in value:
            if isinstance(raw, PageMapEntry):
                entries.append(raw)
                continue
            item = dict(raw)
            item["candidate_pdf_page_ids"] = tuple(item.get("candidate_pdf_page_ids", ()))
            entries.append(PageMapEntry(**item))
        return tuple(entries)
    candidate_root = candidate_pdf_hash[:12] if candidate_pdf_hash else "source-preview"
    return tuple(
        PageMapEntry(
            source_page_id=stable_source_page_id(source_pdf_hash, page),
            source_page_number=page,
            tex_page_marker=f"page:{page}",
            candidate_pdf_page_ids=(f"cand-{candidate_root}-p{index:06d}",),
        )
        for index, page in enumerate(page_range, 1)
    )


def _coerce_verification_evidence(
    value: VerificationEvidence | Mapping[str, Any] | None,
) -> VerificationEvidence | None:
    if value is None:
        return None
    if isinstance(value, VerificationEvidence):
        return value
    item = dict(value)
    try:
        item["expected_page_ids"] = tuple(item.get("expected_page_ids", ()))
        item["checked_page_ids"] = tuple(item.get("checked_page_ids", ()))
        reviews = []
        for review in item.get("final_reviews", ()):
            if isinstance(review, IndependentReviewPass):
                reviews.append(review)
            else:
                review_item = dict(review)
                review_item["checked_page_ids"] = tuple(
                    review_item.get("checked_page_ids", ())
                )
                reviews.append(IndependentReviewPass(**review_item))
        item["final_reviews"] = tuple(reviews)
        return VerificationEvidence(**item)
    except (KeyError, TypeError, ValueError):
        return None


def _line_anchor(text: str, line_number: int, candidate_id: str) -> TexAnchor | None:
    if line_number < 1:
        return None
    lines = text.splitlines(keepends=True)
    if line_number > len(lines):
        return None
    start = sum(len(item) for item in lines[: line_number - 1])
    line = lines[line_number - 1]
    body = line.rstrip("\r\n")
    end = start + len(body)
    seed = canonical_json_bytes({
        "candidate_id": candidate_id,
        "line": line_number,
        "start": start,
        "end": end,
        "text_hash": sha256_text(body),
    })
    return TexAnchor(
        anchor_id=f"anchor-{sha256_bytes(seed)[:16]}",
        start_offset=start,
        end_offset=end,
        text_hash=sha256_text(body),
    )


def _severity(value: object) -> Severity:
    raw = str(value or "MEDIUM").strip().upper()
    try:
        return Severity(raw)
    except ValueError:
        return Severity.MEDIUM


def _bind_decision_page(
    item: Mapping[str, Any], page_map: tuple[PageMapEntry, ...]
) -> str:
    by_id = {entry.source_page_id: entry.source_page_id for entry in page_map}
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    explicit = str(item.get("source_page_id") or item.get("page_id") or "")
    if explicit in by_id:
        return explicit
    for key in ("source_page_number", "page_number", "pdf_page", "page"):
        try:
            number = int(item.get(key))
        except (TypeError, ValueError):
            continue
        if number in by_number:
            return by_number[number]
    return ""


def _ledger_from_decisions(
    *,
    decision_items: Sequence[Mapping[str, Any]],
    page_map: tuple[PageMapEntry, ...],
    baseline_hash: str,
    candidate_hash: str,
    current_tex: str,
) -> tuple[IssueLedger, list[dict[str, Any]]]:
    ledger = IssueLedger()
    unbound: list[dict[str, Any]] = []
    desired: dict[str, tuple[str, str]] = {}
    priority = {"REJECTED": 0, "FIXED": 1, "OPEN": 2, "BLOCKED": 3}
    for index, raw in enumerate(decision_items):
        item = dict(raw)
        candidate_id = str(item.get("candidate_id") or f"decision-{index + 1}")
        page_id = _bind_decision_page(item, page_map)
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        anchor = _line_anchor(current_tex, line, candidate_id)
        if not page_id or anchor is None:
            unbound.append({
                "candidate_id": candidate_id,
                "reason": "missing stable page binding or exact TeX line anchor",
                "record_sha256": sha256_bytes(canonical_json_bytes(_jsonable(item))),
            })
            continue
        status = str(item.get("status") or "ambiguous").strip().casefold()
        description = str(item.get("reason") or item.get("title") or candidate_id)
        proposal = IssueProposal(
            issue_type=str(item.get("kind") or item.get("issue_type") or "STRUCTURE_DECISION"),
            severity=_severity(item.get("severity")),
            source_page_ids=(page_id,),
            tex_anchors=(anchor,),
            detector_role=str(item.get("source") or "pipeline"),
            evidence_hashes=(sha256_bytes(canonical_json_bytes(_jsonable(item))),),
            baseline_hash=baseline_hash,
            candidate_hash=candidate_hash,
            description=description,
            blocker_reason=description if status in {"ambiguous", "rejected"} else "",
        )
        record = ledger.upsert(proposal, round_index=0)
        if status == "applied":
            target = "FIXED"
        elif status in {"preserved", "none", "rejected_false_positive"}:
            target = "REJECTED"
        elif status == "rejected":
            target = "BLOCKED"
        else:
            target = "OPEN"
        previous = desired.get(record.issue_id)
        if previous is None or priority[target] > priority[previous[0]]:
            desired[record.issue_id] = (target, description)

    for issue_id, (target, reason) in desired.items():
        if target == "FIXED":
            ledger.transition(
                issue_id, IssueStatus.FIXING, round_index=1, patch_id=f"PATCH-{issue_id[4:]}"
            )
            ledger.transition(
                issue_id,
                IssueStatus.FIXED_PENDING_REVIEW,
                round_index=1,
                candidate_hash=candidate_hash,
            )
        elif target == "BLOCKED":
            ledger.transition(
                issue_id, IssueStatus.BLOCKED, round_index=1, blocker_reason=reason
            )
        elif target == "REJECTED":
            ledger.transition(issue_id, IssueStatus.REJECTED_FALSE_POSITIVE, round_index=1)
    return ledger, unbound


def _compile_state(pdf: bytes, verification_record: object) -> CompileState:
    record = verification_record if isinstance(verification_record, Mapping) else {}
    if pdf and record.get("ok") is True:
        return CompileState.COMPILED
    if pdf:
        return CompileState.PARTIAL_COMPILED
    return CompileState.SOURCE_PREVIEW


def _quality_payload(
    quality: QualityVector | Mapping[str, Any] | None,
    *,
    current_pdf: bytes,
    verification: Mapping[str, Any],
    ledger: IssueLedger,
) -> tuple[QualityVector, dict[str, Any]]:
    if isinstance(quality, QualityVector):
        vector = quality
        complete = True
        unknown: list[str] = []
    elif isinstance(quality, Mapping):
        vector = QualityVector(**dict(quality))
        complete = True
        unknown = []
    else:
        compile_after = verification.get("compile_after")
        compile_ok = bool(
            current_pdf
            and isinstance(compile_after, Mapping)
            and compile_after.get("ok") is True
        )
        counts = ledger.counts()
        formal = verification.get("final_formal_inventory")
        formal_errors = 0
        if isinstance(formal, Mapping):
            findings = formal.get("findings")
            formal_errors = len(findings) if isinstance(findings, list) else 0
        vector = QualityVector(
            fully_compiled=compile_ok,
            open_critical=sum(
                record.current_status not in {
                    IssueStatus.VERIFIED_CLOSED,
                    IssueStatus.REJECTED_FALSE_POSITIVE,
                }
                and record.severity == Severity.CRITICAL
                for record in ledger.records
            ),
            open_high=sum(
                record.current_status not in {
                    IssueStatus.VERIFIED_CLOSED,
                    IssueStatus.REJECTED_FALSE_POSITIVE,
                }
                and record.severity == Severity.HIGH
                for record in ledger.records
            ),
            formal_errors=formal_errors,
        )
        complete = False
        unknown = [
            "silent_page_omissions",
            "silent_text_losses",
            "unauthorized_math_changes",
            "structure_reference_errors",
            "footnote_figure_equation_errors",
            "severe_visual_errors",
            "ordinary_layout_errors",
        ]
        if counts.get(IssueStatus.BLOCKED.value, 0):
            unknown.append("blocked_issue_impact")
    return vector, {
        "schema": "latexstruct-analysis-quality-vector-v2",
        "evidence_complete": complete,
        "unknown_fields": unknown,
        "vector": _jsonable(vector),
        "priority_key": list(vector.priority_key),
    }


def _successful_compile_passes(record: object) -> int:
    """Read an explicit successful-pass count; never infer it from ``ok``."""

    if not isinstance(record, Mapping) or record.get("ok") is not True:
        return 0
    for key in ("successful_passes", "passes_completed"):
        try:
            value = int(record.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            return value
    return 0


def _formal_error_count(record: object) -> int:
    if not isinstance(record, Mapping):
        return 1
    findings = record.get("findings")
    if not isinstance(findings, list):
        return 1
    return sum(
        str(item.get("kind") or "") in {"missing", "wrong-env", "overwide", "duplicate"}
        for item in findings
        if isinstance(item, Mapping)
    )


def _coerce_review_passes(
    value: object,
    *,
    page_map: tuple[PageMapEntry, ...],
) -> list[IndependentReviewPass]:
    """Accept only explicit, hash-bound review records from the host pipeline."""

    if not isinstance(value, (list, tuple)):
        return []
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    output: list[IndependentReviewPass] = []
    for raw in value:
        if isinstance(raw, IndependentReviewPass):
            output.append(raw)
            continue
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        checked = []
        for page in item.get("checked_page_ids", ()):
            text = str(page or "")
            if text:
                checked.append(text)
        if not checked:
            for page in item.get("checked_source_pages", ()):
                try:
                    page_id = by_number.get(int(page))
                except (TypeError, ValueError):
                    page_id = None
                if page_id:
                    checked.append(page_id)
        item["checked_page_ids"] = tuple(dict.fromkeys(checked))
        try:
            output.append(IndependentReviewPass(**item))
        except (KeyError, TypeError, ValueError):
            continue
    return output


def _visual_review_pass(
    verification: Mapping[str, Any],
    *,
    page_map: tuple[PageMapEntry, ...],
    candidate_hash: str,
    pass_number: int,
    content_ok: bool,
    math_ok: bool,
    formal_ok: bool,
) -> IndependentReviewPass | None:
    """Bind the last real page audit to the exact final candidate hash.

    This is at most one review context.  It never fabricates the second context
    required by :func:`decide_final_status`.
    """

    loop = verification.get("visual_quality_loop")
    if not isinstance(loop, Mapping):
        return None
    if (
        loop.get("checked") is not True
        or loop.get("ok") is not True
        or loop.get("invalid")
        or loop.get("unresolved")
    ):
        return None
    rounds = loop.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        return None
    final_round = rounds[-1]
    if not isinstance(final_round, Mapping):
        return None
    if str(final_round.get("tex_sha256") or "") != candidate_hash:
        return None
    audit = final_round.get("ai_audit")
    compile_record = final_round.get("compile")
    if not isinstance(audit, Mapping) or not isinstance(compile_record, Mapping):
        return None
    if (
        audit.get("checked") is not True
        or audit.get("ok") is not True
        or audit.get("invalid")
        or audit.get("unresolved")
        or audit.get("suggestions")
    ):
        return None
    by_number = {entry.source_page_number: entry.source_page_id for entry in page_map}
    checked = []
    pages = audit.get("pages")
    if isinstance(pages, list):
        for page in pages:
            if not isinstance(page, Mapping):
                continue
            try:
                page_id = by_number.get(int(page.get("source_page")))
            except (TypeError, ValueError):
                page_id = None
            if page_id:
                checked.append(page_id)
    expected = tuple(entry.source_page_id for entry in page_map)
    checked_ids = tuple(dict.fromkeys(checked))
    if set(checked_ids) != set(expected):
        return None
    context_payload = {
        "schema": audit.get("schema"),
        "alignment_sha256": audit.get("alignment_sha256"),
        "candidate_hash": candidate_hash,
        "checked_page_ids": checked_ids,
    }
    return IndependentReviewPass(
        pass_number=pass_number,
        context_id=f"visual-{sha256_bytes(canonical_json_bytes(context_payload))[:16]}",
        candidate_hash=candidate_hash,
        checked_page_ids=checked_ids,
        compile_passes=_successful_compile_passes(compile_record),
        content_conservation_ok=content_ok,
        math_conservation_ok=math_ok,
        formal_inventory_ok=formal_ok,
        visual_review_ok=True,
        new_high_risk_issues=0,
        prior_pass_conclusion_visible=False,
    )


def _host_verification_evidence(
    *,
    verification: Mapping[str, Any],
    artifacts: AnalysisRunArtifacts,
    page_map: tuple[PageMapEntry, ...],
    candidate_hash: str,
    candidate_pdf: bytes,
    ledger: IssueLedger,
    pipeline_current: bool,
) -> VerificationEvidence:
    """Produce conservative v2 evidence from real legacy pipeline records."""

    expected = tuple(entry.source_page_id for entry in page_map)
    invariants = verification.get("invariants")
    invariants = invariants if isinstance(invariants, Mapping) else {}
    body = invariants.get("body_text")
    body = body if isinstance(body, Mapping) else {}
    math = invariants.get("math")
    math = math if isinstance(math, Mapping) else {}
    content_ok = bool(
        verification.get("content_invariant") is True
        and (body.get("equal") is True or body.get("checked") is not True)
    )
    math_ok = math.get("equal") is True
    formal_record = verification.get(
        "final_formal_inventory" if pipeline_current else "formal_inventory"
    )
    formal_errors = _formal_error_count(formal_record)
    formal_ok = formal_errors == 0
    compile_record = verification.get("compile_after" if pipeline_current else "compile_before")

    reviews = _coerce_review_passes(
        verification.get("v2_review_passes"), page_map=page_map
    ) if pipeline_current else []
    used_numbers = {item.pass_number for item in reviews}
    next_number = 1 if 1 not in used_numbers else 2 if 2 not in used_numbers else 0
    if pipeline_current and next_number:
        visual = _visual_review_pass(
            verification,
            page_map=page_map,
            candidate_hash=candidate_hash,
            pass_number=next_number,
            content_ok=content_ok,
            math_ok=math_ok,
            formal_ok=formal_ok,
        )
        if visual is not None and all(
            item.context_id != visual.context_id for item in reviews
        ):
            reviews.append(visual)
    reviews = sorted(reviews, key=lambda item: item.pass_number)
    fully_covered = bool(reviews) and all(
        set(item.checked_page_ids) == set(expected) for item in reviews
    )
    checked = expected if fully_covered else ()
    counts = ledger.counts()
    outline = verification.get("ocr_structure")
    outline = outline if isinstance(outline, Mapping) else {}
    display = verification.get("display_tags")
    display = display if isinstance(display, Mapping) else {}
    no_reference_loss = all(
        isinstance(invariants.get(name), Mapping)
        and invariants[name].get("equal") is True
        for name in ("labels", "refs", "cites")
    )
    raw_frozen = bool(
        artifacts.raw_ocr_tex
        and verification.get("raw_ocr_mutable") is not True
    )
    return VerificationEvidence(
        raw_ocr_frozen=raw_frozen,
        baseline_compile_passes=_successful_compile_passes(
            verification.get("compile_before")
        ),
        best_compile_passes=_successful_compile_passes(compile_record),
        best_pdf_openable=bool(candidate_pdf.startswith(b"%PDF-")),
        expected_page_ids=expected,
        checked_page_ids=checked,
        silent_page_omissions=0 if fully_covered else len(expected),
        silent_text_losses=0 if content_ok else 1,
        unauthorized_math_changes=0 if math_ok else 1,
        formal_errors=formal_errors,
        toc_complete_and_ordered=bool(
            outline.get("checked") is True and outline.get("ok") is True
        ),
        severe_equation_number_errors=0 if display.get("ok") is True else 1,
        silent_footnote_losses=0 if content_ok and fully_covered else 1,
        silent_figure_caption_losses=0 if content_ok and fully_covered else 1,
        silent_bibliography_losses=0 if content_ok and no_reference_loss else 1,
        open_critical=sum(
            record.current_status not in {
                IssueStatus.VERIFIED_CLOSED,
                IssueStatus.REJECTED_FALSE_POSITIVE,
            }
            and record.severity == Severity.CRITICAL
            for record in ledger.records
        ),
        open_high=sum(
            record.current_status not in {
                IssueStatus.VERIFIED_CLOSED,
                IssueStatus.REJECTED_FALSE_POSITIVE,
            }
            and record.severity == Severity.HIGH
            for record in ledger.records
        ),
        regressions=counts.get(IssueStatus.REGRESSION.value, 0),
        candidate_hash=candidate_hash,
        current_candidate_hash=candidate_hash,
        final_reviews=tuple(reviews),
    )


def _evidence_quality(evidence: VerificationEvidence) -> QualityVector:
    return QualityVector(
        fully_compiled=bool(
            evidence.best_compile_passes >= 2 and evidence.best_pdf_openable
        ),
        silent_page_omissions=evidence.silent_page_omissions,
        silent_text_losses=evidence.silent_text_losses,
        unauthorized_math_changes=evidence.unauthorized_math_changes,
        open_critical=evidence.open_critical,
        open_high=evidence.open_high,
        formal_errors=evidence.formal_errors,
        structure_reference_errors=evidence.silent_bibliography_losses,
        footnote_figure_equation_errors=(
            evidence.severe_equation_number_errors
            + evidence.silent_footnote_losses
            + evidence.silent_figure_caption_losses
        ),
        severe_visual_errors=0 if evidence.checked_page_ids else 1,
    )


def _reviews_close_fixed_issues(evidence: VerificationEvidence) -> bool:
    reviews = sorted(evidence.final_reviews, key=lambda item: item.pass_number)
    return bool(
        len(reviews) == 2
        and [item.pass_number for item in reviews] == [1, 2]
        and len({item.context_id for item in reviews}) == 2
        and all(
            item.candidate_hash == evidence.candidate_hash
            and set(item.checked_page_ids) == set(evidence.expected_page_ids)
            and item.compile_passes >= 2
            and item.content_conservation_ok
            and item.math_conservation_ok
            and item.formal_inventory_ok
            and item.visual_review_ok
            and item.new_high_risk_issues == 0
            and not item.prior_pass_conclusion_visible
            for item in reviews
        )
    )


def _derive_final_decision(
    *,
    evidence: VerificationEvidence | None,
    page_map: tuple[PageMapEntry, ...],
    current_tex_hash: str,
    artifacts: AnalysisRunArtifacts,
    processing_failed: bool,
    unbound_decisions: Sequence[Mapping[str, Any]],
    runtime: AnalysisQualityRuntime | None = None,
) -> tuple[VerificationDecision, str]:
    missing = []
    if not artifacts.source_pdf:
        missing.append("source_pdf_missing")
    if not artifacts.raw_ocr_tex:
        missing.append("raw_ocr_tex_missing")
    if not artifacts.baseline_tex:
        missing.append("baseline_tex_missing")
    if not artifacts.baseline_pdf:
        missing.append("baseline_pdf_missing")
    if not artifacts.current_tex:
        missing.append("current_tex_missing")
    if not artifacts.current_pdf:
        missing.append("current_pdf_missing")
    if unbound_decisions:
        missing.append("decision_items_not_page_bound")
    if processing_failed:
        missing.append("processing_failed")

    if evidence is None:
        failures = tuple(dict.fromkeys(["v2_verification_evidence_missing", *missing]))
        status = (
            AnalysisFinalStatus.FAILED_BEST_RETAINED
            if processing_failed
            else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
        )
        return VerificationDecision(status, False, failures), "missing-or-legacy"

    # Bind existing machine evidence to the exact bytes being archived.  Only
    # current_candidate_hash is host-updated; the machine's candidate_hash is
    # left untouched so stale evidence fails closed.
    bound = replace(evidence, current_candidate_hash=current_tex_hash)
    base = (
        runtime.final_decision(bound, processing_failed=processing_failed)
        if runtime is not None
        else decide_final_status(bound, processing_failed=processing_failed)
    )
    failures = list(base.failures)
    expected = {entry.source_page_id for entry in page_map}
    if set(evidence.expected_page_ids) != expected:
        failures.append("snapshot_page_ids_mismatch")
    if evidence.candidate_hash != current_tex_hash:
        failures.append("candidate_hash_not_current_artifact")
    failures.extend(missing)
    failures = list(dict.fromkeys(failures))
    if failures:
        status = (
            AnalysisFinalStatus.FAILED_BEST_RETAINED
            if processing_failed
            else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
        )
        return VerificationDecision(status, False, tuple(failures)), "v2-machine-evidence"
    return base, "v2-machine-evidence"


def _candidate_payloads(
    *,
    tex: str,
    pdf: bytes,
    compile_log: str,
    parent_hash: str,
    ledger: Mapping[str, Any],
    quality: Mapping[str, Any],
    review: Mapping[str, Any],
    diff: str,
    round_index: int,
    disposition: str,
) -> dict[str, bytes]:
    tex_hash = sha256_text(tex)
    payloads = {
        "candidate.tex": tex.encode("utf-8"),
        "compile.log": compile_log.encode("utf-8"),
        "patch.json": _pretty_json_bytes({
            "available": bool(diff),
            "parent_tex_sha256": parent_hash,
            "candidate_tex_sha256": tex_hash,
            "note": "captured from an existing pipeline result; no model was called by adapter",
        }),
        "candidate.diff": diff.encode("utf-8"),
        "issue_ledger.json": _pretty_json_bytes(ledger),
        "quality_vector.json": _pretty_json_bytes(quality),
        "review.json": _pretty_json_bytes(review),
        "candidate.json": _pretty_json_bytes({
            "schema": "latexstruct-analysis-candidate-v2",
            "round_index": round_index,
            "tex_sha256": tex_hash,
            "pdf_sha256": sha256_bytes(pdf) if pdf else "",
            "parent_tex_sha256": parent_hash,
            "disposition": disposition,
        }),
    }
    if pdf:
        payloads["candidate.pdf"] = bytes(pdf)
    return payloads


def _add_candidate_directory(
    builder: _ArchiveBuilder,
    directory: str,
    payloads: Mapping[str, bytes],
) -> None:
    for name, payload in payloads.items():
        builder.add_bytes(
            f"{directory}/{name}", payload, role=f"CANDIDATE_{name.upper()}"
        )
    builder.add_local_sums(directory)


def _performance_payload(
    value: Mapping[str, Any] | object | None,
    *,
    total_pages: int,
    decision: VerificationDecision,
) -> dict[str, Any]:
    if value is None:
        return {
            "schema": "latexstruct-analysis-performance-v2",
            "available": False,
            "total_pages": total_pages,
            "final_status": decision.status.value,
            "target_seconds": 10800.0,
            "target_met": False,
            "missing": ["real_timing_and_model_usage_metrics"],
        }
    raw = _jsonable(value)
    if not isinstance(raw, dict):
        raw = {"recorded": raw}
    previous = raw.get("final_status")
    if previous and previous != decision.status.value:
        raw["recorded_final_status"] = previous
    raw["final_status"] = decision.status.value
    raw.setdefault("schema", "latexstruct-analysis-performance-v2")
    raw.setdefault("available", True)
    raw.setdefault("total_pages", total_pages)
    return raw


def _atomic_commit(builder: _ArchiveBuilder, destination: Path) -> None:
    root = destination.parent
    root.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"immutable analysis run already exists: {destination.name}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=root))
    try:
        for relative, payload in sorted(builder.files.items()):
            path = temporary.joinpath(*PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        if destination.exists():
            raise FileExistsError(
                f"immutable analysis run already exists: {destination.name}"
            )
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def freeze_pipeline_analysis_run(
    *,
    project_dir: str | Path,
    run_id: str,
    project_id: str,
    artifacts: AnalysisRunArtifacts,
    page_range: Sequence[int],
    page_count: int,
    models: Sequence[ModelBinding | Mapping[str, Any]],
    application_version: str,
    verification_evidence: VerificationEvidence | Mapping[str, Any] | None = None,
    page_map: Sequence[PageMapEntry | Mapping[str, Any]] | None = None,
    page_risks: Mapping[int, PageRisk | str] | None = None,
    source_page_hashes: Mapping[int, str] | None = None,
    quality_vector: QualityVector | Mapping[str, Any] | None = None,
    performance_metrics: Mapping[str, Any] | object | None = None,
    processing_failed: bool = False,
    workflow_version: str = "analysis-loop-v2",
    prompt_version: str = "analysis-prompts-v2",
    latex_engine: str = "xelatex",
    concurrency_limit: int = 3,
    started_at: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> AnalysisRunArchiveResult:
    """Atomically freeze one real pipeline run under ``analysis-runs/<run_id>``.

    The caller supplies bytes that already exist and optional *machine-produced*
    ``VerificationEvidence``.  A legacy ``verification`` dictionary is retained
    as evidence but can never by itself produce ``VERIFIED``.  Reusing ``run_id``
    raises ``FileExistsError`` and leaves the prior archive untouched.
    """

    if not _RUN_ID_RE.fullmatch(str(run_id or "")):
        raise AnalysisArchiveError("run_id must be a portable host-generated identifier")
    if not str(project_id or "").strip():
        raise AnalysisArchiveError("project_id is required")
    selected = tuple(int(page) for page in page_range)
    if (
        not selected
        or tuple(sorted(selected)) != selected
        or len(selected) != len(set(selected))
        or selected[0] < 1
        or selected[-1] > int(page_count)
    ):
        raise AnalysisArchiveError("page_range must be unique, ordered, and within page_count")

    source_pdf = bytes(artifacts.source_pdf)
    baseline_pdf = bytes(artifacts.baseline_pdf)
    current_pdf = bytes(artifacts.current_pdf)
    source_pdf_hash = sha256_bytes(source_pdf)
    raw_hash = sha256_text(artifacts.raw_ocr_tex)
    baseline_hash = sha256_text(artifacts.baseline_tex)
    current_hash = sha256_text(artifacts.current_tex)
    baseline_pdf_hash = sha256_bytes(baseline_pdf)
    current_pdf_hash = sha256_bytes(current_pdf) if current_pdf else ""
    model_bindings = _coerce_models(models)
    page_entries = _coerce_page_map(
        value=page_map,
        source_pdf_hash=source_pdf_hash,
        candidate_pdf_hash=current_pdf_hash,
        page_range=selected,
    )

    ledger, unbound_decisions = _ledger_from_decisions(
        decision_items=tuple(artifacts.decision_items),
        page_map=page_entries,
        baseline_hash=baseline_hash,
        candidate_hash=current_hash,
        current_tex=artifacts.current_tex,
    )
    verification_dict = dict(artifacts.verification or {})
    if verification_evidence is not None:
        supplied_evidence = _coerce_verification_evidence(verification_evidence)
    else:
        supplied_evidence = _coerce_verification_evidence(
            verification_dict.get("v2_verification_evidence")
        )
        analysis_v2 = verification_dict.get("analysis_v2")
        if supplied_evidence is None and isinstance(analysis_v2, Mapping):
            supplied_evidence = _coerce_verification_evidence(
                analysis_v2.get("verification_evidence")
            )

    baseline_compile = verification_dict.get("compile_before")
    initial_compile_state = _compile_state(baseline_pdf, baseline_compile)
    initial_ledger_payload = ledger.to_dict()
    initial_ledger_counts = ledger.counts()
    configuration = {
        "workflow_version": workflow_version,
        "prompt_version": prompt_version,
        "application_version": application_version,
        "latex_engine": latex_engine,
        "concurrency_limit": concurrency_limit,
        "models": _jsonable(model_bindings),
        "caller_config": _jsonable(config or {}),
    }
    snapshot = AnalysisRunSnapshot(
        run_id=run_id,
        project_id=project_id,
        workflow_version=workflow_version,
        prompt_version=prompt_version,
        application_version=application_version,
        source_pdf_hash=source_pdf_hash,
        raw_ocr_tex_hash=raw_hash,
        baseline_tex_hash=baseline_hash,
        baseline_pdf_hash=baseline_pdf_hash,
        page_count=int(page_count),
        page_range=selected,
        latex_engine=latex_engine,
        models=model_bindings,
        concurrency_limit=int(concurrency_limit),
        started_at=started_at or datetime.now(timezone.utc).isoformat(),
        page_map=page_entries,
        initial_compile_state=initial_compile_state,
        initial_issue_counts=tuple(initial_ledger_counts.items()),
        config_hash=sha256_bytes(canonical_json_bytes(configuration)),
    )

    risks = dict(page_risks or {})
    supplied_page_hashes = dict(source_page_hashes or {})
    runtime_page_units = []
    for entry in page_entries:
        risk_value = risks.get(entry.source_page_number, PageRisk.R0)
        risk = risk_value if isinstance(risk_value, PageRisk) else PageRisk(str(risk_value))
        page_hash = supplied_page_hashes.get(entry.source_page_number)
        if not page_hash:
            page_hash = sha256_bytes(canonical_json_bytes({
                "source_pdf_sha256": source_pdf_hash,
                "source_page_number": entry.source_page_number,
            }))
        runtime_page_units.append(PageUnit(
            source_page_id=entry.source_page_id,
            source_page_number=entry.source_page_number,
            source_page_hash=page_hash,
            baseline_tex_start_anchor=f"baseline:{baseline_hash[:16]}:{entry.source_page_id}:start",
            baseline_tex_end_anchor=f"baseline:{baseline_hash[:16]}:{entry.source_page_id}:end",
            current_tex_start_anchor=f"current:{current_hash[:16]}:{entry.source_page_id}:start",
            current_tex_end_anchor=f"current:{current_hash[:16]}:{entry.source_page_id}:end",
            candidate_pdf_page_ids=entry.candidate_pdf_page_ids,
            current_render_paths=("candidates/best/candidate.pdf",) if current_pdf else (),
            risk_level=risk,
            risk_reasons=() if risk == PageRisk.R0 else ("host-supplied risk",),
            current_status=PageStatus.PENDING,
        ))

    attempted_evidence = supplied_evidence or _host_verification_evidence(
        verification=verification_dict,
        artifacts=artifacts,
        page_map=page_entries,
        candidate_hash=current_hash,
        candidate_pdf=current_pdf,
        ledger=ledger,
        pipeline_current=True,
    )
    evidence_source = (
        "v2-machine-evidence"
        if supplied_evidence is not None
        else "host-derived-pipeline-evidence"
    )
    if _reviews_close_fixed_issues(attempted_evidence):
        for record in tuple(ledger.records):
            if record.current_status != IssueStatus.FIXED_PENDING_REVIEW:
                continue
            ledger.close_after_review(
                record.issue_id,
                round_index=max(2, record.last_modified_round),
                candidate_hash=current_hash,
                review_result=ReviewResult.PASS,
                compile_ok=attempted_evidence.best_compile_passes >= 2,
                content_conservation_ok=attempted_evidence.silent_text_losses == 0,
                math_conservation_ok=attempted_evidence.unauthorized_math_changes == 0,
                visual_review_ok=True,
                new_high_priority_issues=0,
            )
        if supplied_evidence is None:
            attempted_evidence = _host_verification_evidence(
                verification=verification_dict,
                artifacts=artifacts,
                page_map=page_entries,
                candidate_hash=current_hash,
                candidate_pdf=current_pdf,
                ledger=ledger,
                pipeline_current=True,
            )

    if isinstance(quality_vector, QualityVector):
        current_vector = quality_vector
    elif isinstance(quality_vector, Mapping):
        current_vector = QualityVector(**dict(quality_vector))
    else:
        current_vector = _evidence_quality(attempted_evidence)
    baseline_evidence = _host_verification_evidence(
        verification=verification_dict,
        artifacts=artifacts,
        page_map=page_entries,
        candidate_hash=baseline_hash,
        candidate_pdf=baseline_pdf,
        ledger=IssueLedger.from_dict(initial_ledger_payload),
        pipeline_current=False,
    )
    baseline_vector = _evidence_quality(baseline_evidence)

    analysis_root = Path(project_dir) / "analysis-runs"
    analysis_root.mkdir(parents=True, exist_ok=True)
    runtime_stage = Path(tempfile.mkdtemp(prefix=f".{run_id}-runtime-", dir=analysis_root))
    runtime = AnalysisQualityRuntime(
        snapshot=snapshot,
        page_units=tuple(runtime_page_units),
        candidate_root=runtime_stage / "candidates",
        ledger=ledger,
    )
    runtime_records: list[CandidateRecord] = []
    runtime_payloads: dict[str, dict[str, bytes]] = {}
    try:
        baseline_record = runtime.candidates.save_baseline(
            tex=artifacts.baseline_tex,
            pdf=baseline_pdf,
            compile_log=artifacts.baseline_compile_log,
            quality=baseline_vector,
            issue_ledger=initial_ledger_payload,
        )
        runtime_records.append(baseline_record)
        attempted_record = baseline_record
        current_diff = "".join(difflib.unified_diff(
            artifacts.baseline_tex.splitlines(keepends=True),
            artifacts.current_tex.splitlines(keepends=True),
            fromfile="baseline/baseline.tex",
            tofile="candidates/current/candidate.tex",
        ))
        if artifacts.current_tex != artifacts.baseline_tex:
            invariant_checks = check_invariants(
                artifacts.baseline_tex,
                artifacts.current_tex,
                check_body_text=True,
            )
            unauthorized = tuple(
                name for name, result in invariant_checks.items()
                if name != "ok"
                and isinstance(result, Mapping)
                and result.get("equal") is not True
            )
            application = PatchApplication(
                patch_id=f"PATCH-{sha256_text(current_diff)[:16]}",
                parent_hash=baseline_hash,
                candidate_hash=current_hash,
                candidate_tex=artifacts.current_tex,
                diff=current_diff,
                affected_page_ids=tuple(entry.source_page_id for entry in page_entries),
                conservation=ConservationReport(
                    ok=not unauthorized,
                    checks=invariant_checks,
                    authorized_changes=(),
                    unauthorized_changes=unauthorized,
                ),
            )
            attempted_record = runtime.candidates.evaluate(
                application=application,
                round_index=1,
                pdf=current_pdf,
                compile_log=artifacts.current_compile_log,
                quality=current_vector,
                issue_ledger=ledger.to_dict(),
                review={"v2_verification_evidence": _jsonable(attempted_evidence)},
            )
            runtime_records.append(attempted_record)

        best_record = runtime.candidates.best
        if best_record is None:
            raise AnalysisArchiveError("quality runtime did not retain a best candidate")
        for record in runtime_records:
            directory = runtime.candidates.repository.root / record.candidate_id
            if not runtime.candidates.repository.verify(record.candidate_id):
                raise AnalysisArchiveError("quality runtime candidate hash verification failed")
            runtime_payloads[record.candidate_id] = {
                path.name: path.read_bytes()
                for path in directory.iterdir()
                if path.is_file()
            }
    finally:
        shutil.rmtree(runtime_stage, ignore_errors=True)

    best_is_current = best_record.tex_sha256 == current_hash
    best_tex = artifacts.current_tex if best_is_current else artifacts.baseline_tex
    best_pdf = current_pdf if best_is_current else baseline_pdf
    best_compile_log = (
        artifacts.current_compile_log if best_is_current else artifacts.baseline_compile_log
    )
    best_hash = best_record.tex_sha256
    if best_is_current:
        evidence = attempted_evidence
    else:
        evidence = _host_verification_evidence(
            verification=verification_dict,
            artifacts=artifacts,
            page_map=page_entries,
            candidate_hash=best_hash,
            candidate_pdf=best_pdf,
            ledger=ledger,
            pipeline_current=False,
        )
        evidence_source = "host-derived-history-best-evidence"

    effective_artifacts = replace(
        artifacts,
        current_tex=best_tex,
        current_pdf=best_pdf,
        current_compile_log=best_compile_log,
        rollback_history=tuple(artifacts.rollback_history) + tuple(
            _jsonable(item) for item in runtime.candidates.rollback_history
        ),
    )
    decision, _derived_source = _derive_final_decision(
        evidence=evidence,
        page_map=page_entries,
        current_tex_hash=best_hash,
        artifacts=effective_artifacts,
        processing_failed=processing_failed,
        unbound_decisions=unbound_decisions,
        runtime=runtime,
    )
    checked_page_ids = set(evidence.checked_page_ids)
    page_units = []
    for unit in runtime_page_units:
        checked = unit.source_page_id in checked_page_ids
        page_units.append(replace(
            unit,
            current_tex_start_anchor=(
                f"current:{best_hash[:16]}:{unit.source_page_id}:start"
            ),
            current_tex_end_anchor=(
                f"current:{best_hash[:16]}:{unit.source_page_id}:end"
            ),
            current_render_paths=("candidates/best/candidate.pdf",) if best_pdf else (),
            last_checked_candidate_hash=best_hash if checked else "",
            current_status=(
                PageStatus.VERIFIED
                if checked and decision.verified
                else PageStatus.CHECKED
                if checked
                else PageStatus.PENDING
            ),
        ))

    vector = best_record.quality
    quality_payload = {
        "schema": "latexstruct-analysis-quality-vector-v2",
        "evidence_complete": not bool(decision.failures),
        "unknown_fields": [] if not decision.failures else list(decision.failures),
        "vector": _jsonable(vector),
        "priority_key": list(vector.priority_key),
        "candidate_id": best_record.candidate_id,
        "host_runtime_derived": True,
    }
    ledger_payload = ledger.to_dict()
    ledger_payload["unbound_decision_items"] = unbound_decisions
    ledger_payload["counts"] = ledger.counts()
    review_payload = verification_dict.get("full_document_review")
    if not isinstance(review_payload, Mapping):
        review_payload = verification_dict.get("ai_review")
    if not isinstance(review_payload, Mapping):
        review_payload = {"available": False}

    builder = _ArchiveBuilder()
    if source_pdf:
        builder.add_bytes("inputs/source.pdf", source_pdf, role="SOURCE_PDF")
    if artifacts.source_tex:
        builder.add_text("inputs/source.tex", artifacts.source_tex, role="SOURCE_TEX")
    if artifacts.raw_ocr_tex:
        builder.add_text("baseline/raw_ocr.tex", artifacts.raw_ocr_tex, role="RAW_OCR_TEX")
    if artifacts.baseline_tex:
        builder.add_text("baseline/baseline.tex", artifacts.baseline_tex, role="BASELINE_TEX")
    if baseline_pdf:
        builder.add_bytes("baseline/baseline.pdf", baseline_pdf, role="BASELINE_PDF")
    builder.add_text(
        "baseline/baseline_compile.log",
        artifacts.baseline_compile_log,
        role="BASELINE_COMPILE_LOG",
    )
    builder.add_json("baseline/page_map.json", page_entries, role="PAGE_MAP")
    builder.add_local_sums("baseline")

    def committed_payloads(record: CandidateRecord) -> dict[str, bytes]:
        return {
            name: payload
            for name, payload in runtime_payloads[record.candidate_id].items()
            if name != "SHA256SUMS"
        }

    round_zero = committed_payloads(baseline_record)
    _add_candidate_directory(builder, "candidates/round_000", round_zero)
    # A no-op analysis is still a real candidate evaluation.  Keep round_001
    # even when its bytes equal the baseline so its ledger/review evidence does
    # not disappear behind round_000's deliberately empty baseline metadata.
    round_one = (
        committed_payloads(attempted_record)
        if attempted_record.candidate_id != baseline_record.candidate_id
        else _candidate_payloads(
            tex=artifacts.current_tex,
            pdf=current_pdf,
            compile_log=artifacts.current_compile_log,
            parent_hash=baseline_hash,
            ledger=ledger_payload,
            quality=quality_payload,
            review=dict(review_payload),
            diff=current_diff,
            round_index=1,
            disposition="NO_OP_HISTORY_BEST",
        )
    )
    _add_candidate_directory(builder, "candidates/round_001", round_one)
    best_payloads = committed_payloads(best_record)
    _add_candidate_directory(builder, "candidates/best", best_payloads)

    formal_inventory = verification_dict.get("final_formal_inventory")
    if not isinstance(formal_inventory, Mapping):
        formal_inventory = verification_dict.get("formal_inventory")
    if not isinstance(formal_inventory, Mapping):
        formal_inventory = {"available": False}
    invariants = verification_dict.get("invariants")
    invariants = invariants if isinstance(invariants, Mapping) else {}
    content_payload = {
        "available": bool("content_invariant" in verification_dict or "body_text" in invariants),
        "content_invariant": verification_dict.get("content_invariant"),
        "body_text": invariants.get("body_text"),
    }
    math_payload = {
        "available": "math" in invariants,
        "math": invariants.get("math"),
    }
    visual_payload = verification_dict.get("visual_quality_loop")
    if not isinstance(visual_payload, Mapping):
        visual_payload = {"available": False}
    compile_history = {
        "baseline": verification_dict.get("compile_before", {"available": False}),
        "current": verification_dict.get("compile_after", {"available": False}),
        "baseline_log_path": "baseline/baseline_compile.log",
        "current_log_path": "candidates/best/compile.log",
    }
    final_decision_payload = {
        "schema": "latexstruct-analysis-final-decision-v2",
        "status": decision.status.value,
        "verified": decision.verified,
        "failures": list(decision.failures),
        "evidence_source": evidence_source,
        "host_derived": True,
        "legacy_safe_to_export": verification_dict.get("safe_to_export"),
        "note": "Legacy success flags are retained as evidence and never promote VERIFIED.",
        "quality_runtime_executed": True,
        "best_candidate_id": best_record.candidate_id,
        "attempted_candidate_id": attempted_record.candidate_id,
        "rollback_count": len(runtime.candidates.rollback_history),
    }
    performance_payload = _performance_payload(
        performance_metrics,
        total_pages=len(selected),
        decision=decision,
    )
    builder.add_json("audit/analysis_run_snapshot.json", snapshot, role="ANALYSIS_RUN_SNAPSHOT")
    builder.add_json("audit/page_units.json", page_units, role="PAGE_UNITS")
    builder.add_json("audit/issue_ledger.json", ledger_payload, role="ISSUE_LEDGER")
    builder.add_json("audit/formal_inventory.json", formal_inventory, role="FORMAL_INVENTORY")
    builder.add_json("audit/content_conservation.json", content_payload, role="CONTENT_CONSERVATION")
    builder.add_json("audit/math_token_report.json", math_payload, role="MATH_TOKEN_REPORT")
    builder.add_json("audit/visual_review.json", visual_payload, role="VISUAL_REVIEW")
    builder.add_json("audit/compile_history.json", compile_history, role="COMPILE_HISTORY")
    builder.add_json(
        "audit/rollback_history.json",
        {"items": list(effective_artifacts.rollback_history)},
        role="ROLLBACK_HISTORY",
    )
    builder.add_json(
        "audit/quality_runtime.json",
        {
            "schema": "latexstruct-analysis-quality-runtime-v2",
            "executed": True,
            "candidate_ids": [record.candidate_id for record in runtime_records],
            "best_candidate_id": best_record.candidate_id,
            "attempted_candidate_id": attempted_record.candidate_id,
            "rollback_count": len(runtime.candidates.rollback_history),
            "evidence_source": evidence_source,
            "review_pass_count": len(evidence.final_reviews),
        },
        role="QUALITY_RUNTIME_STATE",
    )
    builder.add_json("audit/quality_vector.json", quality_payload, role="QUALITY_VECTOR")
    builder.add_json(
        "audit/performance_metrics.json", performance_payload, role="PERFORMANCE_METRICS"
    )
    builder.add_json(
        "audit/verification.json", verification_dict, role="PIPELINE_MACHINE_VERIFICATION"
    )
    builder.add_json(
        "audit/v2_verification_evidence.json",
        _jsonable(evidence),
        role="V2_VERIFICATION_EVIDENCE",
    )
    builder.add_json(
        "audit/decision_items.json", list(artifacts.decision_items), role="DECISION_ITEMS"
    )
    builder.add_json("audit/final_decision.json", final_decision_payload, role="FINAL_DECISION")
    builder.add_text("audit/final_report.md", artifacts.report_md, role="FINAL_REPORT")

    manifest_entries = [
        {
            "path": path,
            "artifact_role": builder.roles[path],
            "sha256": sha256_bytes(payload),
            "bytes": len(payload),
        }
        for path, payload in sorted(builder.files.items())
    ]
    manifest = {
        "schema": "latexstruct-analysis-run-artifact-manifest-v2",
        "run_id": run_id,
        "project_id": project_id,
        "status": decision.status.value,
        "verified": decision.verified,
        "paths_are_relative": True,
        "artifacts": manifest_entries,
    }
    builder.add_json("audit/artifact_manifest.json", manifest, role="ARTIFACT_MANIFEST")
    root_sums = "".join(
        f"{sha256_bytes(payload)}  {path}\n"
        for path, payload in sorted(builder.files.items())
        if path != "audit/SHA256SUMS"
    )
    builder.add_text("audit/SHA256SUMS", root_sums, role="RUN_SHA256SUMS")

    destination = Path(project_dir) / "analysis-runs" / run_id
    _atomic_commit(builder, destination)
    snapshot_path = destination / "audit" / "analysis_run_snapshot.json"
    return AnalysisRunArchiveResult(
        run_id=run_id,
        run_directory=destination,
        status=decision.status,
        verified=decision.verified,
        failures=decision.failures,
        snapshot_sha256=sha256_bytes(snapshot_path.read_bytes()),
        artifact_count=len(builder.files),
        runtime_executed=True,
        best_candidate_id=best_record.candidate_id,
        candidate_count=len(runtime_records),
        rollback_count=len(runtime.candidates.rollback_history),
        review_pass_count=len(evidence.final_reviews),
        evidence_source=evidence_source,
    )


def verify_frozen_analysis_run(run_directory: str | Path) -> bool:
    """Recompute the complete run SHA256SUMS without trusting its manifest."""

    root = Path(run_directory)
    manifest = root / "audit" / "SHA256SUMS"
    if not manifest.is_file():
        return False
    expected: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = _SHA256_LINE_RE.fullmatch(line)
            if not match:
                return False
            digest, raw_path = match.groups()
            relative = _ArchiveBuilder._relative_path(raw_path)
            if relative in expected or relative == "audit/SHA256SUMS":
                return False
            expected[relative] = digest
    except (OSError, UnicodeError, AnalysisArchiveError):
        return False
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest
    }
    if actual != set(expected):
        return False
    return all(
        sha256_bytes((root / PurePosixPath(path)).read_bytes()) == digest
        for path, digest in expected.items()
    )


__all__ = [
    "AnalysisArchiveError",
    "AnalysisRunArchiveResult",
    "AnalysisRunArtifacts",
    "freeze_pipeline_analysis_run",
    "stable_source_page_id",
    "verify_frozen_analysis_run",
]
