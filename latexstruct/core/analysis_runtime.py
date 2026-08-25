# -*- coding: utf-8 -*-
"""Deterministic runtime primitives for post-OCR AI analysis.

This module is the authority boundary around model calls.  It accepts only
proposals, resolves host-owned issue identities, applies hash-bound local
patches in memory, compares immutable candidates lexicographically, and
derives final status from machine evidence.  It never edits the raw OCR or
baseline artifacts and it does not change any existing export path.
"""

from __future__ import annotations

import copy
import difflib
import json
import math
import os
import re
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .analysis_recovery import (
    RecoveryValidationError,
    assert_plain_storage_path,
    path_is_link_or_reparse,
    parse_strict_json_bytes,
)
from .analysis_schema import (
    ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT,
    ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS,
    AnalysisCacheKey,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CandidateDisposition,
    IssueProposal,
    IssueRecord,
    IssueStatus,
    PageUnit,
    PatchOperationKind,
    PerformanceTargetStatus,
    QualityVector,
    ReviewResult,
    SEVERITY_ORDER,
    Severity,
    VerificationDecision,
    VerificationEvidence,
    canonical_json_bytes,
    sha256_bytes,
    sha256_text,
)
from .invariants import body_text_tokens, check_invariants


class LedgerTransitionError(ValueError):
    pass


class AnalysisCacheIntegrityError(RuntimeError):
    """A cache path is unsafe, so paid transport must not continue."""

    retryable = False
    fatal_analysis = True


class PatchRejected(ValueError):
    pass


class CandidateStoreError(ValueError):
    pass


_TRANSITIONS: dict[IssueStatus, frozenset[IssueStatus]] = {
    IssueStatus.OPEN: frozenset({
        IssueStatus.FIXING,
        IssueStatus.BLOCKED,
        IssueStatus.REJECTED_FALSE_POSITIVE,
    }),
    IssueStatus.FIXING: frozenset({
        IssueStatus.OPEN,
        IssueStatus.FIXED_PENDING_REVIEW,
        IssueStatus.BLOCKED,
    }),
    IssueStatus.FIXED_PENDING_REVIEW: frozenset({
        IssueStatus.OPEN,
        IssueStatus.BLOCKED,
        IssueStatus.REGRESSION,
    }),
    IssueStatus.VERIFIED_CLOSED: frozenset({IssueStatus.REGRESSION}),
    IssueStatus.BLOCKED: frozenset({IssueStatus.FIXING}),
    IssueStatus.REGRESSION: frozenset({IssueStatus.FIXING, IssueStatus.BLOCKED}),
    IssueStatus.REJECTED_FALSE_POSITIVE: frozenset({IssueStatus.OPEN}),
}


def _normal_words(value: str) -> str:
    return " ".join(re.findall(r"[\w]+", str(value or "").casefold(), re.UNICODE))


def _locations_overlap(left: IssueRecord, right: IssueProposal) -> bool:
    if not set(left.source_page_ids).intersection(right.source_page_ids):
        return False
    if any(a.overlaps(b) for a in left.tex_anchors for b in right.tex_anchors):
        return True
    if any(a.overlaps(b) for a in left.source_pdf_regions for b in right.source_pdf_regions):
        return True
    return False


def _same_issue(left: IssueRecord, right: IssueProposal) -> bool:
    if _normal_words(left.issue_type) != _normal_words(right.issue_type):
        return False
    if not _locations_overlap(left, right):
        return False
    if set(left.evidence_hashes).intersection(right.evidence_hashes):
        return True
    if any(
        a.anchor_id == b.anchor_id
        for a in left.tex_anchors
        for b in right.tex_anchors
    ):
        return True
    similarity = difflib.SequenceMatcher(
        None, _normal_words(left.description), _normal_words(right.description)
    ).ratio()
    return similarity >= 0.82


def _issue_seed(proposal: IssueProposal) -> str:
    location = {
        "issue_type": _normal_words(proposal.issue_type),
        "pages": proposal.source_page_ids,
        "anchors": [
            (item.anchor_id, item.start_offset, item.end_offset)
            for item in proposal.tex_anchors
        ],
        "regions": [
            (
                item.source_page_id,
                round(item.x0, 3),
                round(item.y0, 3),
                round(item.x1, 3),
                round(item.y1, 3),
            )
            for item in proposal.source_pdf_regions
        ],
    }
    return sha256_bytes(canonical_json_bytes(location))[:12]


class IssueLedger:
    """The sole host-side issue identity and lifecycle authority."""

    def __init__(self, records: Iterable[IssueRecord] = ()) -> None:
        self._records: dict[str, IssueRecord] = {}
        for record in records:
            if record.issue_id in self._records:
                raise ValueError(f"duplicate issue id: {record.issue_id}")
            self._records[record.issue_id] = record

    @property
    def records(self) -> tuple[IssueRecord, ...]:
        return tuple(self._records[key] for key in sorted(self._records))

    def get(self, issue_id: str) -> IssueRecord:
        try:
            return self._records[issue_id]
        except KeyError as exc:
            raise KeyError(f"unknown issue id: {issue_id}") from exc

    def _new_issue_id(self, proposal: IssueProposal) -> str:
        root = f"ISS-{_issue_seed(proposal)}"
        issue_id = root
        counter = 2
        while issue_id in self._records:
            issue_id = f"{root}-{counter}"
            counter += 1
        return issue_id

    def upsert(self, proposal: IssueProposal, *, round_index: int) -> IssueRecord:
        if round_index < 0:
            raise ValueError("round_index cannot be negative")
        matches = [record for record in self.records if _same_issue(record, proposal)]
        if len(matches) > 1:
            # Ambiguous ledger topology is not delegated back to a model.
            raise ValueError("proposal overlaps multiple host issues")
        if not matches:
            record = IssueRecord(
                issue_id=self._new_issue_id(proposal),
                issue_type=proposal.issue_type,
                severity=proposal.severity,
                source_page_ids=proposal.source_page_ids,
                source_pdf_regions=proposal.source_pdf_regions,
                tex_anchors=proposal.tex_anchors,
                current_status=IssueStatus.OPEN,
                first_found_round=round_index,
                last_modified_round=round_index,
                detector_roles=(proposal.detector_role,),
                evidence_hashes=proposal.evidence_hashes,
                baseline_hash=proposal.baseline_hash,
                candidate_hash=proposal.candidate_hash,
                blocker_reason=proposal.blocker_reason,
                description=proposal.description,
            )
            self._records[record.issue_id] = record
            return record

        old = matches[0]
        status = old.current_status
        regressions = old.regression_count
        if old.current_status == IssueStatus.VERIFIED_CLOSED:
            status = IssueStatus.REGRESSION
            regressions += 1
        elif old.current_status == IssueStatus.REJECTED_FALSE_POSITIVE:
            status = IssueStatus.OPEN
        severity = min((old.severity, proposal.severity), key=SEVERITY_ORDER.get)
        updated = replace(
            old,
            severity=severity,
            source_page_ids=tuple(sorted(set(old.source_page_ids + proposal.source_page_ids))),
            source_pdf_regions=tuple(dict.fromkeys(old.source_pdf_regions + proposal.source_pdf_regions)),
            tex_anchors=tuple(dict.fromkeys(old.tex_anchors + proposal.tex_anchors)),
            current_status=status,
            last_modified_round=round_index,
            detector_roles=tuple(sorted(set(old.detector_roles + (proposal.detector_role,)))),
            evidence_hashes=tuple(sorted(set(old.evidence_hashes + proposal.evidence_hashes))),
            candidate_hash=proposal.candidate_hash,
            review_result=None if status == IssueStatus.REGRESSION else old.review_result,
            regression_count=regressions,
            blocker_reason=proposal.blocker_reason or old.blocker_reason,
            description=proposal.description or old.description,
        )
        self._records[old.issue_id] = updated
        return updated

    def transition(
        self,
        issue_id: str,
        status: IssueStatus,
        *,
        round_index: int,
        candidate_hash: str | None = None,
        patch_id: str = "",
        blocker_reason: str = "",
    ) -> IssueRecord:
        old = self.get(issue_id)
        if status == IssueStatus.VERIFIED_CLOSED:
            raise LedgerTransitionError("VERIFIED_CLOSED requires independent review evidence")
        if status not in _TRANSITIONS[old.current_status]:
            raise LedgerTransitionError(
                f"illegal issue transition: {old.current_status.value} -> {status.value}"
            )
        updated = replace(
            old,
            current_status=status,
            last_modified_round=round_index,
            candidate_hash=candidate_hash or old.candidate_hash,
            proposed_patch_id=patch_id or old.proposed_patch_id,
            retry_count=old.retry_count + (1 if status == IssueStatus.FIXING else 0),
            blocker_reason=blocker_reason or old.blocker_reason,
        )
        self._records[issue_id] = updated
        return updated

    def close_after_review(
        self,
        issue_id: str,
        *,
        round_index: int,
        candidate_hash: str,
        review_result: ReviewResult,
        compile_ok: bool,
        content_conservation_ok: bool,
        math_conservation_ok: bool,
        visual_review_ok: bool,
        new_high_priority_issues: int,
    ) -> IssueRecord:
        old = self.get(issue_id)
        if old.current_status != IssueStatus.FIXED_PENDING_REVIEW:
            raise LedgerTransitionError("only FIXED_PENDING_REVIEW can be independently closed")
        if candidate_hash != old.candidate_hash:
            raise LedgerTransitionError("review candidate hash does not match the issue")
        passed = (
            review_result == ReviewResult.PASS
            and compile_ok
            and content_conservation_ok
            and math_conservation_ok
            and visual_review_ok
            and new_high_priority_issues == 0
        )
        if passed:
            status = IssueStatus.VERIFIED_CLOSED
        elif review_result == ReviewResult.REGRESSION:
            status = IssueStatus.REGRESSION
        elif review_result == ReviewResult.UNCERTAIN:
            status = IssueStatus.BLOCKED
        else:
            status = IssueStatus.OPEN
        updated = replace(
            old,
            current_status=status,
            last_modified_round=round_index,
            review_result=review_result,
            regression_count=old.regression_count + (status == IssueStatus.REGRESSION),
            blocker_reason=(
                "independent review remained uncertain"
                if status == IssueStatus.BLOCKED
                else old.blocker_reason
            ),
        )
        self._records[issue_id] = updated
        return updated

    def counts(self) -> dict[str, int]:
        output = {status.value: 0 for status in IssueStatus}
        for record in self._records.values():
            output[record.current_status.value] += 1
        return output

    def unresolved(self) -> tuple[IssueRecord, ...]:
        closed = {IssueStatus.VERIFIED_CLOSED, IssueStatus.REJECTED_FALSE_POSITIVE}
        return tuple(record for record in self.records if record.current_status not in closed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "latexstruct-analysis-issue-ledger-v2",
            "issues": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IssueLedger":
        from .analysis_schema import PdfRegion, TexAnchor

        records = []
        for raw in value.get("issues", []):
            item = dict(raw)
            item["severity"] = Severity(item["severity"])
            item["current_status"] = IssueStatus(item["current_status"])
            item["review_result"] = (
                ReviewResult(item["review_result"]) if item.get("review_result") else None
            )
            item["source_page_ids"] = tuple(item.get("source_page_ids", ()))
            item["source_pdf_regions"] = tuple(
                PdfRegion(**region) for region in item.get("source_pdf_regions", ())
            )
            item["tex_anchors"] = tuple(
                TexAnchor(**anchor) for anchor in item.get("tex_anchors", ())
            )
            for name in ("detector_roles", "evidence_hashes", "related_issue_ids"):
                item[name] = tuple(item.get(name, ()))
            records.append(IssueRecord(**item))
        return cls(records)


@dataclass(frozen=True, slots=True)
class PatchScope:
    issue_id: str
    candidate_hash: str
    start_offset: int
    end_offset: int
    source_page_ids: tuple[str, ...]
    allowed_invariant_changes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ISS-[0-9a-f]{12}(?:-[0-9]+)?", self.issue_id):
            raise ValueError("patch scope must reference a host issue id")
        if self.start_offset < 0 or self.end_offset <= self.start_offset:
            raise ValueError("patch scope must be a non-empty local range")
        if not self.source_page_ids:
            raise ValueError("patch scope requires source pages")
        if not re.fullmatch(r"[0-9a-f]{64}", self.candidate_hash):
            raise ValueError("patch scope candidate hash is invalid")
        allowed = frozenset({"body_text", "math", "labels", "refs", "cites", "images"})
        if not set(self.allowed_invariant_changes).issubset(allowed):
            raise ValueError("patch scope contains an unknown invariant authorization")
        object.__setattr__(self, "source_page_ids", tuple(self.source_page_ids))
        object.__setattr__(
            self, "allowed_invariant_changes", tuple(sorted(set(self.allowed_invariant_changes)))
        )


@dataclass(frozen=True, slots=True)
class PatchOperation:
    operation: PatchOperationKind
    issue_ids: tuple[str, ...]
    start_anchor: str
    end_anchor: str
    expected_old_hash: str
    replacement: str
    source_page_ids: tuple[str, ...]
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.issue_ids or not all(
            re.fullmatch(r"ISS-[0-9a-f]{12}(?:-[0-9]+)?", item)
            for item in self.issue_ids
        ):
            raise ValueError("patch operations require host issue ids")
        if not self.start_anchor or not self.end_anchor:
            raise ValueError("patch operations require two stable anchors")
        if not re.fullmatch(r"[0-9a-f]{64}", self.expected_old_hash):
            raise ValueError("expected_old_hash is invalid")
        if not self.source_page_ids:
            raise ValueError("patch operations require source pages")
        object.__setattr__(self, "issue_ids", tuple(sorted(set(self.issue_ids))))
        object.__setattr__(self, "source_page_ids", tuple(sorted(set(self.source_page_ids))))


@dataclass(frozen=True, slots=True)
class PatchPlan:
    candidate_hash: str
    issue_ids: tuple[str, ...]
    operations: tuple[PatchOperation, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.candidate_hash):
            raise ValueError("patch plan candidate hash is invalid")
        issues = tuple(sorted(set(self.issue_ids)))
        operations = tuple(self.operations)
        if not issues or not operations:
            raise ValueError("patch plan must contain issues and operations")
        if any(not set(operation.issue_ids).issubset(issues) for operation in operations):
            raise ValueError("operation references an issue outside the plan")
        object.__setattr__(self, "issue_ids", issues)
        object.__setattr__(self, "operations", operations)

    @property
    def patch_id(self) -> str:
        payload = {
            "candidate_hash": self.candidate_hash,
            "issue_ids": self.issue_ids,
            "operations": [
                {
                    "operation": item.operation.value,
                    "issue_ids": item.issue_ids,
                    "start_anchor": item.start_anchor,
                    "end_anchor": item.end_anchor,
                    "expected_old_hash": item.expected_old_hash,
                    "replacement_hash": sha256_text(item.replacement),
                    "source_page_ids": item.source_page_ids,
                }
                for item in self.operations
            ],
        }
        return "PATCH-" + sha256_bytes(canonical_json_bytes(payload))[:16]


@dataclass(frozen=True, slots=True)
class ConservationReport:
    ok: bool
    checks: Mapping[str, Mapping[str, Any]]
    authorized_changes: tuple[str, ...]
    unauthorized_changes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", copy.deepcopy(dict(self.checks)))


@dataclass(frozen=True, slots=True)
class PatchApplication:
    patch_id: str
    parent_hash: str
    candidate_hash: str
    candidate_tex: str
    diff: str
    affected_page_ids: tuple[str, ...]
    conservation: ConservationReport


def _find_all(text: str, needle: str) -> list[int]:
    indexes: list[int] = []
    cursor = 0
    while True:
        index = text.find(needle, cursor)
        if index < 0:
            return indexes
        indexes.append(index)
        cursor = index + max(1, len(needle))


def _resolve_anchor_pair(text: str, start_anchor: str, end_anchor: str) -> tuple[int, int]:
    starts = _find_all(text, start_anchor)
    matches: list[tuple[int, int]] = []
    for start in starts:
        if start_anchor == end_anchor:
            matches.append((start, start + len(start_anchor)))
            continue
        cursor = start + len(start_anchor)
        end = text.find(end_anchor, cursor)
        if end >= 0:
            matches.append((start, end + len(end_anchor)))
    if len(matches) != 1:
        raise PatchRejected("patch anchors do not resolve to exactly one current range")
    return matches[0]


def _scope_for_operation(
    operation: PatchOperation,
    scopes: Mapping[str, PatchScope],
    start: int,
    end: int,
) -> tuple[PatchScope, ...]:
    selected: list[PatchScope] = []
    for issue_id in operation.issue_ids:
        scope = scopes.get(issue_id)
        if scope is None:
            raise PatchRejected(f"missing host patch scope for {issue_id}")
        selected.append(scope)
    allowed_pages = set().union(*(scope.source_page_ids for scope in selected))
    if not set(operation.source_page_ids).issubset(allowed_pages):
        raise PatchRejected("patch source pages exceed the host-authorized issue pages")
    if not any(scope.start_offset <= start and end <= scope.end_offset for scope in selected):
        raise PatchRejected("patch range exceeds every host-authorized issue boundary")
    return tuple(selected)


def apply_patch_plan(
    current_tex: str,
    plan: PatchPlan,
    *,
    scopes: Mapping[str, PatchScope],
) -> PatchApplication:
    """Apply a batch only after every immutable hash and local range matches."""

    current_hash = sha256_text(current_tex)
    if plan.candidate_hash != current_hash:
        raise PatchRejected("candidate_hash does not match the current TeX")
    if set(scopes) != set(plan.issue_ids):
        raise PatchRejected("host patch scopes must exactly match the plan issue ids")
    if any(scope.candidate_hash != current_hash for scope in scopes.values()):
        raise PatchRejected("a host patch scope belongs to a stale candidate")

    resolved: list[tuple[int, int, int, int, str, PatchOperation, tuple[PatchScope, ...]]] = []
    authorized: set[str] = set()
    for operation in plan.operations:
        start, end = _resolve_anchor_pair(
            current_tex, operation.start_anchor, operation.end_anchor
        )
        old = current_tex[start:end]
        if sha256_text(old) != operation.expected_old_hash:
            raise PatchRejected("expected_old_hash does not match the resolved current range")
        selected_scopes = _scope_for_operation(operation, scopes, start, end)
        authorized.update(
            category
            for scope in selected_scopes
            for category in scope.allowed_invariant_changes
        )
        if operation.operation == PatchOperationKind.INSERT_BEFORE:
            edit_start = edit_end = start
            replacement_text = operation.replacement
        elif operation.operation == PatchOperationKind.INSERT_AFTER:
            edit_start = edit_end = end
            replacement_text = operation.replacement
        else:
            edit_start, edit_end = start, end
            replacement_text = operation.replacement
        if re.search(r"\\documentclass\b|\\begin\{document\}|\\end\{document\}", replacement_text):
            raise PatchRejected("a local patch cannot replace the document shell or class")
        if (
            operation.operation == PatchOperationKind.REPLACE
            and edit_start == 0
            and edit_end == len(current_tex)
        ):
            raise PatchRejected("whole-document replacement is forbidden")
        resolved.append(
            (edit_start, edit_end, start, end, replacement_text, operation, selected_scopes)
        )

    ordered = sorted(resolved, key=lambda item: (item[0], item[1]))
    for left, right in zip(ordered, ordered[1:]):
        if right[0] < left[1] or (right[0] == left[0] and left[0] == left[1]):
            raise PatchRejected("patch operations overlap or target the same insertion point")

    candidate = current_tex
    for edit_start, edit_end, _start, _end, replacement_text, _operation, _scopes in reversed(ordered):
        candidate = candidate[:edit_start] + replacement_text + candidate[edit_end:]

    checks = check_invariants(current_tex, candidate, check_body_text=True)
    # ``body_text_tokens`` intentionally includes math internals in the legacy
    # invariant.  A host-authorized math repair therefore also changes that
    # aggregate even when every non-math body token is untouched.  Recompute a
    # math-elided body comparison so math authorization cannot accidentally
    # authorize unrelated prose edits.
    if "math" in authorized and not checks["body_text"]["equal"]:
        def without_math(value: str) -> str:
            output = value
            patterns = (
                r"\$\$.*?\$\$",
                r"\\\[.*?\\\]",
                r"\\\(.*?\\\)",
                r"(?<!\\)\$[^$\n]*\$",
                r"\\begin\{(?:equation|align|gather|multline|eqnarray|alignat|flalign)\*?\}"
                r".*?\\end\{(?:equation|align|gather|multline|eqnarray|alignat|flalign)\*?\}",
            )
            for pattern in patterns:
                output = re.sub(pattern, " ", output, flags=re.DOTALL)
            return output

        before_body = body_text_tokens(without_math(current_tex))
        after_body = body_text_tokens(without_math(candidate))
        if before_body == after_body:
            checks["body_text"] = {
                **checks["body_text"],
                "equal": True,
                "math_elided": True,
            }
    changed = tuple(sorted(
        name
        for name, result in checks.items()
        if name != "ok" and isinstance(result, Mapping) and not result.get("equal", False)
    ))
    unauthorized = tuple(name for name in changed if name not in authorized)
    conservation = ConservationReport(
        ok=not unauthorized,
        checks={name: value for name, value in checks.items() if name != "ok"},
        authorized_changes=tuple(name for name in changed if name in authorized),
        unauthorized_changes=unauthorized,
    )
    if not conservation.ok:
        raise PatchRejected(
            "patch violates host content conservation: " + ", ".join(unauthorized)
        )
    diff = "".join(difflib.unified_diff(
        current_tex.splitlines(keepends=True),
        candidate.splitlines(keepends=True),
        fromfile=f"{current_hash}.tex",
        tofile=f"{sha256_text(candidate)}.tex",
    ))
    return PatchApplication(
        patch_id=plan.patch_id,
        parent_hash=current_hash,
        candidate_hash=sha256_text(candidate),
        candidate_tex=candidate,
        diff=diff,
        affected_page_ids=tuple(sorted({
            page for operation in plan.operations for page in operation.source_page_ids
        })),
        conservation=conservation,
    )


@dataclass(frozen=True, slots=True)
class CandidateRecord:
    candidate_id: str
    parent_candidate_id: str
    round_index: int
    tex_sha256: str
    pdf_sha256: str
    quality: QualityVector
    disposition: CandidateDisposition
    reason: str
    artifact_directory: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["disposition"] = self.disposition.value
        return payload


def _portable_candidate_id(candidate_id: str) -> str:
    value = str(candidate_id or "")
    if not re.fullmatch(r"cand-r\d{4}-[0-9a-f]{12}", value):
        raise CandidateStoreError("candidate id is not host-generated or portable")
    return value


def make_candidate_id(round_index: int, tex_sha256: str) -> str:
    if round_index < 0 or not re.fullmatch(r"[0-9a-f]{64}", tex_sha256):
        raise ValueError("invalid candidate identity inputs")
    return f"cand-r{round_index:04d}-{tex_sha256[:12]}"


def _json_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CandidateStoreError(
            "candidate evidence is not strictly JSON serializable"
        ) from exc
    return (encoded + "\n").encode("utf-8")


_BASELINE_INPUT_DIRECTORY = "baseline-input"
_BASELINE_INPUT_FILES = frozenset({
    "baseline.tex",
    "baseline.pdf",
    "compile.log",
    "metadata.json",
})

_CANDIDATE_REQUIRED_FILES = frozenset({
    "candidate.tex",
    "compile.log",
    "patch.json",
    "candidate.diff",
    "issue_ledger.json",
    "quality_vector.json",
    "review.json",
    "candidate.json",
})
_CANDIDATE_JSON_FILES = frozenset({
    "patch.json",
    "issue_ledger.json",
    "quality_vector.json",
    "review.json",
    "candidate.json",
})
_CANDIDATE_METADATA_FIELDS = frozenset({
    "candidate_id",
    "parent_candidate_id",
    "round_index",
    "tex_sha256",
    "pdf_sha256",
    "quality",
    "disposition",
    "reason",
    "artifact_directory",
})
_QUALITY_VECTOR_FIELDS = frozenset({
    "fully_compiled",
    "silent_page_omissions",
    "silent_text_losses",
    "unauthorized_math_changes",
    "open_critical",
    "open_high",
    "formal_errors",
    "structure_reference_errors",
    "footnote_figure_equation_errors",
    "severe_visual_errors",
    "ordinary_layout_errors",
})


def _storage_entry_exists(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CandidateStoreError(f"cannot inspect candidate storage path: {path}") from exc


def _assert_plain_candidate_path(path: Path, *, label: str) -> None:
    try:
        assert_plain_storage_path(path)
    except RecoveryValidationError as exc:
        raise CandidateStoreError(f"{label} is unsafe") from exc


def _read_candidate_file(path: Path) -> bytes:
    _assert_plain_candidate_path(path, label="candidate artifact path")
    try:
        linked = path_is_link_or_reparse(path)
    except RecoveryValidationError as exc:
        raise CandidateStoreError("cannot inspect candidate artifact path") from exc
    if linked:
        raise CandidateStoreError("candidate artifact is a link or reparse point")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateStoreError(f"cannot open candidate artifact: {path.name}") from exc
    try:
        item_stat = os.fstat(descriptor)
        if not stat.S_ISREG(item_stat.st_mode):
            raise CandidateStoreError(
                f"candidate artifact is not a regular file: {path.name}"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    _assert_plain_candidate_path(path, label="candidate artifact path")
    return payload


def _write_new_candidate_file(path: Path, payload: bytes) -> None:
    _assert_plain_candidate_path(path.parent, label="candidate staging directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - defensive OS contract check
                raise OSError("short write while persisting candidate artifact")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _assert_plain_candidate_path(path, label="candidate staging artifact")


def _remove_candidate_temp(path: Path) -> None:
    try:
        item_stat = os.lstat(path)
    except FileNotFoundError:
        return
    if path_is_link_or_reparse(path):
        if stat.S_ISDIR(item_stat.st_mode):
            os.rmdir(path)
        else:
            path.unlink()
        return
    if stat.S_ISDIR(item_stat.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _directory_matches_payloads(directory: Path, payloads: Mapping[str, bytes]) -> bool:
    if not _storage_entry_exists(directory):
        return False
    _assert_plain_candidate_path(directory, label="candidate directory")
    if path_is_link_or_reparse(directory):
        raise CandidateStoreError("candidate directory is a link or reparse point")
    try:
        directory_stat = os.lstat(directory)
        entries = tuple(os.scandir(directory))
    except OSError as exc:
        raise CandidateStoreError("cannot inspect immutable candidate directory") from exc
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise CandidateStoreError("immutable candidate path is not a directory")
    if {entry.name for entry in entries} != set(payloads):
        return False
    for name, expected in payloads.items():
        if _read_candidate_file(directory / name) != expected:
            return False
    return True


def _quality_vector_from_json(value: Any) -> QualityVector:
    if not isinstance(value, dict) or set(value) != _QUALITY_VECTOR_FIELDS:
        raise CandidateStoreError("candidate quality vector schema is not exact")
    if type(value["fully_compiled"]) is not bool:
        raise CandidateStoreError("candidate fully_compiled value is not boolean")
    for name in _QUALITY_VECTOR_FIELDS - {"fully_compiled"}:
        count = value[name]
        if type(count) is not int or count < 0:
            raise CandidateStoreError(f"candidate quality count is invalid: {name}")
    return QualityVector(**value)


class CandidateRepository:
    """Write-once candidate directories committed with one same-volume rename."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        try:
            assert_plain_storage_path(self.root)
            self.root.mkdir(parents=True, exist_ok=True)
            assert_plain_storage_path(self.root)
            root_stat = os.lstat(self.root)
            root_is_link = path_is_link_or_reparse(self.root)
        except (OSError, RecoveryValidationError) as exc:
            raise CandidateStoreError("candidate repository root is unsafe") from exc
        if root_is_link or not stat.S_ISDIR(root_stat.st_mode):
            raise CandidateStoreError("candidate repository root is not a plain directory")

    def _reuse_exact_candidate(
        self,
        *,
        destination: Path,
        payloads: Mapping[str, bytes],
        record: CandidateRecord,
    ) -> CandidateRecord:
        try:
            exact = _directory_matches_payloads(destination, payloads)
        except (CandidateStoreError, OSError, RecoveryValidationError) as exc:
            raise CandidateStoreError(
                "immutable candidate already exists with unsafe or invalid evidence"
            ) from exc
        if not exact:
            raise CandidateStoreError(
                "immutable candidate already exists with different or invalid evidence"
            )
        return record

    def save_baseline_input_checkpoint(
        self,
        *,
        run_id: str,
        tex: str,
        pdf: bytes,
        compile_log: str,
        compile_passes: int,
        pdf_openable: bool,
    ) -> Mapping[str, Any]:
        """Atomically freeze recovery evidence before model discovery.

        This checkpoint deliberately is not a ``CandidateRecord`` and does
        not initialize the history-best controller.  It preserves the
        already-verified baseline inputs when the first discovery wave fails,
        while allowing the real selection baseline to be created later with
        the completed issue ledger.  Repeating the call with byte-identical
        evidence is idempotent; existing evidence is never overwritten.
        """

        normalized_run_id = str(run_id).strip()
        tex_bytes = str(tex).encode("utf-8")
        pdf_bytes = bytes(pdf)
        log_bytes = str(compile_log).encode("utf-8")
        passes = int(compile_passes)
        if not normalized_run_id:
            raise CandidateStoreError("baseline input checkpoint requires a run id")
        if passes < 2 or not pdf_openable or not pdf_bytes:
            raise CandidateStoreError(
                "baseline input checkpoint requires an openable two-pass PDF"
            )
        metadata: dict[str, Any] = {
            "artifact_type": "latexstruct-analysis-baseline-input-v1",
            "run_id": normalized_run_id,
            "baseline_tex_sha256": sha256_bytes(tex_bytes),
            "baseline_pdf_sha256": sha256_bytes(pdf_bytes),
            "compile_log_sha256": sha256_bytes(log_bytes),
            "compile_passes": passes,
            "pdf_openable": True,
        }
        destination = self.root / _BASELINE_INPUT_DIRECTORY
        if destination.exists():
            if not self.verify_baseline_input_checkpoint():
                raise CandidateStoreError(
                    "immutable baseline input checkpoint is missing or invalid"
                )
            existing = json.loads(
                (destination / "metadata.json").read_text(encoding="utf-8")
            )
            stable_fields = set(metadata) - {"compile_log_sha256"}
            if any(existing.get(name) != metadata[name] for name in stable_fields):
                raise CandidateStoreError(
                    "immutable baseline input checkpoint belongs to different evidence"
                )
            # A real compiler may embed a private work directory or timestamp
            # in a later resume log.  The original log remains immutable and
            # hash-verified; idempotence is governed by the run, TeX, PDF,
            # pass-count, and openability bindings rather than mutable log text.
            return dict(existing)

        temp = Path(tempfile.mkdtemp(prefix=".baseline-input-", dir=self.root))
        try:
            files = {
                "baseline.tex": tex_bytes,
                "baseline.pdf": pdf_bytes,
                "compile.log": log_bytes,
                "metadata.json": _json_bytes(metadata),
            }
            for name, payload in files.items():
                (temp / name).write_bytes(payload)
            sums = "".join(
                f"{sha256_bytes(payload)}  {name}\n"
                for name, payload in sorted(files.items())
            ).encode("utf-8")
            (temp / "SHA256SUMS").write_bytes(sums)
            os.replace(temp, destination)
        except BaseException:
            if temp.exists():
                shutil.rmtree(temp, ignore_errors=True)
            raise
        return dict(metadata)

    def verify_baseline_input_checkpoint(self) -> bool:
        """Recompute the complete checkpoint manifest and metadata hashes."""

        directory = self.root / _BASELINE_INPUT_DIRECTORY
        manifest = directory / "SHA256SUMS"
        if not manifest.is_file():
            return False
        observed: dict[str, str] = {}
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, separator, name = line.partition("  ")
            if (
                not separator
                or name in observed
                or name not in _BASELINE_INPUT_FILES
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                return False
            path = directory / name
            if not path.is_file() or sha256_bytes(path.read_bytes()) != digest:
                return False
            observed[name] = digest
        if set(observed) != _BASELINE_INPUT_FILES:
            return False
        try:
            metadata = json.loads(
                (directory / "metadata.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        if not isinstance(metadata, dict) or set(metadata) != {
            "artifact_type",
            "run_id",
            "baseline_tex_sha256",
            "baseline_pdf_sha256",
            "compile_log_sha256",
            "compile_passes",
            "pdf_openable",
        }:
            return False
        return (
            metadata["artifact_type"]
            == "latexstruct-analysis-baseline-input-v1"
            and isinstance(metadata["run_id"], str)
            and bool(metadata["run_id"].strip())
            and type(metadata["compile_passes"]) is int
            and metadata["compile_passes"] >= 2
            and metadata["pdf_openable"] is True
            and metadata["baseline_tex_sha256"]
            == sha256_bytes((directory / "baseline.tex").read_bytes())
            and metadata["baseline_pdf_sha256"]
            == sha256_bytes((directory / "baseline.pdf").read_bytes())
            and metadata["compile_log_sha256"]
            == sha256_bytes((directory / "compile.log").read_bytes())
        )

    def persist(
        self,
        *,
        candidate_id: str,
        parent_candidate_id: str,
        round_index: int,
        tex: str,
        pdf: bytes,
        compile_log: str,
        patch: Mapping[str, Any],
        diff: str,
        issue_ledger: Mapping[str, Any],
        quality: QualityVector,
        review: Mapping[str, Any],
        disposition: CandidateDisposition,
        reason: str,
    ) -> CandidateRecord:
        candidate_id = _portable_candidate_id(candidate_id)
        if type(round_index) is not int or round_index < 0 or round_index > 9999:
            raise CandidateStoreError("candidate round index is invalid")
        if type(parent_candidate_id) is not str or type(reason) is not str:
            raise CandidateStoreError("candidate text metadata is not typed")
        if not isinstance(quality, QualityVector):
            raise CandidateStoreError("candidate quality must be a QualityVector")
        quality = _quality_vector_from_json(asdict(quality))
        if not isinstance(disposition, CandidateDisposition):
            raise CandidateStoreError("candidate disposition is invalid")
        destination = self.root / candidate_id
        tex_bytes = tex.encode("utf-8")
        pdf_bytes = bytes(pdf)
        tex_hash = sha256_bytes(tex_bytes)
        pdf_hash = sha256_bytes(pdf_bytes) if pdf_bytes else ""
        if candidate_id != make_candidate_id(round_index, tex_hash):
            raise CandidateStoreError("candidate id does not match candidate TeX bytes")
        record = CandidateRecord(
            candidate_id=candidate_id,
            parent_candidate_id=parent_candidate_id,
            round_index=round_index,
            tex_sha256=tex_hash,
            pdf_sha256=pdf_hash,
            quality=quality,
            disposition=disposition,
            reason=reason,
            # Keep persisted metadata portable and safe for a later audit ZIP.
            # The repository root is host state, never candidate evidence.
            artifact_directory=candidate_id,
        )
        try:
            files: dict[str, bytes] = {
                "candidate.tex": tex_bytes,
                "compile.log": compile_log.encode("utf-8"),
                "patch.json": _json_bytes(dict(patch)),
                "candidate.diff": diff.encode("utf-8"),
                "issue_ledger.json": _json_bytes(dict(issue_ledger)),
                "quality_vector.json": _json_bytes(asdict(quality)),
                "review.json": _json_bytes(dict(review)),
                "candidate.json": _json_bytes(record.to_dict()),
            }
        except (AttributeError, TypeError, UnicodeError) as exc:
            raise CandidateStoreError("candidate evidence inputs are not typed") from exc
        if pdf_bytes:
            files["candidate.pdf"] = pdf_bytes
        sums = "".join(
            f"{sha256_bytes(payload)}  {name}\n"
            for name, payload in sorted(files.items())
        ).encode("utf-8")
        payloads = {**files, "SHA256SUMS": sums}

        _assert_plain_candidate_path(self.root, label="candidate repository root")
        if _storage_entry_exists(destination):
            return self._reuse_exact_candidate(
                destination=destination,
                payloads=payloads,
                record=record,
            )

        try:
            temp = Path(tempfile.mkdtemp(prefix=f".{candidate_id}-", dir=self.root))
        except OSError as exc:
            raise CandidateStoreError("cannot create candidate staging directory") from exc
        try:
            _assert_plain_candidate_path(temp, label="candidate staging directory")
            for name, payload in payloads.items():
                _write_new_candidate_file(temp / name, payload)
            _fsync_directory(temp)
            _assert_plain_candidate_path(self.root, label="candidate repository root")
            if _storage_entry_exists(destination):
                return self._reuse_exact_candidate(
                    destination=destination,
                    payloads=payloads,
                    record=record,
                )
            try:
                # ``rename`` preserves the write-once contract on Windows and
                # publishes the complete directory in one same-volume step.
                os.rename(temp, destination)
            except OSError:
                # Another recovery worker may have published the same complete
                # immutable candidate after our absence check.  Only exact
                # byte-for-byte evidence is an admissible replay.
                if _storage_entry_exists(destination):
                    return self._reuse_exact_candidate(
                        destination=destination,
                        payloads=payloads,
                        record=record,
                    )
                raise
            _fsync_directory(self.root)
            if not _directory_matches_payloads(destination, payloads):
                raise CandidateStoreError(
                    "candidate directory changed during immutable publication"
                )
        finally:
            _remove_candidate_temp(temp)
        return record

    def load(self, candidate_id: str) -> CandidateRecord:
        candidate_id = _portable_candidate_id(candidate_id)
        if not self.verify(candidate_id):
            raise CandidateStoreError("candidate hash manifest is missing or invalid")
        directory = self.root / candidate_id
        try:
            raw = parse_strict_json_bytes(
                _read_candidate_file(directory / "candidate.json"),
                label="candidate.json",
            )
            quality_payload = parse_strict_json_bytes(
                _read_candidate_file(directory / "quality_vector.json"),
                label="quality_vector.json",
            )
        except RecoveryValidationError as exc:
            raise CandidateStoreError("candidate JSON evidence is invalid") from exc
        if not isinstance(raw, dict) or set(raw) != _CANDIDATE_METADATA_FIELDS:
            raise CandidateStoreError("candidate metadata schema is not exact")
        if (
            type(raw["candidate_id"]) is not str
            or type(raw["parent_candidate_id"]) is not str
            or type(raw["reason"]) is not str
            or type(raw["artifact_directory"]) is not str
        ):
            raise CandidateStoreError("candidate metadata text fields are not typed")
        if type(raw["round_index"]) is not int or not 0 <= raw["round_index"] <= 9999:
            raise CandidateStoreError("candidate round index is invalid")
        if not isinstance(raw["tex_sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", raw["tex_sha256"]
        ):
            raise CandidateStoreError("candidate TeX hash is invalid")
        pdf_sha256 = raw["pdf_sha256"]
        if not isinstance(pdf_sha256, str) or (
            pdf_sha256 and not re.fullmatch(r"[0-9a-f]{64}", pdf_sha256)
        ):
            raise CandidateStoreError("candidate PDF hash is invalid")
        quality = _quality_vector_from_json(raw["quality"])
        if asdict(quality) != quality_payload:
            raise CandidateStoreError(
                "candidate quality metadata differs from quality_vector.json"
            )
        try:
            disposition = CandidateDisposition(raw["disposition"])
        except (TypeError, ValueError) as exc:
            raise CandidateStoreError("candidate disposition is invalid") from exc
        record = CandidateRecord(
            candidate_id=raw["candidate_id"],
            parent_candidate_id=raw["parent_candidate_id"],
            round_index=raw["round_index"],
            tex_sha256=raw["tex_sha256"],
            pdf_sha256=pdf_sha256,
            quality=quality,
            disposition=disposition,
            reason=raw["reason"],
            artifact_directory=candidate_id,
        )
        if record.candidate_id != candidate_id:
            raise CandidateStoreError("candidate metadata identity mismatch")
        if raw["artifact_directory"] != candidate_id:
            raise CandidateStoreError("candidate artifact directory identity mismatch")
        if candidate_id != make_candidate_id(record.round_index, record.tex_sha256):
            raise CandidateStoreError("candidate id does not bind its round and TeX")
        if record.tex_sha256 != sha256_bytes(
            _read_candidate_file(directory / "candidate.tex")
        ):
            raise CandidateStoreError("candidate TeX hash mismatch")
        pdf_path = directory / "candidate.pdf"
        actual_pdf_hash = (
            sha256_bytes(_read_candidate_file(pdf_path))
            if _storage_entry_exists(pdf_path)
            else ""
        )
        if record.pdf_sha256 != actual_pdf_hash:
            raise CandidateStoreError("candidate PDF hash mismatch")
        return record

    def verify(self, candidate_id: str) -> bool:
        try:
            directory = self.root / _portable_candidate_id(candidate_id)
            _assert_plain_candidate_path(self.root, label="candidate repository root")
            _assert_plain_candidate_path(directory, label="candidate directory")
            if path_is_link_or_reparse(directory):
                return False
            directory_stat = os.lstat(directory)
            if not stat.S_ISDIR(directory_stat.st_mode):
                return False
            manifest_bytes = _read_candidate_file(directory / "SHA256SUMS")
            manifest_text = manifest_bytes.decode("utf-8")
            observed: set[str] = set()
            allowed = set(_CANDIDATE_REQUIRED_FILES) | {"candidate.pdf"}
            for line in manifest_text.splitlines():
                digest, separator, name = line.partition("  ")
                if (
                    not separator
                    or name in observed
                    or name not in allowed
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)
                ):
                    return False
                payload = _read_candidate_file(directory / name)
                if sha256_bytes(payload) != digest:
                    return False
                observed.add(name)
            if not _CANDIDATE_REQUIRED_FILES.issubset(observed):
                return False
            entries = tuple(os.scandir(directory))
            actual_files = {entry.name for entry in entries}
            if actual_files != observed | {"SHA256SUMS"}:
                return False
            for entry in entries:
                path = directory / entry.name
                if path_is_link_or_reparse(path):
                    return False
                if not entry.is_file(follow_symlinks=False):
                    return False
            for name in _CANDIDATE_JSON_FILES:
                parse_strict_json_bytes(
                    _read_candidate_file(directory / name),
                    label=name,
                )
            return True
        except (
            CandidateStoreError,
            FileNotFoundError,
            OSError,
            RecoveryValidationError,
            UnicodeError,
        ):
            return False


@dataclass(frozen=True, slots=True)
class RollbackRecord:
    rejected_candidate_id: str
    retained_candidate_id: str
    reason: str
    rejected_quality: QualityVector
    retained_quality: QualityVector


class CandidateController:
    """Accept only strict lexicographic improvement; otherwise retain best."""

    def __init__(self, repository: CandidateRepository) -> None:
        self.repository = repository
        self.best: CandidateRecord | None = None
        self.current: CandidateRecord | None = None
        self.rollback_history: list[RollbackRecord] = []

    def save_baseline(
        self,
        *,
        tex: str,
        pdf: bytes,
        compile_log: str,
        quality: QualityVector,
        issue_ledger: Mapping[str, Any],
    ) -> CandidateRecord:
        if self.best is not None:
            raise CandidateStoreError("baseline is already frozen")
        digest = sha256_text(tex)
        candidate_id = make_candidate_id(0, digest)
        destination = self.repository.root / candidate_id
        if _storage_entry_exists(destination):
            record = self.repository.load(candidate_id)
            try:
                stored_ledger = parse_strict_json_bytes(
                    _read_candidate_file(destination / "issue_ledger.json"),
                    label="issue_ledger.json",
                )
            except RecoveryValidationError as exc:
                raise CandidateStoreError(
                    "existing immutable baseline issue ledger is invalid"
                ) from exc
            if (
                record.disposition != CandidateDisposition.BASELINE
                or record.tex_sha256 != digest
                or record.pdf_sha256 != (sha256_bytes(pdf) if pdf else "")
                or record.quality != quality
                or stored_ledger != dict(issue_ledger)
            ):
                raise CandidateStoreError(
                    "existing immutable baseline differs from resumed evidence"
                )
            self.best = self.current = record
            return record
        record = self.repository.persist(
            candidate_id=candidate_id,
            parent_candidate_id="",
            round_index=0,
            tex=tex,
            pdf=pdf,
            compile_log=compile_log,
            patch={},
            diff="",
            issue_ledger=issue_ledger,
            quality=quality,
            review={},
            disposition=CandidateDisposition.BASELINE,
            reason="frozen OCR baseline",
        )
        self.best = self.current = record
        return record

    def resume_from_committed_best(self, candidate_id: str) -> CandidateRecord:
        """Resume only from a fully committed, hash-valid macro-round."""

        if self.best is not None or self.current is not None:
            raise CandidateStoreError("candidate controller is already initialized")
        record = self.repository.load(candidate_id)
        if record.disposition == CandidateDisposition.REJECTED_ROLLED_BACK:
            raise CandidateStoreError("cannot resume from a rejected candidate")
        self.best = self.current = record
        return record

    def evaluate(
        self,
        *,
        application: PatchApplication,
        round_index: int,
        pdf: bytes,
        compile_log: str,
        quality: QualityVector,
        issue_ledger: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> CandidateRecord:
        if self.best is None or self.current is None:
            raise CandidateStoreError("baseline must be frozen before evaluating a candidate")
        if application.parent_hash != self.current.tex_sha256:
            raise CandidateStoreError("candidate does not descend from the current best hash")
        accepted = quality.better_than(self.best.quality)
        disposition = (
            CandidateDisposition.ACCEPTED
            if accepted
            else CandidateDisposition.REJECTED_ROLLED_BACK
        )
        reason = (
            "strict lexicographic quality improvement"
            if accepted
            else "no strict lexicographic improvement; history best retained"
        )
        record = self.repository.persist(
            candidate_id=make_candidate_id(round_index, application.candidate_hash),
            parent_candidate_id=self.current.candidate_id,
            round_index=round_index,
            tex=application.candidate_tex,
            pdf=pdf,
            compile_log=compile_log,
            patch={"patch_id": application.patch_id},
            diff=application.diff,
            issue_ledger=issue_ledger,
            quality=quality,
            review=review,
            disposition=disposition,
            reason=reason,
        )
        if accepted:
            self.best = self.current = record
        else:
            self.rollback_history.append(RollbackRecord(
                rejected_candidate_id=record.candidate_id,
                retained_candidate_id=self.best.candidate_id,
                reason=reason,
                rejected_quality=quality,
                retained_quality=self.best.quality,
            ))
            self.current = self.best
        return record


def _fsync_directory(path: Path) -> None:
    """Persist a directory entry after an atomic replace when supported."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(descriptor)


class LocalAnalysisCache:
    """Content-addressed, optionally persistent, run-local response cache.

    The caller supplies a directory that is already scoped by ``run_id``.
    Every key still binds the immutable snapshot, response schema and tool
    version, so copying a cache directory into another run cannot make stale
    evidence admissible.  Writes are atomic and an existing digest is
    immutable: two different responses for the same complete input identity
    are treated as evidence corruption rather than last-writer-wins state.
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self._values: dict[str, Any] = {}
        self._keys: dict[str, AnalysisCacheKey] = {}
        self.root = (
            Path(os.path.abspath(os.fspath(root))) if root is not None else None
        )
        if self.root is not None:
            try:
                assert_plain_storage_path(self.root)
                self.root.mkdir(parents=True, exist_ok=True)
                assert_plain_storage_path(self.root)
            except (OSError, RecoveryValidationError) as exc:
                raise AnalysisCacheIntegrityError(
                    "analysis cache root is unsafe"
                ) from exc

    def _path(self, key: AnalysisCacheKey) -> Path | None:
        if self.root is None:
            return None
        role = re.sub(r"[^A-Za-z0-9._-]+", "-", key.audit_role).strip("-._")
        if not role:
            raise ValueError("cache role cannot be mapped to a safe path")
        return self.root / role / key.digest[:2] / f"{key.digest}.json"

    @staticmethod
    def _payload(key: AnalysisCacheKey, value: Any) -> dict[str, Any]:
        frozen = json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
        )
        return {
            "schema": "latexstruct-analysis-cache-entry-v2",
            "cache_key": asdict(key),
            "cache_key_sha256": key.digest,
            "response": frozen,
            "response_sha256": sha256_bytes(canonical_json_bytes(frozen)),
        }

    def put(self, key: AnalysisCacheKey, value: Any) -> None:
        # JSON round-trip prevents callers from mutating cached evidence later.
        payload = self._payload(key, value)
        frozen = payload["response"]
        path = self._path(key)
        if path is not None:
            try:
                assert_plain_storage_path(path.parent)
                path.parent.mkdir(parents=True, exist_ok=True)
                assert_plain_storage_path(path.parent)
                if path_is_link_or_reparse(path):
                    raise RecoveryValidationError(
                        "analysis cache entry is a link or reparse point"
                    )
            except (OSError, RecoveryValidationError) as exc:
                raise AnalysisCacheIntegrityError(
                    "analysis cache entry path is unsafe"
                ) from exc
            encoded = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            if path.exists():
                if path_is_link_or_reparse(path):
                    raise AnalysisCacheIntegrityError(
                        "analysis cache entry is a link or reparse point"
                    )
                if (
                    not path.is_file()
                    or path.read_bytes() != encoded
                ):
                    raise ValueError("immutable analysis cache entry changed for one key")
            else:
                fd, temp_name = tempfile.mkstemp(
                    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
                )
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
                    assert_plain_storage_path(path.parent)
                    if path_is_link_or_reparse(path):
                        raise RecoveryValidationError(
                            "analysis cache entry became a link or reparse point"
                        )
                    os.replace(temp_name, path)
                    _fsync_directory(path.parent)
                except RecoveryValidationError as exc:
                    raise AnalysisCacheIntegrityError(
                        "analysis cache entry path became unsafe"
                    ) from exc
                finally:
                    if os.path.exists(temp_name):
                        os.unlink(temp_name)
        self._keys[key.digest] = key
        self._values[key.digest] = frozen

    def get(self, key: AnalysisCacheKey) -> Any | None:
        value = self._values.get(key.digest)
        if value is None:
            path = self._path(key)
            if path is None:
                return None
            try:
                assert_plain_storage_path(path.parent)
                if path_is_link_or_reparse(path):
                    raise AnalysisCacheIntegrityError(
                        "analysis cache entry is a link or reparse point"
                    )
            except RecoveryValidationError as exc:
                raise AnalysisCacheIntegrityError(
                    "analysis cache entry path is unsafe"
                ) from exc
            if not path.is_file():
                return None
            try:
                payload = parse_strict_json_bytes(
                    path.read_bytes(),
                    label="analysis cache entry",
                )
            except (OSError, RecoveryValidationError):
                return None
            expected_key = asdict(key)
            response = payload.get("response") if isinstance(payload, dict) else None
            if (
                set(payload) != {
                    "schema",
                    "cache_key",
                    "cache_key_sha256",
                    "response",
                    "response_sha256",
                }
                or payload.get("schema") != "latexstruct-analysis-cache-entry-v2"
                or payload.get("cache_key") != expected_key
                or payload.get("cache_key_sha256") != key.digest
                or payload.get("response_sha256")
                != sha256_bytes(canonical_json_bytes(response))
            ):
                return None
            value = response
            self._keys[key.digest] = key
            self._values[key.digest] = value
        return copy.deepcopy(value) if value is not None else None

    def invalidate_changed(self, current: AnalysisCacheKey) -> tuple[str, ...]:
        removed = []
        for digest, key in tuple(self._keys.items()):
            if (
                key.source_page_id == current.source_page_id
                and key.audit_role == current.audit_role
                and digest != current.digest
            ):
                removed.append(digest)
                self._keys.pop(digest, None)
                self._values.pop(digest, None)
                path = self._path(key)
                if path is not None:
                    self._unlink_plain_entry(path)
        return tuple(sorted(removed))

    def discard(self, key: AnalysisCacheKey) -> bool:
        """Remove one exact cache key after response validation fails.

        Cache entries are immutable only while they remain admissible evidence.
        A strict parser may discover that an on-disk entry is syntactically valid
        JSON but violates the role response contract; in that case the caller must
        be able to evict only that key before obtaining fresh transport evidence.
        """

        existed = key.digest in self._keys or key.digest in self._values
        self._keys.pop(key.digest, None)
        self._values.pop(key.digest, None)
        path = self._path(key)
        if path is not None and self._unlink_plain_entry(path):
            existed = True
        return existed

    @staticmethod
    def _unlink_plain_entry(path: Path) -> bool:
        try:
            assert_plain_storage_path(path.parent)
            if path_is_link_or_reparse(path):
                raise AnalysisCacheIntegrityError(
                    "analysis cache entry is a link or reparse point"
                )
        except RecoveryValidationError as exc:
            raise AnalysisCacheIntegrityError(
                "analysis cache entry path is unsafe"
            ) from exc
        if not path.is_file():
            return False
        path.unlink()
        return True

    @property
    def size(self) -> int:
        return len(self._values)


class EscalationAction(str, Enum):
    RELOAD_CURRENT = "RELOAD_CURRENT"
    REDUCE_TO_SINGLE_ISSUE = "REDUCE_TO_SINGLE_ISSUE"
    INCLUDE_NEIGHBOUR_PAGES = "INCLUDE_NEIGHBOUR_PAGES"
    INCREASE_SOURCE_RESOLUTION = "INCREASE_SOURCE_RESOLUTION"
    CROP_EVIDENCE_REGION = "CROP_EVIDENCE_REGION"
    NEW_INDEPENDENT_CONTEXT = "NEW_INDEPENDENT_CONTEXT"
    STRONG_MODEL_ADJUDICATION = "STRONG_MODEL_ADJUDICATION"
    ROLLBACK_HISTORY_BEST = "ROLLBACK_HISTORY_BEST"


ESCALATION_SEQUENCE = tuple(EscalationAction)


@dataclass(frozen=True, slots=True)
class RoundObservation:
    round_index: int
    unresolved_total: int
    unresolved_high_risk: int
    regressions: int
    rejected_patches: int
    quality: QualityVector


@dataclass(frozen=True, slots=True)
class ProgressDecision:
    no_progress_rounds: int
    stop_current_strategy: bool
    action: EscalationAction | None


class NoProgressController:
    """Prevent identical evidence/prompt loops and escalate after two stalls."""

    def __init__(self) -> None:
        self._last_round: RoundObservation | None = None
        self._no_progress_rounds = 0
        self._escalation_index = 0
        self._issue_attempts: dict[str, tuple[str, int]] = {}

    def _next_action(self) -> EscalationAction:
        index = min(self._escalation_index, len(ESCALATION_SEQUENCE) - 1)
        self._escalation_index += 1
        return ESCALATION_SEQUENCE[index]

    def observe_round(self, observation: RoundObservation) -> ProgressDecision:
        previous = self._last_round
        if previous is None:
            improved = True
        else:
            improved = (
                observation.unresolved_total < previous.unresolved_total
                or observation.unresolved_high_risk < previous.unresolved_high_risk
                or observation.regressions < previous.regressions
                or observation.quality.better_than(previous.quality)
            )
        self._no_progress_rounds = 0 if improved else self._no_progress_rounds + 1
        self._last_round = observation
        stop = self._no_progress_rounds >= 2
        return ProgressDecision(
            no_progress_rounds=self._no_progress_rounds,
            stop_current_strategy=stop,
            action=self._next_action() if stop else None,
        )

    def record_issue_attempt(
        self,
        issue_id: str,
        *,
        prompt_and_evidence_fingerprint: str,
        resolved: bool,
    ) -> ProgressDecision:
        if resolved:
            self._issue_attempts.pop(issue_id, None)
            return ProgressDecision(0, False, None)
        previous_fingerprint, count = self._issue_attempts.get(issue_id, ("", 0))
        count = count + 1 if previous_fingerprint == prompt_and_evidence_fingerprint else 1
        self._issue_attempts[issue_id] = (prompt_and_evidence_fingerprint, count)
        stop = count >= 2
        return ProgressDecision(
            no_progress_rounds=count,
            stop_current_strategy=stop,
            action=self._next_action() if stop else None,
        )


def verification_failures(evidence: VerificationEvidence) -> tuple[str, ...]:
    failures: list[str] = []
    checks = (
        (evidence.raw_ocr_frozen, "raw_ocr_not_frozen"),
        (evidence.baseline_compile_passes >= 2, "baseline_not_compiled_twice"),
        (evidence.best_compile_passes >= 2, "best_not_compiled_twice"),
        (evidence.best_pdf_openable, "best_pdf_not_openable"),
        (set(evidence.checked_page_ids) == set(evidence.expected_page_ids), "page_coverage_incomplete"),
        (evidence.silent_page_omissions == 0, "silent_page_omission"),
        (evidence.silent_text_losses == 0, "silent_text_loss"),
        (evidence.unauthorized_math_changes == 0, "unauthorized_math_change"),
        (evidence.formal_errors == 0, "formal_error"),
        (evidence.toc_complete_and_ordered, "toc_incomplete_or_unordered"),
        (evidence.severe_equation_number_errors == 0, "equation_number_error"),
        (evidence.silent_footnote_losses == 0, "silent_footnote_loss"),
        (evidence.silent_figure_caption_losses == 0, "silent_figure_caption_loss"),
        (evidence.silent_bibliography_losses == 0, "silent_bibliography_loss"),
        (evidence.open_critical == 0, "open_critical_issue"),
        (evidence.open_high == 0, "open_high_issue"),
        (evidence.regressions == 0, "regression_present"),
        (evidence.candidate_hash == evidence.current_candidate_hash, "candidate_hash_stale"),
    )
    failures.extend(code for passed, code in checks if not passed)
    reviews = sorted(evidence.final_reviews, key=lambda item: item.pass_number)
    if len(reviews) != 2 or [item.pass_number for item in reviews] != [1, 2]:
        failures.append("two_independent_reviews_missing")
    else:
        contexts = {item.context_id for item in reviews}
        if len(contexts) != 2 or any(item.prior_pass_conclusion_visible for item in reviews):
            failures.append("reviews_not_independent")
        for item in reviews:
            if item.candidate_hash != evidence.candidate_hash:
                failures.append(f"review_{item.pass_number}_candidate_hash_stale")
            if set(item.checked_page_ids) != set(evidence.expected_page_ids):
                failures.append(f"review_{item.pass_number}_coverage_incomplete")
            if item.compile_passes < 2:
                failures.append(f"review_{item.pass_number}_compile_incomplete")
            if not (
                item.content_conservation_ok
                and item.math_conservation_ok
                and item.formal_inventory_ok
                and item.visual_review_ok
            ):
                failures.append(f"review_{item.pass_number}_gate_failed")
            if item.new_high_risk_issues:
                failures.append(f"review_{item.pass_number}_new_high_risk_issue")
    return tuple(dict.fromkeys(failures))


def decide_final_status(
    evidence: VerificationEvidence,
    *,
    processing_failed: bool = False,
) -> VerificationDecision:
    """Derive status from host evidence; no model status parameter exists."""

    failures = verification_failures(evidence)
    if not failures:
        return VerificationDecision(AnalysisFinalStatus.VERIFIED, True, ())
    status = (
        AnalysisFinalStatus.FAILED_BEST_RETAINED
        if processing_failed
        else AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    )
    return VerificationDecision(status, False, failures)


@dataclass(frozen=True, slots=True)
class PerformanceMetrics:
    available: bool
    total_pages: int
    elapsed_seconds: float
    pages_per_minute: float
    machine_preflight_seconds: float
    whole_book_scan_seconds: float
    role_call_counts: tuple[tuple[str, int], ...]
    model_elapsed_seconds: tuple[tuple[str, float], ...]
    input_tokens: int | None
    output_tokens: int | None
    cache_hits: int
    cache_misses: int
    checked_pages: int
    high_risk_pages: int
    modified_pages: int
    full_compile_count: int
    incremental_check_count: int
    rollback_count: int
    auto_closed_issues: int
    blocked_issues: int
    final_status: AnalysisFinalStatus
    target_seconds: float
    benchmark_page_count: int
    benchmark_eligible: bool
    target_status: PerformanceTargetStatus
    target_evaluated: bool
    target_met: bool | None
    estimated_remaining_seconds: float | None
    cached_tokens: int | None = None
    total_tokens: int | None = None
    usage_complete: bool = False
    observed_input_tokens: int = 0
    observed_output_tokens: int = 0
    observed_cached_tokens: int = 0
    observed_total_tokens: int = 0
    transport_call_count: int = 0
    usage_observed_call_count: int = 0
    usage_missing_call_count: int = 0
    transport_attempt_count: int | None = None
    observed_transport_attempt_count: int = 0
    usage_observed_attempt_count: int = 0
    usage_missing_attempt_count: int | None = None
    attempt_evidence_complete: bool = False
    cache_status: str = "DISABLED"
    estimated_cost_cny: float | None = None
    cost_status: str = "UNKNOWN"
    pricing_sources: tuple[str, ...] = ()
    billing_mode: str | None = None
    orchestration_invocation_count: int = 0
    cache_hit_evidence_count: int = 0

    @property
    def cache_hit_rate(self) -> float:
        if self.cache_status != "ENABLED":
            return 0.0
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["final_status"] = self.final_status.value
        payload["target_status"] = self.target_status.value
        payload["cache_hit_rate"] = self.cache_hit_rate
        return payload


class PerformanceTracker:
    """Compute honest throughput and ETA from the last ten completed units."""

    def __init__(
        self,
        *,
        total_pages: int,
        target_seconds: float = ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS,
        benchmark_eligible: bool | None = None,
    ) -> None:
        if total_pages < 1 or target_seconds <= 0:
            raise ValueError("performance tracker requires positive totals")
        if benchmark_eligible is True and total_pages != ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT:
            raise ValueError("performance benchmark eligibility requires exactly 600 pages")
        self.total_pages = total_pages
        self.target_seconds = target_seconds
        page_count_eligible = total_pages == ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT
        requested_eligible = (
            page_count_eligible if benchmark_eligible is None else benchmark_eligible
        )
        self.benchmark_eligible = bool(
            requested_eligible
            and page_count_eligible
            and target_seconds == ANALYSIS_PERFORMANCE_BENCHMARK_SECONDS
        )
        self._completions: dict[str, float] = {}

    def record_page_completion(self, source_page_id: str, elapsed_seconds: float) -> None:
        if source_page_id in self._completions:
            raise ValueError("a page completion cannot inflate throughput twice")
        if elapsed_seconds < 0:
            raise ValueError("elapsed time cannot be negative")
        self._completions[source_page_id] = float(elapsed_seconds)

    def _recent_pages_per_second(self, now_elapsed: float) -> float:
        ordered = sorted(self._completions.values())[-10:]
        if not ordered:
            return 0.0
        if len(ordered) == 1:
            return 1.0 / max(ordered[0], now_elapsed, 1e-9)
        span = ordered[-1] - ordered[0]
        return (len(ordered) - 1) / span if span > 0 else 0.0

    def estimated_remaining_seconds(self, now_elapsed: float) -> float | None:
        rate = self._recent_pages_per_second(now_elapsed)
        if rate <= 0:
            return None
        remaining = max(0, self.total_pages - len(self._completions))
        return remaining / rate

    def snapshot(
        self,
        *,
        elapsed_seconds: float,
        machine_preflight_seconds: float,
        whole_book_scan_seconds: float,
        role_call_counts: Mapping[str, int],
        model_elapsed_seconds: Mapping[str, float],
        input_tokens: int | None,
        output_tokens: int | None,
        cache_hits: int,
        cache_misses: int,
        high_risk_pages: int,
        modified_pages: int,
        full_compile_count: int,
        incremental_check_count: int,
        rollback_count: int,
        auto_closed_issues: int,
        blocked_issues: int,
        final_status: AnalysisFinalStatus,
        usage_complete: bool | None = None,
        cached_tokens: int | None = None,
        total_tokens: int | None = None,
        cache_status: str | None = None,
    ) -> PerformanceMetrics:
        checked_pages = len(self._completions)
        pages_per_minute = checked_pages * 60.0 / elapsed_seconds if elapsed_seconds > 0 else 0.0
        benchmark_complete = (
            self.benchmark_eligible
            and checked_pages == self.total_pages
            and math.isfinite(elapsed_seconds)
            and elapsed_seconds > 0
        )
        if benchmark_complete:
            target_met: bool | None = (
                elapsed_seconds <= self.target_seconds
                and final_status in {
                    AnalysisFinalStatus.VERIFIED,
                    AnalysisFinalStatus.COMPLETED_WITH_ISSUES,
                }
            )
            target_status = (
                PerformanceTargetStatus.PASSED
                if target_met
                else PerformanceTargetStatus.FAILED
            )
        else:
            target_met = None
            target_status = PerformanceTargetStatus.NOT_EVALUATED
        input_count = None if input_tokens is None else int(input_tokens)
        output_count = None if output_tokens is None else int(output_tokens)
        complete_usage = bool(
            input_count is not None and output_count is not None
            if usage_complete is None
            else usage_complete and input_count is not None and output_count is not None
        )
        cached_count = None if cached_tokens is None else int(cached_tokens)
        total_count = None if total_tokens is None else int(total_tokens)
        if complete_usage:
            cached_count = 0 if cached_count is None else cached_count
            total_count = (
                input_count + output_count if total_count is None else total_count
            )
        else:
            input_count = output_count = cached_count = total_count = None
        normalized_cache_status = str(cache_status or "").strip().upper()
        if not normalized_cache_status:
            normalized_cache_status = (
                "ENABLED" if int(cache_hits) + int(cache_misses) else "DISABLED"
            )
        if normalized_cache_status not in {"DISABLED", "ENABLED"}:
            raise ValueError("cache_status must be DISABLED or ENABLED")
        if normalized_cache_status == "DISABLED" and (cache_hits or cache_misses):
            raise ValueError("disabled analysis cache cannot report hits or misses")
        return PerformanceMetrics(
            available=True,
            total_pages=self.total_pages,
            elapsed_seconds=float(elapsed_seconds),
            pages_per_minute=pages_per_minute,
            machine_preflight_seconds=float(machine_preflight_seconds),
            whole_book_scan_seconds=float(whole_book_scan_seconds),
            role_call_counts=tuple(sorted((str(k), int(v)) for k, v in role_call_counts.items())),
            model_elapsed_seconds=tuple(sorted(
                (str(k), float(v)) for k, v in model_elapsed_seconds.items()
            )),
            input_tokens=input_count,
            output_tokens=output_count,
            cache_hits=int(cache_hits),
            cache_misses=int(cache_misses),
            checked_pages=checked_pages,
            high_risk_pages=int(high_risk_pages),
            modified_pages=int(modified_pages),
            full_compile_count=int(full_compile_count),
            incremental_check_count=int(incremental_check_count),
            rollback_count=int(rollback_count),
            auto_closed_issues=int(auto_closed_issues),
            blocked_issues=int(blocked_issues),
            final_status=final_status,
            target_seconds=self.target_seconds,
            benchmark_page_count=ANALYSIS_PERFORMANCE_BENCHMARK_PAGE_COUNT,
            benchmark_eligible=self.benchmark_eligible,
            target_status=target_status,
            target_evaluated=benchmark_complete,
            target_met=target_met,
            estimated_remaining_seconds=self.estimated_remaining_seconds(elapsed_seconds),
            cached_tokens=cached_count,
            total_tokens=total_count,
            usage_complete=complete_usage,
            observed_input_tokens=input_count or 0,
            observed_output_tokens=output_count or 0,
            observed_cached_tokens=cached_count or 0,
            observed_total_tokens=total_count or 0,
            cache_status=normalized_cache_status,
        )


class AnalysisQualityRuntime:
    """Small composition root for resumable host-side quality state."""

    def __init__(
        self,
        *,
        snapshot: AnalysisRunSnapshot,
        page_units: Sequence[PageUnit],
        candidate_root: str | Path,
        ledger: IssueLedger | None = None,
    ) -> None:
        units = tuple(page_units)
        ids = [unit.source_page_id for unit in units]
        numbers = [unit.source_page_number for unit in units]
        if len(ids) != len(set(ids)) or set(numbers) != set(snapshot.page_range):
            raise ValueError("PageUnits must cover the immutable snapshot exactly once")
        if any(unit.source_page_hash == "" for unit in units):
            raise ValueError("PageUnits require source hashes")
        self.snapshot = snapshot
        self.page_units = units
        self.ledger = ledger or IssueLedger()
        self.cache = LocalAnalysisCache()
        self.progress = NoProgressController()
        self.candidates = CandidateController(CandidateRepository(candidate_root))
        self.performance = PerformanceTracker(
            total_pages=len(units),
            target_seconds=snapshot.performance_target_seconds,
            benchmark_eligible=snapshot.performance_benchmark_eligible,
        )

    def register_findings(
        self, findings: Iterable[IssueProposal], *, round_index: int
    ) -> tuple[IssueRecord, ...]:
        return tuple(self.ledger.upsert(item, round_index=round_index) for item in findings)

    def final_decision(
        self,
        evidence: VerificationEvidence,
        *,
        processing_failed: bool = False,
    ) -> VerificationDecision:
        if self.candidates.best is not None and evidence.candidate_hash != self.candidates.best.tex_sha256:
            # The status gate remains fail-closed even if a caller assembled
            # otherwise clean evidence for a rejected or stale candidate.
            evidence = replace(evidence, current_candidate_hash=self.candidates.best.tex_sha256)
        return decide_final_status(evidence, processing_failed=processing_failed)


__all__ = [
    "AnalysisCacheIntegrityError",
    "AnalysisQualityRuntime",
    "CandidateController",
    "CandidateRecord",
    "CandidateRepository",
    "CandidateStoreError",
    "ConservationReport",
    "ESCALATION_SEQUENCE",
    "EscalationAction",
    "IssueLedger",
    "LedgerTransitionError",
    "LocalAnalysisCache",
    "NoProgressController",
    "PatchApplication",
    "PatchOperation",
    "PatchPlan",
    "PatchRejected",
    "PatchScope",
    "PerformanceMetrics",
    "PerformanceTracker",
    "ProgressDecision",
    "RollbackRecord",
    "RoundObservation",
    "apply_patch_plan",
    "decide_final_status",
    "make_candidate_id",
    "verification_failures",
]
