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
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .analysis_schema import (
    AnalysisCacheKey,
    AnalysisFinalStatus,
    AnalysisRunSnapshot,
    CandidateDisposition,
    IssueProposal,
    IssueRecord,
    IssueStatus,
    PageUnit,
    PatchOperationKind,
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
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
        + "\n"
    ).encode("utf-8")


class CandidateRepository:
    """Write-once candidate directories committed with one same-volume rename."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

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
        destination = self.root / candidate_id
        if destination.exists():
            raise CandidateStoreError("immutable candidate already exists")
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
        temp = Path(tempfile.mkdtemp(prefix=f".{candidate_id}-", dir=self.root))
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
            if pdf_bytes:
                files["candidate.pdf"] = pdf_bytes
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
        return record

    def load(self, candidate_id: str) -> CandidateRecord:
        candidate_id = _portable_candidate_id(candidate_id)
        if not self.verify(candidate_id):
            raise CandidateStoreError("candidate hash manifest is missing or invalid")
        directory = self.root / candidate_id
        raw = json.loads((directory / "candidate.json").read_text(encoding="utf-8"))
        raw["quality"] = QualityVector(**raw["quality"])
        raw["disposition"] = CandidateDisposition(raw["disposition"])
        raw["artifact_directory"] = candidate_id
        record = CandidateRecord(**raw)
        if record.candidate_id != candidate_id:
            raise CandidateStoreError("candidate metadata identity mismatch")
        if record.tex_sha256 != sha256_bytes((directory / "candidate.tex").read_bytes()):
            raise CandidateStoreError("candidate TeX hash mismatch")
        pdf_path = directory / "candidate.pdf"
        actual_pdf_hash = sha256_bytes(pdf_path.read_bytes()) if pdf_path.is_file() else ""
        if record.pdf_sha256 != actual_pdf_hash:
            raise CandidateStoreError("candidate PDF hash mismatch")
        return record

    def verify(self, candidate_id: str) -> bool:
        directory = self.root / _portable_candidate_id(candidate_id)
        manifest = directory / "SHA256SUMS"
        if not manifest.is_file():
            return False
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, separator, name = line.partition("  ")
            path = directory / name
            if not separator or not path.is_file() or sha256_bytes(path.read_bytes()) != digest:
                return False
        return True


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
        record = self.repository.persist(
            candidate_id=make_candidate_id(0, digest),
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


class LocalAnalysisCache:
    """Content-addressed model-result cache with page/role-local invalidation."""

    def __init__(self) -> None:
        self._values: dict[str, Any] = {}
        self._keys: dict[str, AnalysisCacheKey] = {}

    def put(self, key: AnalysisCacheKey, value: Any) -> None:
        # JSON round-trip prevents callers from mutating cached evidence later.
        frozen = json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))
        self._keys[key.digest] = key
        self._values[key.digest] = frozen

    def get(self, key: AnalysisCacheKey) -> Any | None:
        value = self._values.get(key.digest)
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
        return tuple(sorted(removed))

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
    total_pages: int
    elapsed_seconds: float
    pages_per_minute: float
    machine_preflight_seconds: float
    whole_book_scan_seconds: float
    role_call_counts: tuple[tuple[str, int], ...]
    model_elapsed_seconds: tuple[tuple[str, float], ...]
    input_tokens: int
    output_tokens: int
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
    target_met: bool
    estimated_remaining_seconds: float | None

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total else 0.0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["final_status"] = self.final_status.value
        payload["cache_hit_rate"] = self.cache_hit_rate
        return payload


class PerformanceTracker:
    """Compute honest throughput and ETA from the last ten completed units."""

    def __init__(self, *, total_pages: int, target_seconds: float = 10800.0) -> None:
        if total_pages < 1 or target_seconds <= 0:
            raise ValueError("performance tracker requires positive totals")
        self.total_pages = total_pages
        self.target_seconds = target_seconds
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
        input_tokens: int,
        output_tokens: int,
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
    ) -> PerformanceMetrics:
        checked_pages = len(self._completions)
        pages_per_minute = checked_pages * 60.0 / elapsed_seconds if elapsed_seconds > 0 else 0.0
        target_met = (
            checked_pages == self.total_pages
            and elapsed_seconds <= self.target_seconds
            and final_status in {
                AnalysisFinalStatus.VERIFIED,
                AnalysisFinalStatus.COMPLETED_WITH_ISSUES,
            }
        )
        return PerformanceMetrics(
            total_pages=self.total_pages,
            elapsed_seconds=float(elapsed_seconds),
            pages_per_minute=pages_per_minute,
            machine_preflight_seconds=float(machine_preflight_seconds),
            whole_book_scan_seconds=float(whole_book_scan_seconds),
            role_call_counts=tuple(sorted((str(k), int(v)) for k, v in role_call_counts.items())),
            model_elapsed_seconds=tuple(sorted(
                (str(k), float(v)) for k, v in model_elapsed_seconds.items()
            )),
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
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
            target_met=target_met,
            estimated_remaining_seconds=self.estimated_remaining_seconds(elapsed_seconds),
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
            total_pages=len(units), target_seconds=snapshot.performance_target_seconds
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
