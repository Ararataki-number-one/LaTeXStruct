# -*- coding: utf-8 -*-
"""Fail-closed, source-evidence-authorized OCR content corrections.

This module is intentionally independent from the server and baseline manifest
writer.  It consumes immutable raw/syntax baseline text plus exact operations
authorized by frozen source-page evidence.  It either produces one atomic
evidence-corrected baseline or no output at all, together with a deterministic
audit report.

The producer is not a structure-analysis stage.  It accepts only exact textual
replacement operations outside TeX math and rejects changes to TeX commands or
structural tokens.  It never mutates either input baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Sequence


EVIDENCE_CORRECTION_OPERATION_SCHEMA = (
    "latexstruct-ocr-evidence-correction-operation-v1"
)
SOURCE_EVIDENCE_AUTHORIZATION_SCHEMA = (
    "latexstruct-ocr-source-evidence-authorization-v1"
)
INDEPENDENT_VERIFICATION_SCHEMA = (
    "latexstruct-ocr-evidence-correction-independent-verification-v1"
)
EVIDENCE_CORRECTION_REPORT_SCHEMA = (
    "latexstruct-ocr-evidence-correction-report-v1"
)

EVIDENCE_CORRECTION_POLICY = {
    "schema_version": "latexstruct-ocr-evidence-correction-policy-v1",
    "atomic": True,
    "allowed_actions": ["replace_exact"],
    "authorization": "exact-operation-sha256-bound-to-source-page-evidence",
    "independent_verification_required": True,
    "math_rewrite_allowed": False,
    "structural_inference_allowed": False,
    "raw_ocr_mutation_allowed": False,
    "syntax_baseline_mutation_allowed": False,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FORBIDDEN_PATCH_TOKEN_RE = re.compile(r"\\(?:[A-Za-z@]+|.)|[{}$&#^_%~]")
_STRUCTURAL_TOKEN_RE = re.compile(r"\\(?:[A-Za-z@]+|.)|[{}$&#^_%~]")
_MATH_ENVIRONMENT_BEGIN_RE = re.compile(
    r"\\begin\s*\{(?P<name>(?:equation|align|alignat|flalign|gather|"
    r"multline|displaymath|math|eqnarray)\*?)\}",
    re.IGNORECASE,
)


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical JSON representation used by this audit contract."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(str(value).encode("utf-8"))


EVIDENCE_CORRECTION_POLICY_SHA256 = sha256_bytes(
    canonical_json_bytes(EVIDENCE_CORRECTION_POLICY)
)


class EvidenceCorrectionStatus(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PASS = "PASS"
    FAILED = "FAILED"


class EvidenceCorrectionOperationStatus(str, Enum):
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    NOT_APPLIED = "NOT_APPLIED"


@dataclass(frozen=True, slots=True)
class EvidenceCorrectionOperation:
    """One exact replacement against the immutable syntax baseline."""

    operation_id: str
    syntax_baseline_sha256: str
    page_id: str
    source_page_number: int
    start_offset: int
    end_offset: int
    old_text: str
    new_text: str
    reason: str
    source_page_sha256: str
    source_evidence_sha256: str
    recognition_model: str
    crop_sha256: str = ""
    action: str = "replace_exact"
    schema_version: str = EVIDENCE_CORRECTION_OPERATION_SCHEMA

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "operation_id": self.operation_id,
            "action": self.action,
            "syntax_baseline_sha256": self.syntax_baseline_sha256,
            "page_id": self.page_id,
            "source_page_number": self.source_page_number,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "old_text": self.old_text,
            "old_text_sha256": sha256_text(self.old_text),
            "new_text": self.new_text,
            "new_text_sha256": sha256_text(self.new_text),
            "reason": self.reason,
            "source_page_sha256": self.source_page_sha256,
            "source_evidence_sha256": self.source_evidence_sha256,
            "crop_sha256": self.crop_sha256 or None,
            "recognition_model": self.recognition_model,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class SourceEvidenceAuthorization:
    """Frozen page evidence authorizing exact operation digests."""

    syntax_baseline_sha256: str
    page_id: str
    source_page_number: int
    syntax_start_offset: int
    syntax_end_offset: int
    syntax_region_sha256: str
    source_page_sha256: str
    source_evidence_sha256: str
    authorized_operation_sha256s: tuple[str, ...]
    authorized_crop_sha256s: tuple[str, ...] = ()
    decision: str = "AUTHORIZED"
    authority_kind: str = "SOURCE_EVIDENCE"
    schema_version: str = SOURCE_EVIDENCE_AUTHORIZATION_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "authorized_operation_sha256s",
            tuple(self.authorized_operation_sha256s),
        )
        object.__setattr__(
            self,
            "authorized_crop_sha256s",
            tuple(self.authorized_crop_sha256s),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_kind": self.authority_kind,
            "decision": self.decision,
            "syntax_baseline_sha256": self.syntax_baseline_sha256,
            "page_id": self.page_id,
            "source_page_number": self.source_page_number,
            "syntax_start_offset": self.syntax_start_offset,
            "syntax_end_offset": self.syntax_end_offset,
            "syntax_region_sha256": self.syntax_region_sha256,
            "source_page_sha256": self.source_page_sha256,
            "source_evidence_sha256": self.source_evidence_sha256,
            "authorized_crop_sha256s": sorted(self.authorized_crop_sha256s),
            "authorized_operation_sha256s": sorted(
                self.authorized_operation_sha256s
            ),
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class IndependentEvidenceVerification:
    """An independently persisted PASS/FAIL result bound to one operation."""

    operation_sha256: str
    source_evidence_sha256: str
    old_text_sha256: str
    new_text_sha256: str
    verification_evidence_sha256: str
    verifier: str
    verdict: str
    independent: bool
    math_unchanged: bool
    structure_unchanged: bool
    notes: str = ""
    schema_version: str = INDEPENDENT_VERIFICATION_SCHEMA

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "operation_sha256": self.operation_sha256,
            "source_evidence_sha256": self.source_evidence_sha256,
            "old_text_sha256": self.old_text_sha256,
            "new_text_sha256": self.new_text_sha256,
            "verification_evidence_sha256": self.verification_evidence_sha256,
            "verifier": self.verifier,
            "verdict": self.verdict,
            "independent": self.independent,
            "math_unchanged": self.math_unchanged,
            "structure_unchanged": self.structure_unchanged,
            "notes": self.notes,
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))


@dataclass(frozen=True, slots=True)
class EvidenceCorrectionOperationAudit:
    operation: EvidenceCorrectionOperation
    status: EvidenceCorrectionOperationStatus
    reason_codes: tuple[str, ...]
    source_authorization: SourceEvidenceAuthorization | None = None
    independent_verification: IndependentEvidenceVerification | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))

    @property
    def authorization_sha256(self) -> str:
        return (
            self.source_authorization.digest
            if self.source_authorization is not None
            else ""
        )

    def to_dict(self) -> dict[str, object]:
        authorization = self.source_authorization
        verification = self.independent_verification
        return {
            "operation": self.operation.canonical_payload(),
            "operation_sha256": self.operation.digest,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "source_authorization": (
                authorization.canonical_payload() if authorization is not None else None
            ),
            "authorization_sha256": self.authorization_sha256 or None,
            "independent_verification": (
                verification.canonical_payload() if verification is not None else None
            ),
            "independent_verification_sha256": (
                verification.digest if verification is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class EvidenceCorrectionReport:
    status: EvidenceCorrectionStatus
    raw_ocr_sha256: str
    raw_ocr_bytes: int
    syntax_baseline_sha256: str
    syntax_baseline_bytes: int
    evidence_tex_sha256: str | None
    evidence_tex_bytes: int
    selected_baseline_role: str | None
    operation_audits: tuple[EvidenceCorrectionOperationAudit, ...]
    failure_reasons: tuple[str, ...]
    policy_sha256: str = EVIDENCE_CORRECTION_POLICY_SHA256
    schema_version: str = EVIDENCE_CORRECTION_REPORT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_audits", tuple(self.operation_audits))
        object.__setattr__(self, "failure_reasons", tuple(self.failure_reasons))

    @property
    def applied_operation_count(self) -> int:
        return sum(
            audit.status is EvidenceCorrectionOperationStatus.APPLIED
            for audit in self.operation_audits
        )

    @property
    def rejected_operation_count(self) -> int:
        return sum(
            audit.status is EvidenceCorrectionOperationStatus.REJECTED
            for audit in self.operation_audits
        )

    @property
    def not_applied_operation_count(self) -> int:
        return sum(
            audit.status is EvidenceCorrectionOperationStatus.NOT_APPLIED
            for audit in self.operation_audits
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "policy_sha256": self.policy_sha256,
            "raw_ocr": {
                "sha256": self.raw_ocr_sha256,
                "bytes": self.raw_ocr_bytes,
                "immutable": True,
            },
            "syntax_baseline": {
                "sha256": self.syntax_baseline_sha256,
                "bytes": self.syntax_baseline_bytes,
                "immutable": True,
            },
            "evidence_corrected_baseline": {
                "sha256": self.evidence_tex_sha256,
                "bytes": self.evidence_tex_bytes,
            },
            "selected_baseline_role": self.selected_baseline_role,
            "operation_count": len(self.operation_audits),
            "applied_operation_count": self.applied_operation_count,
            "rejected_operation_count": self.rejected_operation_count,
            "not_applied_operation_count": self.not_applied_operation_count,
            "failure_reasons": list(self.failure_reasons),
            "operations": [audit.to_dict() for audit in self.operation_audits],
        }

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json_bytes(self.canonical_payload()))

    def to_dict(self) -> dict[str, object]:
        return {**self.canonical_payload(), "report_sha256": self.digest}

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class EvidenceCorrectionResult:
    evidence_tex: str | None
    report: EvidenceCorrectionReport


@dataclass(frozen=True, slots=True)
class EvidenceCorrectionProductionInput:
    """Typed host-only input carried from quality evidence to baseline freeze."""

    operations: tuple[EvidenceCorrectionOperation, ...] = ()
    source_authorizations: tuple[SourceEvidenceAuthorization, ...] = ()
    independent_verifications: tuple[IndependentEvidenceVerification, ...] = ()

    def __post_init__(self) -> None:
        operations = tuple(self.operations)
        authorizations = tuple(self.source_authorizations)
        verifications = tuple(self.independent_verifications)
        if not all(isinstance(item, EvidenceCorrectionOperation) for item in operations):
            raise TypeError("production operations have an invalid type")
        if not all(
            isinstance(item, SourceEvidenceAuthorization) for item in authorizations
        ):
            raise TypeError("production source authorizations have an invalid type")
        if not all(
            isinstance(item, IndependentEvidenceVerification)
            for item in verifications
        ):
            raise TypeError("production independent verifications have an invalid type")
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "source_authorizations", authorizations)
        object.__setattr__(self, "independent_verifications", verifications)


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _valid_positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_offset(value: object) -> bool:
    return type(value) is int and value >= 0


def _is_escaped(value: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and value[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _is_commented(value: str, index: int) -> bool:
    line_start = value.rfind("\n", 0, index) + 1
    cursor = line_start
    while True:
        cursor = value.find("%", cursor, index)
        if cursor < 0:
            return False
        if not _is_escaped(value, cursor):
            return True
        cursor += 1


def _find_unescaped_token(value: str, token: str, start: int) -> int:
    cursor = max(0, start)
    while True:
        cursor = value.find(token, cursor)
        if cursor < 0:
            return -1
        if not _is_escaped(value, cursor) and not _is_commented(value, cursor):
            return cursor
        cursor += len(token)


def _find_inline_dollar_close(value: str, start: int, display: bool) -> int:
    cursor = max(0, start)
    while cursor < len(value):
        cursor = value.find("$", cursor)
        if cursor < 0:
            return -1
        if _is_escaped(value, cursor) or _is_commented(value, cursor):
            cursor += 1
            continue
        is_display = value.startswith("$$", cursor)
        if is_display == display:
            return cursor
        cursor += 2 if is_display else 1
    return -1


def _math_spans(value: str) -> tuple[tuple[int, int], ...]:
    """Return conservative source offsets for TeX math regions."""

    spans: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(value):
        if value[cursor] == "%" and not _is_escaped(value, cursor):
            newline = value.find("\n", cursor)
            cursor = len(value) if newline < 0 else newline + 1
            continue
        if value[cursor] == "\\" and not _is_escaped(value, cursor):
            environment = _MATH_ENVIRONMENT_BEGIN_RE.match(value, cursor)
            if environment is not None:
                name = environment.group("name")
                closing_pattern = re.compile(
                    rf"\\end\s*\{{{re.escape(name)}\}}",
                    re.IGNORECASE,
                )
                closing = closing_pattern.search(value, environment.end())
                while closing is not None and _is_commented(value, closing.start()):
                    closing = closing_pattern.search(value, closing.end())
                end = closing.end() if closing is not None else len(value)
                spans.append((cursor, end))
                cursor = end
                continue
            delimiter = next(
                (
                    (opening, closing)
                    for opening, closing in ((r"\[", r"\]"), (r"\(", r"\)"))
                    if value.startswith(opening, cursor)
                ),
                None,
            )
            if delimiter is not None:
                opening, closing = delimiter
                close = _find_unescaped_token(
                    value,
                    closing,
                    cursor + len(opening),
                )
                end = close + len(closing) if close >= 0 else len(value)
                spans.append((cursor, end))
                cursor = end
                continue
        if value[cursor] == "$" and not _is_escaped(value, cursor):
            display = value.startswith("$$", cursor)
            token_length = 2 if display else 1
            close = _find_inline_dollar_close(
                value,
                cursor + token_length,
                display,
            )
            end = close + token_length if close >= 0 else len(value)
            spans.append((cursor, end))
            cursor = end
            continue
        cursor += 1
    return tuple(spans)


def _intersects_math(
    start: int,
    end: int,
    math_spans: Sequence[tuple[int, int]],
) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in math_spans)


def _math_fingerprint(value: str) -> tuple[str, ...]:
    return tuple(sha256_text(value[start:end]) for start, end in _math_spans(value))


def _structure_fingerprint(value: str) -> tuple[str, ...]:
    return tuple(_STRUCTURAL_TOKEN_RE.findall(value))


def _authorization_errors(
    authorization: SourceEvidenceAuthorization,
    syntax_baseline_tex: str,
    syntax_baseline_sha256: str,
) -> tuple[str, ...]:
    errors: list[str] = []
    if authorization.schema_version != SOURCE_EVIDENCE_AUTHORIZATION_SCHEMA:
        errors.append("INVALID_AUTHORIZATION_SCHEMA")
    if (
        authorization.authority_kind != "SOURCE_EVIDENCE"
        or authorization.decision != "AUTHORIZED"
    ):
        errors.append("SOURCE_EVIDENCE_NOT_AUTHORIZED")
    if authorization.syntax_baseline_sha256 != syntax_baseline_sha256:
        errors.append("STALE_AUTHORIZATION_BASELINE")
    if _IDENTIFIER_RE.fullmatch(authorization.page_id or "") is None:
        errors.append("INVALID_AUTHORIZATION_PAGE_ID")
    if not _valid_positive_int(authorization.source_page_number):
        errors.append("INVALID_AUTHORIZATION_SOURCE_PAGE")
    start = authorization.syntax_start_offset
    end = authorization.syntax_end_offset
    if (
        not _valid_offset(start)
        or not _valid_offset(end)
        or start >= end
        or end > len(syntax_baseline_tex)
    ):
        errors.append("INVALID_AUTHORIZATION_RANGE")
    elif authorization.syntax_region_sha256 != sha256_text(
        syntax_baseline_tex[start:end]
    ):
        errors.append("AUTHORIZATION_REGION_HASH_MISMATCH")
    for field_value in (
        authorization.syntax_region_sha256,
        authorization.source_page_sha256,
        authorization.source_evidence_sha256,
        *authorization.authorized_crop_sha256s,
        *authorization.authorized_operation_sha256s,
    ):
        if not _valid_sha256(field_value):
            errors.append("INVALID_AUTHORIZATION_HASH")
            break
    if len(set(authorization.authorized_crop_sha256s)) != len(
        authorization.authorized_crop_sha256s
    ):
        errors.append("DUPLICATE_AUTHORIZED_CROP")
    if len(set(authorization.authorized_operation_sha256s)) != len(
        authorization.authorized_operation_sha256s
    ):
        errors.append("DUPLICATE_AUTHORIZED_OPERATION")
    return tuple(sorted(set(errors)))


def _verification_errors(
    verification: IndependentEvidenceVerification,
    operation: EvidenceCorrectionOperation,
) -> tuple[str, ...]:
    errors: list[str] = []
    if verification.schema_version != INDEPENDENT_VERIFICATION_SCHEMA:
        errors.append("INVALID_INDEPENDENT_VERIFICATION_SCHEMA")
    if verification.operation_sha256 != operation.digest:
        errors.append("VERIFICATION_OPERATION_HASH_MISMATCH")
    if verification.source_evidence_sha256 != operation.source_evidence_sha256:
        errors.append("VERIFICATION_SOURCE_EVIDENCE_MISMATCH")
    if verification.old_text_sha256 != sha256_text(operation.old_text):
        errors.append("VERIFICATION_OLD_TEXT_MISMATCH")
    if verification.new_text_sha256 != sha256_text(operation.new_text):
        errors.append("VERIFICATION_NEW_TEXT_MISMATCH")
    if not _valid_sha256(verification.verification_evidence_sha256):
        errors.append("INVALID_VERIFICATION_EVIDENCE_HASH")
    if not str(verification.verifier or "").strip():
        errors.append("MISSING_INDEPENDENT_VERIFIER")
    if verification.independent is not True:
        errors.append("VERIFICATION_NOT_INDEPENDENT")
    if verification.verdict != "PASS":
        errors.append("INDEPENDENT_VERIFICATION_NOT_PASS")
    if verification.math_unchanged is not True:
        errors.append("VERIFICATION_MATH_CHANGE")
    if verification.structure_unchanged is not True:
        errors.append("VERIFICATION_STRUCTURE_CHANGE")
    return tuple(sorted(set(errors)))


def _operation_errors(
    operation: EvidenceCorrectionOperation,
    *,
    syntax_baseline_tex: str,
    syntax_baseline_sha256: str,
    math_spans: Sequence[tuple[int, int]],
    authorization: SourceEvidenceAuthorization | None,
    authorization_errors: Sequence[str],
    verification: IndependentEvidenceVerification | None,
) -> tuple[str, ...]:
    errors: list[str] = []
    if operation.schema_version != EVIDENCE_CORRECTION_OPERATION_SCHEMA:
        errors.append("INVALID_OPERATION_SCHEMA")
    if operation.action != "replace_exact":
        errors.append("UNSUPPORTED_OPERATION_ACTION")
    if _IDENTIFIER_RE.fullmatch(operation.operation_id or "") is None:
        errors.append("INVALID_OPERATION_ID")
    if _IDENTIFIER_RE.fullmatch(operation.page_id or "") is None:
        errors.append("INVALID_PAGE_ID")
    if not _valid_positive_int(operation.source_page_number):
        errors.append("INVALID_SOURCE_PAGE")
    if operation.syntax_baseline_sha256 != syntax_baseline_sha256:
        errors.append("STALE_SYNTAX_BASELINE")
    for value in (
        operation.syntax_baseline_sha256,
        operation.source_page_sha256,
        operation.source_evidence_sha256,
    ):
        if not _valid_sha256(value):
            errors.append("INVALID_OPERATION_HASH")
            break
    if operation.crop_sha256 and not _valid_sha256(operation.crop_sha256):
        errors.append("INVALID_CROP_HASH")
    start = operation.start_offset
    end = operation.end_offset
    range_valid = (
        _valid_offset(start)
        and _valid_offset(end)
        and start < end
        and end <= len(syntax_baseline_tex)
    )
    if not range_valid:
        errors.append("OPERATION_RANGE_OUT_OF_BOUNDS")
    elif syntax_baseline_tex[start:end] != operation.old_text:
        errors.append("OLD_TEXT_MISMATCH")
    if not operation.old_text:
        errors.append("EMPTY_OLD_TEXT")
    if operation.old_text == operation.new_text:
        errors.append("NO_EFFECT_OPERATION")
    if not str(operation.reason or "").strip():
        errors.append("MISSING_CORRECTION_REASON")
    if not str(operation.recognition_model or "").strip():
        errors.append("MISSING_RECOGNITION_MODEL")
    if _FORBIDDEN_PATCH_TOKEN_RE.search(operation.old_text + operation.new_text):
        errors.append("STRUCTURAL_REWRITE_FORBIDDEN")
    if range_valid and _intersects_math(start, end, math_spans):
        errors.append("MATH_REWRITE_FORBIDDEN")

    if authorization is None:
        errors.append("SOURCE_EVIDENCE_AUTHORIZATION_MISSING")
    else:
        errors.extend(authorization_errors)
        if authorization.page_id != operation.page_id:
            errors.append("AUTHORIZATION_PAGE_ID_MISMATCH")
        if authorization.source_page_number != operation.source_page_number:
            errors.append("AUTHORIZATION_SOURCE_PAGE_MISMATCH")
        if authorization.source_page_sha256 != operation.source_page_sha256:
            errors.append("AUTHORIZATION_SOURCE_PAGE_HASH_MISMATCH")
        if authorization.source_evidence_sha256 != operation.source_evidence_sha256:
            errors.append("AUTHORIZATION_SOURCE_EVIDENCE_HASH_MISMATCH")
        if range_valid and not (
            authorization.syntax_start_offset <= start
            and end <= authorization.syntax_end_offset
        ):
            errors.append("OPERATION_OUTSIDE_AUTHORIZED_PAGE_RANGE")
        if operation.digest not in set(authorization.authorized_operation_sha256s):
            errors.append("OPERATION_NOT_AUTHORIZED")
        if (
            operation.crop_sha256
            and operation.crop_sha256
            not in set(authorization.authorized_crop_sha256s)
        ):
            errors.append("CROP_NOT_AUTHORIZED")

    if verification is None:
        errors.append("INDEPENDENT_VERIFICATION_MISSING")
    else:
        errors.extend(_verification_errors(verification, operation))
    return tuple(sorted(set(errors)))


def _report(
    *,
    status: EvidenceCorrectionStatus,
    raw_ocr_tex: str,
    syntax_baseline_tex: str,
    evidence_tex: str | None,
    operation_audits: Sequence[EvidenceCorrectionOperationAudit],
    failure_reasons: Sequence[str],
) -> EvidenceCorrectionReport:
    if status is EvidenceCorrectionStatus.PASS:
        selected_role: str | None = "EVIDENCE_CORRECTED_BASELINE_TEX"
    elif status is EvidenceCorrectionStatus.NOT_APPLICABLE:
        selected_role = "SYNTAX_BASELINE_TEX"
    else:
        selected_role = None
    return EvidenceCorrectionReport(
        status=status,
        raw_ocr_sha256=sha256_text(raw_ocr_tex),
        raw_ocr_bytes=len(raw_ocr_tex.encode("utf-8")),
        syntax_baseline_sha256=sha256_text(syntax_baseline_tex),
        syntax_baseline_bytes=len(syntax_baseline_tex.encode("utf-8")),
        evidence_tex_sha256=(sha256_text(evidence_tex) if evidence_tex is not None else None),
        evidence_tex_bytes=(len(evidence_tex.encode("utf-8")) if evidence_tex is not None else 0),
        selected_baseline_role=selected_role,
        operation_audits=tuple(operation_audits),
        failure_reasons=tuple(sorted(set(failure_reasons))),
    )


def produce_evidence_corrected_baseline(
    *,
    raw_ocr_tex: str,
    syntax_baseline_tex: str,
    operations: Sequence[EvidenceCorrectionOperation] = (),
    source_authorizations: Sequence[SourceEvidenceAuthorization] = (),
    independent_verifications: Sequence[IndependentEvidenceVerification] = (),
) -> EvidenceCorrectionResult:
    """Conditionally produce an atomic evidence-corrected OCR baseline.

    No operations is a successful conditional no-op and returns
    ``NOT_APPLICABLE`` with ``evidence_tex=None``.  Any invalid, stale,
    unauthorized, overlapping, structural, mathematical, or unverified
    operation makes the entire batch ``FAILED`` and likewise returns no TeX.
    """

    if not isinstance(raw_ocr_tex, str) or not isinstance(syntax_baseline_tex, str):
        raise TypeError("raw and syntax baselines must be strings")
    if not raw_ocr_tex.strip() or not syntax_baseline_tex.strip():
        raise ValueError("raw and syntax baselines must be non-blank")
    operation_tuple = tuple(operations)
    if not all(isinstance(item, EvidenceCorrectionOperation) for item in operation_tuple):
        raise TypeError("operations must contain EvidenceCorrectionOperation values")
    if not operation_tuple:
        report = _report(
            status=EvidenceCorrectionStatus.NOT_APPLICABLE,
            raw_ocr_tex=raw_ocr_tex,
            syntax_baseline_tex=syntax_baseline_tex,
            evidence_tex=None,
            operation_audits=(),
            failure_reasons=(),
        )
        return EvidenceCorrectionResult(evidence_tex=None, report=report)

    authorization_tuple = tuple(source_authorizations)
    verification_tuple = tuple(independent_verifications)
    if not all(
        isinstance(item, SourceEvidenceAuthorization)
        for item in authorization_tuple
    ):
        raise TypeError(
            "source_authorizations must contain SourceEvidenceAuthorization values"
        )
    if not all(
        isinstance(item, IndependentEvidenceVerification)
        for item in verification_tuple
    ):
        raise TypeError(
            "independent_verifications must contain IndependentEvidenceVerification values"
        )

    syntax_sha256 = sha256_text(syntax_baseline_tex)
    math_spans = _math_spans(syntax_baseline_tex)
    authorizations_by_page: dict[str, SourceEvidenceAuthorization] = {}
    duplicate_authorization_pages: set[str] = set()
    authorization_errors_by_page: dict[str, tuple[str, ...]] = {}
    for authorization in authorization_tuple:
        if authorization.page_id in authorizations_by_page:
            duplicate_authorization_pages.add(authorization.page_id)
        else:
            authorizations_by_page[authorization.page_id] = authorization
        authorization_errors_by_page[authorization.page_id] = _authorization_errors(
            authorization,
            syntax_baseline_tex,
            syntax_sha256,
        )
    for page_id in duplicate_authorization_pages:
        authorization_errors_by_page[page_id] = tuple(sorted(set(
            authorization_errors_by_page.get(page_id, ())
            + ("DUPLICATE_PAGE_AUTHORIZATION",)
        )))

    verifications_by_operation: dict[str, IndependentEvidenceVerification] = {}
    duplicate_verification_operations: set[str] = set()
    for verification in verification_tuple:
        if verification.operation_sha256 in verifications_by_operation:
            duplicate_verification_operations.add(verification.operation_sha256)
        else:
            verifications_by_operation[verification.operation_sha256] = verification

    errors_by_digest: dict[str, set[str]] = {}
    operation_ids: dict[str, list[EvidenceCorrectionOperation]] = {}
    operation_digests: dict[str, list[EvidenceCorrectionOperation]] = {}
    for operation in operation_tuple:
        operation_ids.setdefault(operation.operation_id, []).append(operation)
        operation_digests.setdefault(operation.digest, []).append(operation)
        authorization = authorizations_by_page.get(operation.page_id)
        verification = verifications_by_operation.get(operation.digest)
        errors_by_digest.setdefault(operation.digest, set()).update(_operation_errors(
            operation,
            syntax_baseline_tex=syntax_baseline_tex,
            syntax_baseline_sha256=syntax_sha256,
            math_spans=math_spans,
            authorization=authorization,
            authorization_errors=authorization_errors_by_page.get(
                operation.page_id,
                (),
            ),
            verification=verification,
        ))
        if operation.digest in duplicate_verification_operations:
            errors_by_digest[operation.digest].add(
                "DUPLICATE_INDEPENDENT_VERIFICATION"
            )

    for duplicate_id, items in operation_ids.items():
        if len(items) > 1:
            for operation in items:
                errors_by_digest[operation.digest].add(
                    f"DUPLICATE_OPERATION_ID:{duplicate_id}"
                )
    for digest, items in operation_digests.items():
        if len(items) > 1:
            errors_by_digest[digest].add("DUPLICATE_OPERATION_DIGEST")

    ordered = tuple(sorted(
        operation_tuple,
        key=lambda item: (item.start_offset, item.end_offset, item.operation_id),
    ))
    for previous, current in zip(ordered, ordered[1:]):
        if (
            _valid_offset(previous.end_offset)
            and _valid_offset(current.start_offset)
            and current.start_offset < previous.end_offset
        ):
            errors_by_digest[previous.digest].add("OVERLAPPING_OPERATION")
            errors_by_digest[current.digest].add("OVERLAPPING_OPERATION")

    if any(errors_by_digest.values()):
        audits: list[EvidenceCorrectionOperationAudit] = []
        all_reasons: set[str] = set()
        for operation in ordered:
            reasons = tuple(sorted(errors_by_digest[operation.digest]))
            all_reasons.update(reasons)
            authorization = authorizations_by_page.get(operation.page_id)
            verification = verifications_by_operation.get(operation.digest)
            audits.append(EvidenceCorrectionOperationAudit(
                operation=operation,
                status=(
                    EvidenceCorrectionOperationStatus.REJECTED
                    if reasons
                    else EvidenceCorrectionOperationStatus.NOT_APPLIED
                ),
                reason_codes=(reasons if reasons else ("ATOMIC_BATCH_ABORT",)),
                source_authorization=authorization,
                independent_verification=verification,
            ))
        report = _report(
            status=EvidenceCorrectionStatus.FAILED,
            raw_ocr_tex=raw_ocr_tex,
            syntax_baseline_tex=syntax_baseline_tex,
            evidence_tex=None,
            operation_audits=audits,
            failure_reasons=all_reasons,
        )
        return EvidenceCorrectionResult(evidence_tex=None, report=report)

    evidence_tex = syntax_baseline_tex
    for operation in reversed(ordered):
        evidence_tex = (
            evidence_tex[:operation.start_offset]
            + operation.new_text
            + evidence_tex[operation.end_offset:]
        )
    postcondition_errors: list[str] = []
    if evidence_tex == syntax_baseline_tex:
        postcondition_errors.append("EVIDENCE_BASELINE_HAS_NO_CHANGE")
    if _math_fingerprint(evidence_tex) != _math_fingerprint(syntax_baseline_tex):
        postcondition_errors.append("MATH_FINGERPRINT_CHANGED")
    if _structure_fingerprint(evidence_tex) != _structure_fingerprint(
        syntax_baseline_tex
    ):
        postcondition_errors.append("STRUCTURE_FINGERPRINT_CHANGED")
    if postcondition_errors:
        audits = tuple(EvidenceCorrectionOperationAudit(
            operation=operation,
            status=EvidenceCorrectionOperationStatus.REJECTED,
            reason_codes=tuple(sorted(postcondition_errors)),
            source_authorization=authorizations_by_page[operation.page_id],
            independent_verification=verifications_by_operation[operation.digest],
        ) for operation in ordered)
        report = _report(
            status=EvidenceCorrectionStatus.FAILED,
            raw_ocr_tex=raw_ocr_tex,
            syntax_baseline_tex=syntax_baseline_tex,
            evidence_tex=None,
            operation_audits=audits,
            failure_reasons=postcondition_errors,
        )
        return EvidenceCorrectionResult(evidence_tex=None, report=report)

    audits = tuple(EvidenceCorrectionOperationAudit(
        operation=operation,
        status=EvidenceCorrectionOperationStatus.APPLIED,
        reason_codes=("SOURCE_EVIDENCE_AUTHORIZED_AND_INDEPENDENTLY_VERIFIED",),
        source_authorization=authorizations_by_page[operation.page_id],
        independent_verification=verifications_by_operation[operation.digest],
    ) for operation in ordered)
    report = _report(
        status=EvidenceCorrectionStatus.PASS,
        raw_ocr_tex=raw_ocr_tex,
        syntax_baseline_tex=syntax_baseline_tex,
        evidence_tex=evidence_tex,
        operation_audits=audits,
        failure_reasons=(),
    )
    return EvidenceCorrectionResult(evidence_tex=evidence_tex, report=report)


def produce_evidence_corrected_baseline_from_input(
    *,
    raw_ocr_tex: str,
    syntax_baseline_tex: str,
    production_input: EvidenceCorrectionProductionInput,
) -> EvidenceCorrectionResult:
    """Run the producer from one explicit typed production input."""

    if not isinstance(production_input, EvidenceCorrectionProductionInput):
        raise TypeError("production_input must be EvidenceCorrectionProductionInput")
    return produce_evidence_corrected_baseline(
        raw_ocr_tex=raw_ocr_tex,
        syntax_baseline_tex=syntax_baseline_tex,
        operations=production_input.operations,
        source_authorizations=production_input.source_authorizations,
        independent_verifications=production_input.independent_verifications,
    )


def _report_json_object(data: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate correction report key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite correction report value: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("correction report is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("correction report must be a JSON object")
    if bytes(data) != canonical_json_bytes(value):
        raise ValueError("correction report is not canonically encoded")
    return value


def verify_evidence_correction_report_bytes(
    report_bytes: bytes,
    *,
    raw_ocr_tex: str,
    syntax_baseline_tex: str,
    evidence_tex: str | None,
) -> dict[str, object]:
    """Recompute one serialized report and its exact baseline bindings."""

    payload = _report_json_object(report_bytes)
    expected_keys = {
        "schema_version",
        "status",
        "policy_sha256",
        "raw_ocr",
        "syntax_baseline",
        "evidence_corrected_baseline",
        "selected_baseline_role",
        "operation_count",
        "applied_operation_count",
        "rejected_operation_count",
        "not_applied_operation_count",
        "failure_reasons",
        "operations",
        "report_sha256",
    }
    if set(payload) != expected_keys:
        raise ValueError("correction report keys mismatch")
    if payload["schema_version"] != EVIDENCE_CORRECTION_REPORT_SCHEMA:
        raise ValueError("correction report schema is invalid")
    if payload["policy_sha256"] != EVIDENCE_CORRECTION_POLICY_SHA256:
        raise ValueError("correction report policy is stale")
    report_sha256 = payload["report_sha256"]
    body = {key: value for key, value in payload.items() if key != "report_sha256"}
    if not _valid_sha256(report_sha256) or report_sha256 != sha256_bytes(
        canonical_json_bytes(body)
    ):
        raise ValueError("correction report digest mismatch")

    def verify_input_binding(
        value: object,
        *,
        label: str,
        text: str,
    ) -> None:
        if not isinstance(value, dict) or set(value) != {
            "sha256", "bytes", "immutable"
        }:
            raise ValueError(f"correction report {label} binding is invalid")
        if value != {
            "sha256": sha256_text(text),
            "bytes": len(text.encode("utf-8")),
            "immutable": True,
        }:
            raise ValueError(f"correction report {label} binding mismatch")

    verify_input_binding(payload["raw_ocr"], label="raw OCR", text=raw_ocr_tex)
    verify_input_binding(
        payload["syntax_baseline"],
        label="syntax baseline",
        text=syntax_baseline_tex,
    )
    evidence_binding = payload["evidence_corrected_baseline"]
    if not isinstance(evidence_binding, dict) or set(evidence_binding) != {
        "sha256", "bytes"
    }:
        raise ValueError("correction report evidence baseline binding is invalid")
    expected_evidence_binding = {
        "sha256": sha256_text(evidence_tex) if evidence_tex is not None else None,
        "bytes": len(evidence_tex.encode("utf-8")) if evidence_tex is not None else 0,
    }
    if evidence_binding != expected_evidence_binding:
        raise ValueError("correction report evidence baseline binding mismatch")

    raw_operations = payload["operations"]
    if not isinstance(raw_operations, list):
        raise ValueError("correction report operations must be an array")
    status_counts = {
        EvidenceCorrectionOperationStatus.APPLIED.value: 0,
        EvidenceCorrectionOperationStatus.REJECTED.value: 0,
        EvidenceCorrectionOperationStatus.NOT_APPLIED.value: 0,
    }
    parsed_operations: list[EvidenceCorrectionOperation] = []
    parsed_authorizations: dict[str, SourceEvidenceAuthorization] = {}
    parsed_verifications: dict[str, IndependentEvidenceVerification] = {}
    operation_ids: set[str] = set()
    operation_digests: set[str] = set()
    for item in raw_operations:
        if not isinstance(item, dict) or set(item) != {
            "operation",
            "operation_sha256",
            "status",
            "reason_codes",
            "source_authorization",
            "authorization_sha256",
            "independent_verification",
            "independent_verification_sha256",
        }:
            raise ValueError("correction report operation audit is invalid")
        raw_operation = item["operation"]
        if not isinstance(raw_operation, dict):
            raise ValueError("correction report operation is invalid")
        expected_operation_keys = {
            "schema_version",
            "operation_id",
            "action",
            "syntax_baseline_sha256",
            "page_id",
            "source_page_number",
            "start_offset",
            "end_offset",
            "old_text",
            "old_text_sha256",
            "new_text",
            "new_text_sha256",
            "reason",
            "source_page_sha256",
            "source_evidence_sha256",
            "crop_sha256",
            "recognition_model",
        }
        if set(raw_operation) != expected_operation_keys:
            raise ValueError("correction report operation keys mismatch")
        operation = EvidenceCorrectionOperation(
            operation_id=raw_operation["operation_id"],
            syntax_baseline_sha256=raw_operation["syntax_baseline_sha256"],
            page_id=raw_operation["page_id"],
            source_page_number=raw_operation["source_page_number"],
            start_offset=raw_operation["start_offset"],
            end_offset=raw_operation["end_offset"],
            old_text=raw_operation["old_text"],
            new_text=raw_operation["new_text"],
            reason=raw_operation["reason"],
            source_page_sha256=raw_operation["source_page_sha256"],
            source_evidence_sha256=raw_operation["source_evidence_sha256"],
            recognition_model=raw_operation["recognition_model"],
            crop_sha256=raw_operation["crop_sha256"] or "",
            action=raw_operation["action"],
            schema_version=raw_operation["schema_version"],
        )
        if raw_operation != operation.canonical_payload():
            raise ValueError("correction report operation payload mismatch")
        if item["operation_sha256"] != operation.digest:
            raise ValueError("correction report operation digest mismatch")
        if operation.operation_id in operation_ids or operation.digest in operation_digests:
            raise ValueError("correction report contains duplicate operations")
        operation_ids.add(operation.operation_id)
        operation_digests.add(operation.digest)
        parsed_operations.append(operation)
        operation_status = item["status"]
        if operation_status not in status_counts:
            raise ValueError("correction report operation status is invalid")
        status_counts[operation_status] += 1
        reason_codes = item["reason_codes"]
        if (
            not isinstance(reason_codes, list)
            or not reason_codes
            or not all(isinstance(reason, str) and reason for reason in reason_codes)
        ):
            raise ValueError("correction report operation reasons are invalid")
        authorization_sha256 = item["authorization_sha256"]
        if authorization_sha256 is not None and not _valid_sha256(
            authorization_sha256
        ):
            raise ValueError("correction report authorization digest is invalid")
        raw_authorization = item["source_authorization"]
        authorization: SourceEvidenceAuthorization | None = None
        if raw_authorization is None:
            if authorization_sha256 is not None:
                raise ValueError("correction report authorization binding mismatch")
        else:
            expected_authorization_keys = {
                "schema_version",
                "authority_kind",
                "decision",
                "syntax_baseline_sha256",
                "page_id",
                "source_page_number",
                "syntax_start_offset",
                "syntax_end_offset",
                "syntax_region_sha256",
                "source_page_sha256",
                "source_evidence_sha256",
                "authorized_crop_sha256s",
                "authorized_operation_sha256s",
            }
            if (
                not isinstance(raw_authorization, dict)
                or set(raw_authorization) != expected_authorization_keys
                or not isinstance(
                    raw_authorization["authorized_crop_sha256s"], list
                )
                or not isinstance(
                    raw_authorization["authorized_operation_sha256s"], list
                )
            ):
                raise ValueError("correction report source authorization is invalid")
            authorization = SourceEvidenceAuthorization(
                syntax_baseline_sha256=raw_authorization[
                    "syntax_baseline_sha256"
                ],
                page_id=raw_authorization["page_id"],
                source_page_number=raw_authorization["source_page_number"],
                syntax_start_offset=raw_authorization["syntax_start_offset"],
                syntax_end_offset=raw_authorization["syntax_end_offset"],
                syntax_region_sha256=raw_authorization["syntax_region_sha256"],
                source_page_sha256=raw_authorization["source_page_sha256"],
                source_evidence_sha256=raw_authorization[
                    "source_evidence_sha256"
                ],
                authorized_operation_sha256s=tuple(
                    raw_authorization["authorized_operation_sha256s"]
                ),
                authorized_crop_sha256s=tuple(
                    raw_authorization["authorized_crop_sha256s"]
                ),
                decision=raw_authorization["decision"],
                authority_kind=raw_authorization["authority_kind"],
                schema_version=raw_authorization["schema_version"],
            )
            if raw_authorization != authorization.canonical_payload():
                raise ValueError("correction report authorization payload mismatch")
            if authorization_sha256 != authorization.digest:
                raise ValueError("correction report authorization digest mismatch")
            parsed_authorizations.setdefault(authorization.digest, authorization)
        raw_verification = item["independent_verification"]
        verification_sha256 = item["independent_verification_sha256"]
        verification: IndependentEvidenceVerification | None = None
        if raw_verification is None:
            if verification_sha256 is not None:
                raise ValueError("correction report verification binding mismatch")
        else:
            expected_verification_keys = {
                "schema_version",
                "operation_sha256",
                "source_evidence_sha256",
                "old_text_sha256",
                "new_text_sha256",
                "verification_evidence_sha256",
                "verifier",
                "verdict",
                "independent",
                "math_unchanged",
                "structure_unchanged",
                "notes",
            }
            if (
                not isinstance(raw_verification, dict)
                or set(raw_verification) != expected_verification_keys
            ):
                raise ValueError("correction report independent verification is invalid")
            verification = IndependentEvidenceVerification(
                operation_sha256=raw_verification["operation_sha256"],
                source_evidence_sha256=raw_verification["source_evidence_sha256"],
                old_text_sha256=raw_verification["old_text_sha256"],
                new_text_sha256=raw_verification["new_text_sha256"],
                verification_evidence_sha256=raw_verification[
                    "verification_evidence_sha256"
                ],
                verifier=raw_verification["verifier"],
                verdict=raw_verification["verdict"],
                independent=raw_verification["independent"],
                math_unchanged=raw_verification["math_unchanged"],
                structure_unchanged=raw_verification["structure_unchanged"],
                notes=raw_verification["notes"],
                schema_version=raw_verification["schema_version"],
            )
            if raw_verification != verification.canonical_payload():
                raise ValueError("correction report verification payload mismatch")
            if verification_sha256 != verification.digest:
                raise ValueError("correction report verification digest mismatch")
            parsed_verifications.setdefault(verification.digest, verification)
        if operation_status == EvidenceCorrectionOperationStatus.APPLIED.value:
            if authorization is None or verification is None:
                raise ValueError("applied correction lacks authority or verification")
            intrinsic_errors = _operation_errors(
                operation,
                syntax_baseline_tex=syntax_baseline_tex,
                syntax_baseline_sha256=sha256_text(syntax_baseline_tex),
                math_spans=_math_spans(syntax_baseline_tex),
                authorization=authorization,
                authorization_errors=_authorization_errors(
                    authorization,
                    syntax_baseline_tex,
                    sha256_text(syntax_baseline_tex),
                ),
                verification=verification,
            )
            if intrinsic_errors:
                raise ValueError("applied correction report operation is not valid")

    count_bindings = {
        "operation_count": len(raw_operations),
        "applied_operation_count": status_counts[
            EvidenceCorrectionOperationStatus.APPLIED.value
        ],
        "rejected_operation_count": status_counts[
            EvidenceCorrectionOperationStatus.REJECTED.value
        ],
        "not_applied_operation_count": status_counts[
            EvidenceCorrectionOperationStatus.NOT_APPLIED.value
        ],
    }
    if any(
        type(payload[key]) is not int or payload[key] != expected
        for key, expected in count_bindings.items()
    ):
        raise ValueError("correction report operation counts mismatch")
    failure_reasons = payload["failure_reasons"]
    if (
        not isinstance(failure_reasons, list)
        or not all(isinstance(reason, str) and reason for reason in failure_reasons)
        or failure_reasons != sorted(set(failure_reasons))
    ):
        raise ValueError("correction report failure reasons are invalid")

    try:
        report_status = EvidenceCorrectionStatus(payload["status"])
    except (TypeError, ValueError) as exc:
        raise ValueError("correction report status is invalid") from exc
    if report_status is EvidenceCorrectionStatus.NOT_APPLICABLE:
        if (
            raw_operations
            or evidence_tex is not None
            or payload["selected_baseline_role"] != "SYNTAX_BASELINE_TEX"
            or failure_reasons
        ):
            raise ValueError("NOT_APPLICABLE correction report is contradictory")
    elif report_status is EvidenceCorrectionStatus.PASS:
        if (
            evidence_tex is None
            or not raw_operations
            or status_counts[EvidenceCorrectionOperationStatus.APPLIED.value]
            != len(raw_operations)
            or payload["selected_baseline_role"]
            != "EVIDENCE_CORRECTED_BASELINE_TEX"
            or failure_reasons
        ):
            raise ValueError("PASS correction report is contradictory")
        # A hash-consistent report is not sufficient authority by itself: rerun
        # the deterministic producer from the embedded, hash-bound operations
        # and require the complete canonical report and output TeX to match.
        # This rejects semantic report rewrites even when an attacker also
        # refreshes the report/artifact/manifest hashes.
        recomputed = produce_evidence_corrected_baseline(
            raw_ocr_tex=raw_ocr_tex,
            syntax_baseline_tex=syntax_baseline_tex,
            operations=tuple(parsed_operations),
            source_authorizations=tuple(parsed_authorizations.values()),
            independent_verifications=tuple(parsed_verifications.values()),
        )
        if (
            recomputed.report.status is not EvidenceCorrectionStatus.PASS
            or recomputed.evidence_tex != evidence_tex
            or recomputed.report.to_dict() != payload
        ):
            raise ValueError("PASS correction report is not producer-recomputable")
    elif (
        evidence_tex is not None
        or payload["selected_baseline_role"] is not None
        or status_counts[EvidenceCorrectionOperationStatus.APPLIED.value]
        or not failure_reasons
    ):
        raise ValueError("FAILED correction report is contradictory")
    return payload


__all__ = [
    "EVIDENCE_CORRECTION_OPERATION_SCHEMA",
    "EVIDENCE_CORRECTION_POLICY",
    "EVIDENCE_CORRECTION_POLICY_SHA256",
    "EVIDENCE_CORRECTION_REPORT_SCHEMA",
    "INDEPENDENT_VERIFICATION_SCHEMA",
    "SOURCE_EVIDENCE_AUTHORIZATION_SCHEMA",
    "EvidenceCorrectionOperation",
    "EvidenceCorrectionOperationAudit",
    "EvidenceCorrectionOperationStatus",
    "EvidenceCorrectionProductionInput",
    "EvidenceCorrectionReport",
    "EvidenceCorrectionResult",
    "EvidenceCorrectionStatus",
    "IndependentEvidenceVerification",
    "SourceEvidenceAuthorization",
    "canonical_json_bytes",
    "produce_evidence_corrected_baseline",
    "produce_evidence_corrected_baseline_from_input",
    "sha256_bytes",
    "sha256_text",
    "verify_evidence_correction_report_bytes",
]
