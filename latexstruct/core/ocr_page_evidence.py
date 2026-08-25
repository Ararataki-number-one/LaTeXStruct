"""Fail-closed page coverage and append-only OCR evidence storage.

The classes in this module deliberately do not run OCR or infer document
structure.  They bind host-created page candidates, visual/full-OCR facts and
exact artifact bytes into a recomputable page-coverage record.  A page is never
counted as completed merely because a placeholder record exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence

from .ocr_schema import PageCandidate, PageClassification
from .ocr_visual import PageVisualVerification, VisualVerdict


PAGE_SOURCE_SCHEMA_VERSION = "latexstruct-ocr-page-source-v1"
PAGE_CANDIDATE_SCHEMA_VERSION = "latexstruct-ocr-page-candidate-v1"
PAGE_VERIFICATION_SCHEMA_VERSION = "latexstruct-ocr-page-verification-v1"
PAGE_RETRY_INTENT_SCHEMA_VERSION = "latexstruct-ocr-page-retry-intent-v1"
LEGACY_PAGE_RETRY_RECORD_SCHEMA_VERSION = "latexstruct-ocr-page-retry-record-v1"
PAGE_RETRY_RECORD_SCHEMA_VERSION = "latexstruct-ocr-page-retry-record-v2"
VISUAL_CALL_INTENT_SCHEMA_VERSION = "latexstruct-ocr-visual-call-intent-v1"
VISUAL_CALL_RESULT_SCHEMA_VERSION = "latexstruct-ocr-visual-call-result-v1"
VISUAL_CALL_CONSUMED_SCHEMA_VERSION = "latexstruct-ocr-visual-call-consumed-v1"
PAGE_COVERAGE_SCHEMA_VERSION = "latexstruct-ocr-page-coverage-v1"
PAGE_RECORDS_SCHEMA_VERSION = "latexstruct-ocr-page-records-coverage-v1"
COVERAGE_SUMMARY_SCHEMA_VERSION = "latexstruct-ocr-coverage-summary-v1"

COVERAGE_CHECK_NAMES = (
    "source_hash_bound",
    "candidate_created",
    "visual_authority_checked",
    "reading_order_checked",
    "text_coverage_checked",
    "math_region_coverage_checked",
    "syntax_checked",
    "persisted",
)

_PAGE_ID_RE = re.compile(r"^ocr-page-([0-9]{6})$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RETRY_ID_RE = re.compile(r"^retry-[0-9]{4,8}(?:-[A-Za-z0-9_-]{1,40})?$")
_VISUAL_CALL_ID_RE = re.compile(r"^visual-[0-9]{4,8}-[0-9a-f]{32}$")
_FIXED_PAGE_ARTIFACTS = frozenset(
    {"source.json", "candidate.json", "verification.json", "raw-response.json", "page.tex"}
)
_RETRY_FILENAMES = frozenset(
    {"request.json", "verification.json", "raw-response.json", "record.json", "page.tex"}
)
_VISUAL_CALL_FILENAMES = frozenset({"intent.json", "result.json", "consumed.json"})
_VISUAL_CALL_KINDS = frozenset({"INITIAL", "LOCAL_PATCH"})


class PageEvidenceError(RuntimeError):
    """Base class for invalid or unverifiable page evidence."""


class PageEvidenceConflictError(PageEvidenceError):
    """An append-only artifact name already exists with different bytes."""


class PageEvidenceIntegrityError(PageEvidenceError):
    """Persisted bytes do not satisfy their recorded hash bindings."""


class CoverageCheck(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class VisualMode(str, Enum):
    VERIFIER = "VERIFIER"
    FULL_OCR = "FULL_OCR"
    FULL_OCR_WITH_CROPS = "FULL_OCR_WITH_CROPS"


class FinalPageStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _canonical_json_value_sha256(value: object) -> str:
    """Hash canonical JSON content without the artifact's trailing newline."""

    return _sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _digest(value: str, label: str) -> str:
    digest = str(value or "").strip().lower()
    if _SHA256_RE.fullmatch(digest) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _page_index(page_id: str) -> int:
    match = _PAGE_ID_RE.fullmatch(str(page_id or ""))
    if match is None or int(match.group(1)) < 1:
        raise ValueError("invalid stable OCR page_id")
    return int(match.group(1))


def _strict_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{label} keys mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _json_object(data: bytes, label: str) -> Mapping[str, object]:
    try:
        value = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PageEvidenceIntegrityError(f"{label} is not UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise PageEvidenceIntegrityError(f"{label} must contain a JSON object")
    return value


def _unresolved_hashes(values: Sequence[object]) -> tuple[str, ...]:
    return tuple(sorted({_sha256(_canonical_json_bytes(value)) for value in values}))


def _normalized_artifact_hashes(value: Mapping[str, str]) -> Mapping[str, str]:
    normalized: dict[str, str] = {}
    for raw_name, raw_digest in value.items():
        name = PurePosixPath(str(raw_name)).as_posix()
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or name in normalized
        ):
            raise ValueError("artifact hash names must be unique safe relative paths")
        normalized[name] = _digest(raw_digest, f"artifact hash for {name}")
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True, slots=True)
class PageCoverageChecks:
    """The exact eight host-owned page coverage checks."""

    source_hash_bound: CoverageCheck = CoverageCheck.FAIL
    candidate_created: CoverageCheck = CoverageCheck.FAIL
    visual_authority_checked: CoverageCheck = CoverageCheck.FAIL
    reading_order_checked: CoverageCheck = CoverageCheck.FAIL
    text_coverage_checked: CoverageCheck = CoverageCheck.FAIL
    math_region_coverage_checked: CoverageCheck = CoverageCheck.FAIL
    syntax_checked: CoverageCheck = CoverageCheck.FAIL
    persisted: CoverageCheck = CoverageCheck.FAIL

    def __post_init__(self) -> None:
        for name in COVERAGE_CHECK_NAMES:
            object.__setattr__(self, name, CoverageCheck(getattr(self, name)))

    @classmethod
    def from_bools(cls, **values: bool) -> PageCoverageChecks:
        if set(values) != set(COVERAGE_CHECK_NAMES):
            raise ValueError("coverage checks must contain exactly the required eight fields")
        return cls(
            **{
                name: CoverageCheck.PASS if bool(values[name]) else CoverageCheck.FAIL
                for name in COVERAGE_CHECK_NAMES
            }
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PageCoverageChecks:
        _strict_keys(value, set(COVERAGE_CHECK_NAMES), "coverage checks")
        return cls(**{name: CoverageCheck(str(value[name])) for name in COVERAGE_CHECK_NAMES})

    @property
    def all_pass(self) -> bool:
        return all(getattr(self, name) is CoverageCheck.PASS for name in COVERAGE_CHECK_NAMES)

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name).value for name in COVERAGE_CHECK_NAMES}


@dataclass(frozen=True, slots=True)
class PageCoverageRecord:
    """Recomputable coverage result for one selected source page."""

    page_id: str
    source_page_number: int
    source_sha256: str
    source_page_object_hash: str
    checks: PageCoverageChecks = field(default_factory=PageCoverageChecks)
    visual_mode: VisualMode | None = None
    final_status: FinalPageStatus | None = None
    artifact_hashes: Mapping[str, str] = field(default_factory=dict)
    unresolved_region_hashes: tuple[str, ...] = ()
    schema_version: str = PAGE_COVERAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        selected_index = _page_index(self.page_id)
        if selected_index < 1 or int(self.source_page_number) < 1:
            raise ValueError("page coverage requires positive page identities")
        object.__setattr__(self, "source_page_number", int(self.source_page_number))
        object.__setattr__(self, "source_sha256", _digest(self.source_sha256, "source_sha256"))
        object.__setattr__(
            self,
            "source_page_object_hash",
            _digest(self.source_page_object_hash, "source_page_object_hash"),
        )
        if not isinstance(self.checks, PageCoverageChecks):
            if not isinstance(self.checks, Mapping):
                raise ValueError("checks must be PageCoverageChecks or a mapping")
            object.__setattr__(self, "checks", PageCoverageChecks.from_dict(self.checks))
        if self.visual_mode is not None:
            object.__setattr__(self, "visual_mode", VisualMode(self.visual_mode))
        if self.final_status is not None:
            object.__setattr__(self, "final_status", FinalPageStatus(self.final_status))
        object.__setattr__(
            self,
            "artifact_hashes",
            _normalized_artifact_hashes(self.artifact_hashes),
        )
        unresolved = tuple(
            _digest(item, "unresolved region hash") for item in self.unresolved_region_hashes
        )
        if len(unresolved) != len(set(unresolved)):
            raise ValueError("unresolved region hashes must be unique")
        object.__setattr__(self, "unresolved_region_hashes", tuple(sorted(unresolved)))
        if self.schema_version != PAGE_COVERAGE_SCHEMA_VERSION:
            raise ValueError("unsupported page coverage schema_version")
        if self.final_status is FinalPageStatus.SUCCESS and unresolved:
            raise ValueError("SUCCESS page coverage cannot contain unresolved regions")

    @property
    def selected_index(self) -> int:
        return _page_index(self.page_id)

    @property
    def evidence_complete(self) -> bool:
        return (
            self.checks.all_pass
            and self.visual_mode is not None
            and self.final_status is not None
            and _FIXED_PAGE_ARTIFACTS.issubset(self.artifact_hashes)
        )

    @property
    def completed(self) -> bool:
        """Only successful/review terminal pages with complete evidence count."""
        return self.evidence_complete and self.final_status in {
            FinalPageStatus.SUCCESS,
            FinalPageStatus.NEEDS_REVIEW,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "page_id": self.page_id,
            "selected_index": self.selected_index,
            "source_page_number": self.source_page_number,
            "source_sha256": self.source_sha256,
            "source_page_object_hash": self.source_page_object_hash,
            "checks": self.checks.to_dict(),
            "visual_mode": self.visual_mode.value if self.visual_mode is not None else None,
            "final_status": self.final_status.value if self.final_status is not None else None,
            "artifact_hashes": dict(self.artifact_hashes),
            "unresolved_region_hashes": list(self.unresolved_region_hashes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PageCoverageRecord:
        expected = {
            "schema_version",
            "page_id",
            "selected_index",
            "source_page_number",
            "source_sha256",
            "source_page_object_hash",
            "checks",
            "visual_mode",
            "final_status",
            "artifact_hashes",
            "unresolved_region_hashes",
        }
        _strict_keys(value, expected, "page coverage record")
        page_id = str(value["page_id"])
        if value["selected_index"] != _page_index(page_id):
            raise ValueError("page coverage selected_index does not match page_id")
        checks = value["checks"]
        artifacts = value["artifact_hashes"]
        unresolved = value["unresolved_region_hashes"]
        if not isinstance(checks, Mapping) or not isinstance(artifacts, Mapping):
            raise ValueError("page coverage checks/artifact_hashes must be objects")
        if not isinstance(unresolved, list) or not all(isinstance(item, str) for item in unresolved):
            raise ValueError("unresolved_region_hashes must be an array of strings")
        visual_mode = value["visual_mode"]
        final_status = value["final_status"]
        return cls(
            page_id=page_id,
            source_page_number=int(value["source_page_number"]),
            source_sha256=str(value["source_sha256"]),
            source_page_object_hash=str(value["source_page_object_hash"]),
            checks=PageCoverageChecks.from_dict(checks),
            visual_mode=None if visual_mode is None else VisualMode(str(visual_mode)),
            final_status=None if final_status is None else FinalPageStatus(str(final_status)),
            artifact_hashes={str(key): str(item) for key, item in artifacts.items()},
            unresolved_region_hashes=tuple(unresolved),
            schema_version=str(value["schema_version"]),
        )


@dataclass(frozen=True, slots=True)
class PageCoverageFacts:
    """Host facts used to derive, never assert, the eight coverage checks."""

    source_sha256: str
    source_page_object_hash: str
    final_page_tex: str
    final_status: FinalPageStatus | None
    verification: PageVisualVerification | None = None
    full_ocr_performed: bool = False
    full_ocr_with_crops: bool = False
    full_ocr_reading_order_checked: bool = False
    full_ocr_text_coverage_checked: bool = False
    full_ocr_math_region_coverage_checked: bool = False
    syntax_checked: bool = False
    persisted: bool = False
    artifact_hashes: Mapping[str, str] = field(default_factory=dict)
    unresolved_regions: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_sha256", _digest(self.source_sha256, "source_sha256"))
        object.__setattr__(
            self,
            "source_page_object_hash",
            _digest(self.source_page_object_hash, "source_page_object_hash"),
        )
        if self.final_status is not None:
            object.__setattr__(self, "final_status", FinalPageStatus(self.final_status))
        if self.full_ocr_with_crops and not self.full_ocr_performed:
            raise ValueError("full_ocr_with_crops requires full_ocr_performed")
        object.__setattr__(self, "artifact_hashes", _normalized_artifact_hashes(self.artifact_hashes))
        object.__setattr__(self, "unresolved_regions", tuple(self.unresolved_regions))


def _candidate(value: PageCandidate | PageClassification) -> PageCandidate:
    if isinstance(value, PageClassification):
        return value.candidate
    if not isinstance(value, PageCandidate):
        raise TypeError("coverage requires PageCandidate or PageClassification")
    return value


def build_page_coverage_record(
    candidate_or_classification: PageCandidate | PageClassification,
    facts: PageCoverageFacts,
    *,
    expected_source_sha256: str,
) -> PageCoverageRecord:
    """Derive every PASS/FAIL value from candidate and visual/full-OCR facts."""
    candidate = _candidate(candidate_or_classification)
    if facts.verification is not None and facts.verification.page_id != candidate.page_id:
        raise ValueError("candidate and visual verification page_id mismatch")
    expected_source = _digest(expected_source_sha256, "expected_source_sha256")
    source_bound = (
        facts.source_sha256 == expected_source
        and facts.source_page_object_hash == candidate.source_page_object_hash
    )
    final_tex = str(facts.final_page_tex or "")
    candidate_created = bool(candidate.candidate_tex.strip()) or (
        facts.full_ocr_performed and bool(final_tex.strip())
    )

    if facts.full_ocr_performed:
        visual_mode = (
            VisualMode.FULL_OCR_WITH_CROPS
            if facts.full_ocr_with_crops
            else VisualMode.FULL_OCR
        )
        visual_authority_checked = True
        reading_order_checked = facts.full_ocr_reading_order_checked
        text_coverage_checked = facts.full_ocr_text_coverage_checked
        math_region_coverage_checked = facts.full_ocr_math_region_coverage_checked
        unresolved = facts.unresolved_regions
    else:
        visual_mode = VisualMode.VERIFIER if facts.verification is not None else None
        verification = facts.verification
        accepted = verification is not None and verification.verdict in {
            VisualVerdict.PASS,
            VisualVerdict.PATCH,
        }
        visual_authority_checked = accepted
        reading_order_checked = bool(accepted and verification and verification.reading_order_ok)
        text_coverage_checked = bool(accepted and verification and verification.coverage_ok)
        math_region_coverage_checked = text_coverage_checked
        unresolved = tuple(facts.unresolved_regions) + (
            tuple(verification.unresolved_regions) if verification is not None else ()
        )

    artifacts = facts.artifact_hashes
    page_tex_bound = bool(final_tex) and artifacts.get("page.tex") == _sha256(
        final_tex.encode("utf-8")
    )
    persisted = (
        facts.persisted
        and _FIXED_PAGE_ARTIFACTS.issubset(artifacts)
        and page_tex_bound
    )
    checks = PageCoverageChecks.from_bools(
        source_hash_bound=source_bound,
        candidate_created=candidate_created,
        visual_authority_checked=visual_authority_checked,
        reading_order_checked=reading_order_checked,
        text_coverage_checked=text_coverage_checked,
        math_region_coverage_checked=math_region_coverage_checked,
        syntax_checked=bool(facts.syntax_checked and final_tex.strip()),
        persisted=persisted,
    )
    return PageCoverageRecord(
        page_id=candidate.page_id,
        source_page_number=candidate.source_page_number,
        source_sha256=facts.source_sha256,
        source_page_object_hash=candidate.source_page_object_hash,
        checks=checks,
        visual_mode=visual_mode,
        final_status=facts.final_status,
        artifact_hashes=artifacts,
        unresolved_region_hashes=_unresolved_hashes(unresolved),
    )


@dataclass(frozen=True, slots=True)
class StoredPageArtifact:
    path: Path
    relative_path: str
    byte_count: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PageSummaryBundle:
    page_records_bytes: bytes
    page_records_sha256: str
    coverage_bytes: bytes
    coverage_sha256: str
    records: tuple[PageCoverageRecord, ...]
    coverage: Mapping[str, object]


def _validate_record_order(
    records: Sequence[PageCoverageRecord],
    expected_source_pages: Sequence[int],
) -> tuple[PageCoverageRecord, ...]:
    frozen = tuple(records)
    expected = tuple(int(item) for item in expected_source_pages)
    if not expected or any(item < 1 for item in expected):
        raise ValueError("expected_source_pages must contain positive pages")
    if list(expected) != sorted(expected) or len(expected) != len(set(expected)):
        raise ValueError("expected_source_pages must be unique and in source order")
    if len(frozen) != len(expected):
        raise ValueError("page coverage is missing or inventing selected pages")
    page_ids = [record.page_id for record in frozen]
    source_pages = [record.source_page_number for record in frozen]
    if len(page_ids) != len(set(page_ids)) or len(source_pages) != len(set(source_pages)):
        raise ValueError("page coverage repeats a page_id or source page")
    for selected_index, (record, source_page) in enumerate(zip(frozen, expected), start=1):
        if record.selected_index != selected_index or record.source_page_number != source_page:
            raise ValueError("page coverage order/identity does not match selected source pages")
    return frozen


def build_page_summaries(
    records: Sequence[PageCoverageRecord],
    *,
    run_id: str,
    source_sha256: str,
    expected_source_pages: Sequence[int],
) -> PageSummaryBundle:
    """Create canonical page_records.json and coverage.json bytes."""
    if _RUN_ID_RE.fullmatch(str(run_id or "")) is None:
        raise ValueError("invalid OCR run_id")
    source = _digest(source_sha256, "source_sha256")
    frozen = _validate_record_order(records, expected_source_pages)
    if any(record.source_sha256 != source for record in frozen):
        raise ValueError("page coverage record is bound to a different source")
    page_records_value = {
        "schema_version": PAGE_RECORDS_SCHEMA_VERSION,
        "run_id": run_id,
        "source_sha256": source,
        "pages": [record.to_dict() for record in frozen],
    }
    page_records_bytes = _canonical_json_bytes(page_records_value)
    page_records_sha = _sha256(page_records_bytes)
    completed = sum(record.completed for record in frozen)
    success = sum(
        record.completed and record.final_status is FinalPageStatus.SUCCESS for record in frozen
    )
    needs_review = sum(
        record.completed and record.final_status is FinalPageStatus.NEEDS_REVIEW
        for record in frozen
    )
    failed = sum(record.final_status is FinalPageStatus.FAILED for record in frozen)
    cancelled = sum(record.final_status is FinalPageStatus.CANCELLED for record in frozen)
    incomplete = len(frozen) - completed - failed - cancelled
    if incomplete < 0:
        raise ValueError("page coverage statuses are contradictory")
    coverage: dict[str, object] = {
        "schema_version": COVERAGE_SUMMARY_SCHEMA_VERSION,
        "run_id": run_id,
        "source_sha256": source,
        "page_records_sha256": page_records_sha,
        "selected": len(frozen),
        "completed": completed,
        "success": success,
        "needs_review": needs_review,
        "failed": failed,
        "cancelled": cancelled,
        "incomplete": incomplete,
        "unresolved_pages": sum(bool(record.unresolved_region_hashes) for record in frozen),
        "all_selected_pages_present": True,
    }
    coverage_bytes = _canonical_json_bytes(coverage)
    return PageSummaryBundle(
        page_records_bytes=page_records_bytes,
        page_records_sha256=page_records_sha,
        coverage_bytes=coverage_bytes,
        coverage_sha256=_sha256(coverage_bytes),
        records=frozen,
        coverage=MappingProxyType(coverage),
    )


def parse_page_records(data: bytes) -> tuple[str, str, tuple[PageCoverageRecord, ...]]:
    value = _json_object(data, "page_records.json")
    _strict_keys(value, {"schema_version", "run_id", "source_sha256", "pages"}, "page records")
    if value["schema_version"] != PAGE_RECORDS_SCHEMA_VERSION:
        raise ValueError("unsupported page records schema_version")
    pages = value["pages"]
    if not isinstance(pages, list) or not all(isinstance(item, Mapping) for item in pages):
        raise ValueError("page records pages must be an array of objects")
    return (
        str(value["run_id"]),
        _digest(str(value["source_sha256"]), "source_sha256"),
        tuple(PageCoverageRecord.from_dict(item) for item in pages),
    )


def verify_page_summaries(
    page_records_bytes: bytes,
    coverage_bytes: bytes,
    *,
    expected_source_pages: Sequence[int],
) -> PageSummaryBundle:
    run_id, source_sha256, records = parse_page_records(page_records_bytes)
    rebuilt = build_page_summaries(
        records,
        run_id=run_id,
        source_sha256=source_sha256,
        expected_source_pages=expected_source_pages,
    )
    if rebuilt.page_records_bytes != bytes(page_records_bytes):
        raise PageEvidenceIntegrityError("page_records.json is not canonical/recomputable")
    if rebuilt.coverage_bytes != bytes(coverage_bytes):
        raise PageEvidenceIntegrityError("coverage.json differs from recomputed coverage")
    return rebuilt


class PageEvidenceStore:
    """Atomic, append-only evidence storage under ``root/<run_id>/pages``."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        run_id: str,
        source_sha256: str,
    ) -> None:
        if _RUN_ID_RE.fullmatch(str(run_id or "")) is None:
            raise ValueError("invalid OCR run_id")
        self.root = Path(root).resolve()
        self.run_id = str(run_id)
        self.source_sha256 = _digest(source_sha256, "source_sha256")
        self.run_dir = self.root / self.run_id
        self.pages_dir = self.run_dir / "pages"
        self.pages_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def page_dir(self, page_id: str) -> Path:
        selected_index = _page_index(page_id)
        path = self.pages_dir / f"page-{selected_index:06d}"
        self._ensure_safe(path)
        return path

    def _ensure_safe(self, path: Path) -> Path:
        resolved = path.resolve(strict=False)
        try:
            resolved.relative_to(self.run_dir.resolve())
        except ValueError as exc:
            raise PageEvidenceError("page evidence path escapes its run directory") from exc
        current = path
        while current != self.run_dir.parent and current != current.parent:
            if current.exists() and current.is_symlink():
                raise PageEvidenceError("page evidence path contains a symlink")
            if current == self.run_dir:
                break
            current = current.parent
        return path

    def _artifact_path(self, page_id: str, relative_name: str) -> Path:
        name = str(relative_name or "")
        pure = PurePosixPath(name)
        if (
            name not in _FIXED_PAGE_ARTIFACTS
            or pure.is_absolute()
            or len(pure.parts) != 1
            or "\\" in name
        ):
            raise PageEvidenceError("unsupported or unsafe page artifact path")
        return self._ensure_safe(self.page_dir(page_id) / name)

    def _retry_path(self, page_id: str, retry_id: str, filename: str) -> Path:
        if _RETRY_ID_RE.fullmatch(str(retry_id or "")) is None:
            raise PageEvidenceError("invalid retry evidence id")
        if str(filename or "") not in _RETRY_FILENAMES:
            raise PageEvidenceError("unsupported or unsafe retry artifact path")
        return self._ensure_safe(
            self.page_dir(page_id) / "retries" / str(retry_id) / str(filename)
        )

    def _visual_call_path(self, page_id: str, call_id: str, filename: str) -> Path:
        if _VISUAL_CALL_ID_RE.fullmatch(str(call_id or "")) is None:
            raise PageEvidenceError("invalid visual call evidence id")
        if str(filename or "") not in _VISUAL_CALL_FILENAMES:
            raise PageEvidenceError("unsupported or unsafe visual call artifact path")
        return self._ensure_safe(
            self.page_dir(page_id) / "visual-calls" / str(call_id) / str(filename)
        )

    @staticmethod
    def _artifact(path: Path, relative_path: str, data: bytes) -> StoredPageArtifact:
        return StoredPageArtifact(
            path=path,
            relative_path=relative_path,
            byte_count=len(data),
            sha256=_sha256(data),
        )

    def _atomic_write_once(self, path: Path, data: bytes, relative_path: str) -> StoredPageArtifact:
        payload = bytes(data)
        with self._lock:
            self._ensure_safe(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = path.read_bytes()
                if existing != payload:
                    raise PageEvidenceConflictError(
                        f"append-only artifact already exists with different bytes: {relative_path}"
                    )
                return self._artifact(path, relative_path, existing)
            temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
            descriptor: int | None = None
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = None
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    existing = path.read_bytes()
                    if existing != payload:
                        raise PageEvidenceConflictError(
                            "concurrent append-only artifact conflict: " + relative_path
                        )
                return self._artifact(path, relative_path, payload)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def write_artifact(
        self,
        page_id: str,
        relative_name: str,
        data: bytes | bytearray | memoryview,
    ) -> StoredPageArtifact:
        path = self._artifact_path(page_id, relative_name)
        return self._atomic_write_once(path, bytes(data), str(relative_name))

    def write_retry_artifact(
        self,
        page_id: str,
        retry_id: str,
        filename: str,
        data: bytes | bytearray | memoryview | Mapping[str, object],
    ) -> StoredPageArtifact:
        payload = _canonical_json_bytes(data) if isinstance(data, Mapping) else bytes(data)
        path = self._retry_path(page_id, retry_id, filename)
        relative = f"retries/{retry_id}/{filename}"
        return self._atomic_write_once(path, payload, relative)

    def next_visual_call_sequence(self, page_id: str) -> int:
        """Return the next page-local visual provider-call sequence."""

        root = self._ensure_safe(self.page_dir(page_id) / "visual-calls")
        if not root.exists():
            return 1
        if root.is_symlink() or not root.is_dir():
            raise PageEvidenceIntegrityError("visual call evidence root is not a directory")
        maximum = 0
        for path in root.iterdir():
            if path.is_symlink() or not path.is_dir():
                raise PageEvidenceIntegrityError("visual call evidence contains an unsafe entry")
            if _VISUAL_CALL_ID_RE.fullmatch(path.name) is None:
                raise PageEvidenceIntegrityError("visual call evidence contains an invalid id")
            maximum = max(maximum, int(path.name.split("-", 2)[1]))
        return maximum + 1

    def persist_visual_call_intent(
        self,
        page_id: str,
        call_id: str,
        *,
        source_page: int,
        task_index: int,
        call_kind: str,
        runtime_call_index: int,
        visual_call_sequence: int,
        provider_batch_id: str,
        image_sha256: str,
        candidate_tex_sha256: str,
        parent_result_sha256: str = "",
        required_block_ids: Sequence[str] = (),
    ) -> Mapping[str, object]:
        """Commit one exact verifier intent before invoking the provider."""

        kind = str(call_kind or "")
        block_ids = tuple(str(item) for item in required_block_ids)
        if (
            any(not item for item in block_ids)
            or len(set(block_ids)) != len(block_ids)
            or tuple(sorted(block_ids)) != block_ids
        ):
            raise PageEvidenceError("visual call required block ids must be unique and sorted")
        if kind not in _VISUAL_CALL_KINDS:
            raise PageEvidenceError("unsupported visual call kind")
        for value, label in (
            (source_page, "source_page"),
            (task_index, "task_index"),
            (runtime_call_index, "runtime_call_index"),
            (visual_call_sequence, "visual_call_sequence"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise PageEvidenceError(f"visual call {label} must be positive")
        try:
            encoded_sequence = int(str(call_id).split("-", 2)[1])
        except (IndexError, ValueError) as exc:
            raise PageEvidenceError("invalid visual call evidence id") from exc
        if (
            _VISUAL_CALL_ID_RE.fullmatch(str(call_id or "")) is None
            or encoded_sequence != visual_call_sequence
        ):
            raise PageEvidenceError("visual call id/sequence mismatch")
        if re.fullmatch(r"ocr-verify-batch-[0-9a-f]{24}", str(provider_batch_id or "")) is None:
            raise PageEvidenceError("invalid visual provider batch id")
        image_digest = _digest(image_sha256, "visual image_sha256")
        candidate_digest = _digest(candidate_tex_sha256, "visual candidate_tex_sha256")
        parent_digest = str(parent_result_sha256 or "").lower()
        if kind == "INITIAL":
            if parent_digest or block_ids:
                raise PageEvidenceError("initial visual call cannot name patch parent evidence")
        elif not block_ids or _SHA256_RE.fullmatch(parent_digest) is None:
            raise PageEvidenceError("local patch visual call lacks exact parent/coverage evidence")
        block_ids_sha256 = _sha256(_canonical_json_bytes(list(block_ids)))
        value = {
            "schema_version": VISUAL_CALL_INTENT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "source_sha256": self.source_sha256,
            "page_id": page_id,
            "source_page": source_page,
            "task_index": task_index,
            "call_id": str(call_id),
            "call_kind": kind,
            "runtime_call_index": runtime_call_index,
            "visual_call_sequence": visual_call_sequence,
            "provider_batch_id": str(provider_batch_id),
            "image_sha256": image_digest,
            "candidate_tex_sha256": candidate_digest,
            "parent_result_sha256": parent_digest,
            "required_block_ids": list(block_ids),
            "required_block_ids_sha256": block_ids_sha256,
        }
        path = self._visual_call_path(page_id, call_id, "intent.json")
        artifact = self._atomic_write_once(
            path,
            _canonical_json_bytes(value),
            f"visual-calls/{call_id}/intent.json",
        )
        loaded = dict(self.load_visual_call_intent(
            page_id, call_id, expected_sha256=artifact.sha256
        ))
        if loaded != value:
            raise PageEvidenceIntegrityError("persisted visual call intent changed")
        return MappingProxyType({
            "intent": MappingProxyType(loaded),
            "intent_sha256": artifact.sha256,
        })

    def load_visual_call_intent(
        self,
        page_id: str,
        call_id: str,
        *,
        expected_sha256: str = "",
    ) -> Mapping[str, object]:
        path = self._visual_call_path(page_id, call_id, "intent.json")
        if not path.is_file() or path.is_symlink():
            raise PageEvidenceIntegrityError("visual call intent is missing")
        try:
            data = path.read_bytes()
            value = _json_object(data, "visual call intent")
            _strict_keys(value, {
                "schema_version", "run_id", "source_sha256", "page_id",
                "source_page", "task_index", "call_id", "call_kind",
                "runtime_call_index", "visual_call_sequence", "provider_batch_id",
                "image_sha256", "candidate_tex_sha256", "parent_result_sha256",
                "required_block_ids", "required_block_ids_sha256",
            }, "visual call intent")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PageEvidenceIntegrityError("visual call intent is corrupt") from exc
        expected_digest = str(expected_sha256 or "").lower()
        if expected_digest and (
            _SHA256_RE.fullmatch(expected_digest) is None
            or _sha256(data) != expected_digest
        ):
            raise PageEvidenceIntegrityError("visual call intent SHA-256 mismatch")
        source_page = value.get("source_page")
        task_index = value.get("task_index")
        runtime_call_index = value.get("runtime_call_index")
        sequence = value.get("visual_call_sequence")
        kind = value.get("call_kind")
        blocks = value.get("required_block_ids")
        parent = str(value.get("parent_result_sha256") or "").lower()
        if (
            value.get("schema_version") != VISUAL_CALL_INTENT_SCHEMA_VERSION
            or value.get("run_id") != self.run_id
            or value.get("source_sha256") != self.source_sha256
            or value.get("page_id") != page_id
            or value.get("call_id") != call_id
            or kind not in _VISUAL_CALL_KINDS
            or not all(
                isinstance(item, int) and not isinstance(item, bool) and item >= 1
                for item in (source_page, task_index, runtime_call_index, sequence)
            )
            or int(str(call_id).split("-", 2)[1]) != sequence
            or re.fullmatch(
                r"ocr-verify-batch-[0-9a-f]{24}",
                str(value.get("provider_batch_id") or ""),
            ) is None
            or _SHA256_RE.fullmatch(str(value.get("image_sha256") or "")) is None
            or _SHA256_RE.fullmatch(str(value.get("candidate_tex_sha256") or "")) is None
            or not isinstance(blocks, list)
            or any(not isinstance(item, str) or not item for item in blocks)
            or len(set(blocks)) != len(blocks)
            or sorted(blocks) != blocks
            or value.get("required_block_ids_sha256")
            != _sha256(_canonical_json_bytes(blocks))
            or (kind == "INITIAL" and (parent or blocks))
            or (
                kind == "LOCAL_PATCH"
                and (not blocks or _SHA256_RE.fullmatch(parent) is None)
            )
        ):
            raise PageEvidenceIntegrityError("visual call intent identity/binding mismatch")
        return MappingProxyType(dict(value))

    def persist_visual_call_result(
        self,
        page_id: str,
        call_id: str,
        *,
        expected_intent_sha256: str,
        response_sha256: str,
        raw_response: Mapping[str, object],
        verification: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Persist the validated provider result before any page/lane commit."""

        intent_path = self._visual_call_path(page_id, call_id, "intent.json")
        intent_data = intent_path.read_bytes()
        intent = dict(self.load_visual_call_intent(
            page_id, call_id, expected_sha256=expected_intent_sha256
        ))
        raw_value = dict(raw_response)
        verification_value = dict(verification)
        if verification_value.get("page_id") != page_id:
            raise PageEvidenceError("visual call result is bound to another page")
        response_digest = _digest(response_sha256, "visual response_sha256")
        raw_digest = _canonical_json_value_sha256(raw_value)
        if response_digest != raw_digest:
            raise PageEvidenceError("visual response digest differs from raw response")
        value = {
            "schema_version": VISUAL_CALL_RESULT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "source_sha256": self.source_sha256,
            "page_id": page_id,
            "call_id": call_id,
            "call_kind": intent["call_kind"],
            "intent_sha256": _sha256(intent_data),
            "provider_batch_id": intent["provider_batch_id"],
            "response_sha256": response_digest,
            "raw_response_sha256": raw_digest,
            "verification_sha256": _canonical_json_value_sha256(
                verification_value
            ),
            "raw_response": raw_value,
            "verification": verification_value,
        }
        path = self._visual_call_path(page_id, call_id, "result.json")
        artifact = self._atomic_write_once(
            path,
            _canonical_json_bytes(value),
            f"visual-calls/{call_id}/result.json",
        )
        loaded = dict(self.load_visual_call_result(
            page_id, call_id, expected_sha256=artifact.sha256
        ))
        if loaded != value:
            raise PageEvidenceIntegrityError("persisted visual call result changed")
        return MappingProxyType({
            "result": MappingProxyType(loaded),
            "result_sha256": artifact.sha256,
        })

    def load_visual_call_result(
        self,
        page_id: str,
        call_id: str,
        *,
        expected_sha256: str = "",
    ) -> Mapping[str, object]:
        path = self._visual_call_path(page_id, call_id, "result.json")
        if not path.is_file() or path.is_symlink():
            raise PageEvidenceIntegrityError("visual call result is missing")
        try:
            data = path.read_bytes()
            value = _json_object(data, "visual call result")
            _strict_keys(value, {
                "schema_version", "run_id", "source_sha256", "page_id", "call_id",
                "call_kind", "intent_sha256", "provider_batch_id", "response_sha256",
                "raw_response_sha256", "verification_sha256", "raw_response",
                "verification",
            }, "visual call result")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PageEvidenceIntegrityError("visual call result is corrupt") from exc
        expected_digest = str(expected_sha256 or "").lower()
        if expected_digest and (
            _SHA256_RE.fullmatch(expected_digest) is None
            or _sha256(data) != expected_digest
        ):
            raise PageEvidenceIntegrityError("visual call result SHA-256 mismatch")
        intent_path = self._visual_call_path(page_id, call_id, "intent.json")
        intent_data = intent_path.read_bytes()
        intent = self.load_visual_call_intent(page_id, call_id)
        raw = value.get("raw_response")
        verification = value.get("verification")
        if not isinstance(raw, Mapping) or not isinstance(verification, Mapping):
            raise PageEvidenceIntegrityError("visual call result payload is malformed")
        raw_digest = _canonical_json_value_sha256(raw)
        verification_digest = _canonical_json_value_sha256(verification)
        if (
            value.get("schema_version") != VISUAL_CALL_RESULT_SCHEMA_VERSION
            or value.get("run_id") != self.run_id
            or value.get("source_sha256") != self.source_sha256
            or value.get("page_id") != page_id
            or value.get("call_id") != call_id
            or value.get("call_kind") != intent["call_kind"]
            or value.get("intent_sha256") != _sha256(intent_data)
            or value.get("provider_batch_id") != intent["provider_batch_id"]
            or value.get("response_sha256") != raw_digest
            or value.get("raw_response_sha256") != raw_digest
            or value.get("verification_sha256") != verification_digest
            or verification.get("page_id") != page_id
        ):
            raise PageEvidenceIntegrityError("visual call result identity/binding mismatch")
        return MappingProxyType(dict(value))

    def persist_visual_call_consumed(
        self,
        page_id: str,
        call_id: str,
        *,
        disposition: str,
        runtime_record_sha256: str,
        record_status: str,
        lane_owner: str,
        lane_route_sha256: str,
    ) -> Mapping[str, object]:
        """Close an intent after commit or an explicit fail-closed decision."""

        intent_path = self._visual_call_path(page_id, call_id, "intent.json")
        intent = self.load_visual_call_intent(page_id, call_id)
        intent_sha = _sha256(intent_path.read_bytes())
        result_path = self._visual_call_path(page_id, call_id, "result.json")
        result_sha = ""
        if result_path.exists():
            self.load_visual_call_result(page_id, call_id)
            result_sha = _sha256(result_path.read_bytes())
        selected_disposition = str(disposition or "")
        if selected_disposition not in {"COMMITTED", "FAIL_CLOSED"}:
            raise PageEvidenceError("invalid visual call consumed disposition")
        if selected_disposition == "COMMITTED" and not result_sha:
            raise PageEvidenceError("committed visual call has no durable result")
        value = {
            "schema_version": VISUAL_CALL_CONSUMED_SCHEMA_VERSION,
            "run_id": self.run_id,
            "source_sha256": self.source_sha256,
            "page_id": page_id,
            "call_id": call_id,
            "call_kind": intent["call_kind"],
            "intent_sha256": intent_sha,
            "result_sha256": result_sha,
            "disposition": selected_disposition,
            "runtime_record_sha256": _digest(
                runtime_record_sha256, "visual runtime_record_sha256"
            ),
            "record_status": str(record_status or ""),
            "lane_owner": str(lane_owner or ""),
            "lane_route_sha256": _digest(
                lane_route_sha256, "visual lane_route_sha256"
            ),
        }
        if not value["record_status"] or not value["lane_owner"]:
            raise PageEvidenceError("visual call consumed terminal identity is incomplete")
        path = self._visual_call_path(page_id, call_id, "consumed.json")
        artifact = self._atomic_write_once(
            path,
            _canonical_json_bytes(value),
            f"visual-calls/{call_id}/consumed.json",
        )
        loaded = dict(self.load_visual_call_consumed(
            page_id, call_id, expected_sha256=artifact.sha256
        ))
        if loaded != value:
            raise PageEvidenceIntegrityError("persisted visual call consumed marker changed")
        return MappingProxyType(loaded)

    def load_visual_call_consumed(
        self,
        page_id: str,
        call_id: str,
        *,
        expected_sha256: str = "",
    ) -> Mapping[str, object]:
        path = self._visual_call_path(page_id, call_id, "consumed.json")
        if not path.is_file() or path.is_symlink():
            raise PageEvidenceIntegrityError("visual call consumed marker is missing")
        try:
            data = path.read_bytes()
            value = _json_object(data, "visual call consumed marker")
            _strict_keys(value, {
                "schema_version", "run_id", "source_sha256", "page_id", "call_id",
                "call_kind", "intent_sha256", "result_sha256", "disposition",
                "runtime_record_sha256", "record_status", "lane_owner",
                "lane_route_sha256",
            }, "visual call consumed marker")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PageEvidenceIntegrityError("visual call consumed marker is corrupt") from exc
        expected_digest = str(expected_sha256 or "").lower()
        if expected_digest and (
            _SHA256_RE.fullmatch(expected_digest) is None
            or _sha256(data) != expected_digest
        ):
            raise PageEvidenceIntegrityError("visual call consumed SHA-256 mismatch")
        intent_path = self._visual_call_path(page_id, call_id, "intent.json")
        intent = self.load_visual_call_intent(page_id, call_id)
        result_path = self._visual_call_path(page_id, call_id, "result.json")
        actual_result_sha = ""
        if result_path.exists():
            self.load_visual_call_result(page_id, call_id)
            actual_result_sha = _sha256(result_path.read_bytes())
        if (
            value.get("schema_version") != VISUAL_CALL_CONSUMED_SCHEMA_VERSION
            or value.get("run_id") != self.run_id
            or value.get("source_sha256") != self.source_sha256
            or value.get("page_id") != page_id
            or value.get("call_id") != call_id
            or value.get("call_kind") != intent["call_kind"]
            or value.get("intent_sha256") != _sha256(intent_path.read_bytes())
            or value.get("result_sha256") != actual_result_sha
            or value.get("disposition") not in {"COMMITTED", "FAIL_CLOSED"}
            or (
                value.get("disposition") == "COMMITTED"
                and not actual_result_sha
            )
            or _SHA256_RE.fullmatch(
                str(value.get("runtime_record_sha256") or "")
            ) is None
            or _SHA256_RE.fullmatch(
                str(value.get("lane_route_sha256") or "")
            ) is None
            or not str(value.get("record_status") or "")
            or not str(value.get("lane_owner") or "")
        ):
            raise PageEvidenceIntegrityError("visual call consumed binding mismatch")
        return MappingProxyType(dict(value))

    def pending_visual_calls(
        self,
        page_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        """Return strict visual intents that have no consumed marker."""

        root = self._ensure_safe(self.page_dir(page_id) / "visual-calls")
        if not root.exists():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise PageEvidenceIntegrityError("visual call evidence root is not a directory")
        pending: list[Mapping[str, object]] = []
        seen_sequences: set[int] = set()
        for path in sorted(root.iterdir(), key=lambda item: item.name):
            if path.is_symlink() or not path.is_dir():
                raise PageEvidenceIntegrityError("visual call evidence contains an unsafe entry")
            call_id = path.name
            if _VISUAL_CALL_ID_RE.fullmatch(call_id) is None:
                raise PageEvidenceIntegrityError("visual call evidence contains an invalid id")
            intent_path = self._visual_call_path(page_id, call_id, "intent.json")
            if not intent_path.exists():
                raise PageEvidenceIntegrityError("visual call directory has no intent")
            intent = dict(self.load_visual_call_intent(page_id, call_id))
            sequence = int(intent["visual_call_sequence"])
            if sequence in seen_sequences:
                raise PageEvidenceIntegrityError("visual call sequence is duplicated")
            seen_sequences.add(sequence)
            result_path = self._visual_call_path(page_id, call_id, "result.json")
            result = None
            result_sha = ""
            if result_path.exists():
                result = dict(self.load_visual_call_result(page_id, call_id))
                result_sha = _sha256(result_path.read_bytes())
            consumed_path = self._visual_call_path(page_id, call_id, "consumed.json")
            if consumed_path.exists():
                self.load_visual_call_consumed(page_id, call_id)
                continue
            pending.append(MappingProxyType({
                "call_id": call_id,
                "intent": MappingProxyType(intent),
                "intent_sha256": _sha256(intent_path.read_bytes()),
                "result": None if result is None else MappingProxyType(result),
                "result_sha256": result_sha,
            }))
        return tuple(sorted(
            pending,
            key=lambda item: int(item["intent"]["visual_call_sequence"]),
        ))

    def base_commit_marker_exists(self, page_id: str) -> bool:
        """Return whether the immutable base verification marker exists.

        A link, directory, or unreadable marker is corruption, not absence.  A
        caller may repair only the genuinely absent case; append-only writes
        then check every pre-marker fragment byte-for-byte.
        """

        path = self._artifact_path(page_id, "verification.json")
        if not path.exists():
            return False
        if path.is_symlink() or not path.is_file():
            raise PageEvidenceIntegrityError(
                "base page evidence commit marker is not a plain file"
            )
        try:
            path.read_bytes()
        except OSError as exc:
            raise PageEvidenceIntegrityError(
                "base page evidence commit marker is unreadable"
            ) from exc
        return True

    def retry_commit_marker_exists(self, page_id: str, retry_id: str) -> bool:
        """Return whether one retry has its immutable record.json marker."""

        path = self._retry_path(page_id, retry_id, "record.json")
        if not path.exists():
            return False
        if path.is_symlink() or not path.is_file():
            raise PageEvidenceIntegrityError(
                "retry evidence commit marker is not a plain file"
            )
        try:
            path.read_bytes()
        except OSError as exc:
            raise PageEvidenceIntegrityError(
                "retry evidence commit marker is unreadable"
            ) from exc
        return True

    def persist_retry_intent(
        self,
        page_id: str,
        retry_id: str,
        *,
        intended_call_index: int,
        request: Mapping[str, object],
        parent_artifact_hashes: Mapping[str, str],
    ) -> Mapping[str, object]:
        """Commit a hash-bound retry intent before any provider invocation."""

        if (
            not isinstance(intended_call_index, int)
            or isinstance(intended_call_index, bool)
            or intended_call_index < 1
        ):
            raise PageEvidenceError("retry intended_call_index must be positive")
        request_value = dict(request)
        if request_value.get("page_id") != page_id:
            raise PageEvidenceError("retry intent request is bound to another page")
        if request_value.get("retry_id") != retry_id:
            raise PageEvidenceError("retry intent request id mismatch")
        if request_value.get("intended_call_index") != intended_call_index:
            raise PageEvidenceError("retry intent request call index mismatch")
        parent = dict(
            self.verify_coverage_artifact_hashes(
                page_id, parent_artifact_hashes
            )
        )
        value = {
            "schema_version": PAGE_RETRY_INTENT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "page_id": page_id,
            "retry_id": retry_id,
            "intended_call_index": intended_call_index,
            "request": request_value,
            "parent_artifact_hashes": parent,
        }
        artifact = self.write_retry_artifact(
            page_id,
            retry_id,
            "request.json",
            value,
        )
        loaded = dict(self.load_retry_intent(page_id, retry_id))
        if loaded != value:
            raise PageEvidenceIntegrityError(
                "persisted retry intent differs from the requested intent"
            )
        return MappingProxyType({
            "intent": MappingProxyType(loaded),
            "intent_sha256": artifact.sha256,
            "parent_artifact_hashes": MappingProxyType(parent),
        })

    def load_retry_intent(
        self,
        page_id: str,
        retry_id: str,
        *,
        expected_sha256: str = "",
    ) -> Mapping[str, object]:
        """Load one exact, append-only retry intent after identity checks."""

        path = self._retry_path(page_id, retry_id, "request.json")
        if not path.is_file() or path.is_symlink():
            raise PageEvidenceIntegrityError("retry intent request.json is missing")
        try:
            data = path.read_bytes()
            value = _json_object(data, "retry intent request.json")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PageEvidenceIntegrityError("retry intent request.json is corrupt") from exc
        expected_digest = str(expected_sha256 or "").lower()
        if expected_digest and (
            _SHA256_RE.fullmatch(expected_digest) is None
            or _sha256(data) != expected_digest
        ):
            raise PageEvidenceIntegrityError("retry intent SHA-256 binding mismatch")
        expected_fields = {
            "schema_version",
            "run_id",
            "page_id",
            "retry_id",
            "intended_call_index",
            "request",
            "parent_artifact_hashes",
        }
        try:
            _strict_keys(value, expected_fields, "retry intent")
        except ValueError as exc:
            raise PageEvidenceIntegrityError("retry intent fields are not exact") from exc
        call_index = value.get("intended_call_index")
        request = value.get("request")
        parent = value.get("parent_artifact_hashes")
        if (
            value.get("schema_version") != PAGE_RETRY_INTENT_SCHEMA_VERSION
            or value.get("run_id") != self.run_id
            or value.get("page_id") != page_id
            or value.get("retry_id") != retry_id
            or not isinstance(call_index, int)
            or isinstance(call_index, bool)
            or call_index < 1
            or not isinstance(request, Mapping)
            or request.get("page_id") != page_id
            or request.get("retry_id") != retry_id
            or request.get("intended_call_index") != call_index
            or not isinstance(parent, Mapping)
        ):
            raise PageEvidenceIntegrityError("retry intent identity is invalid")
        try:
            normalized_parent = dict(_normalized_artifact_hashes({
                str(key): str(item) for key, item in parent.items()
            }))
            verified_parent = dict(
                self.verify_coverage_artifact_hashes(page_id, normalized_parent)
            )
        except (PageEvidenceError, ValueError) as exc:
            raise PageEvidenceIntegrityError(
                "retry intent parent evidence is invalid"
            ) from exc
        if verified_parent != normalized_parent:
            raise PageEvidenceIntegrityError(
                "retry intent parent evidence differs after verification"
            )
        return MappingProxyType({
            **value,
            "request": dict(request),
            "parent_artifact_hashes": normalized_parent,
        })

    def latest_committed_coverage_head(
        self,
        page_id: str,
    ) -> Mapping[str, object]:
        """Return the newest fully committed, hash-valid evidence head."""

        heads = self._verified_coverage_heads(page_id)
        hashes, retry_id = heads[-1]
        return MappingProxyType({
            "artifact_hashes": MappingProxyType(dict(hashes)),
            "retry_id": retry_id,
        })

    def pending_retry_intents(
        self,
        page_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        """Return verified durable intents that have no retry commit marker."""

        retry_root = self._ensure_safe(self.page_dir(page_id) / "retries")
        if not retry_root.exists():
            return ()
        if retry_root.is_symlink() or not retry_root.is_dir():
            raise PageEvidenceIntegrityError("retry evidence root is not a directory")
        pending: list[Mapping[str, object]] = []
        for path in sorted(retry_root.iterdir(), key=lambda item: item.name):
            if path.is_symlink() or not path.is_dir():
                raise PageEvidenceIntegrityError(
                    "retry evidence contains an unsafe entry"
                )
            retry_id = path.name
            if self.retry_commit_marker_exists(page_id, retry_id):
                self.verify_retry_artifacts(page_id, retry_id)
                continue
            request_path = self._retry_path(page_id, retry_id, "request.json")
            if not request_path.exists():
                continue
            if request_path.is_symlink() or not request_path.is_file():
                raise PageEvidenceIntegrityError(
                    "pending retry request is not a plain file"
                )
            request = _json_object(
                request_path.read_bytes(), "pending retry request.json"
            )
            if request.get("schema_version") != PAGE_RETRY_INTENT_SCHEMA_VERSION:
                # Legacy pre-intent fragments are not durable provider intents.
                continue
            pending.append(self.load_retry_intent(page_id, retry_id))
        return tuple(sorted(
            pending,
            key=lambda item: (
                int(item["intended_call_index"]),
                str(item["retry_id"]),
            ),
        ))

    def persist_retry_bundle(
        self,
        page_id: str,
        retry_id: str,
        *,
        request: Mapping[str, object],
        verification: Mapping[str, object],
        raw_response: bytes | bytearray | memoryview | Mapping[str, object],
        page_tex: str,
        parent_artifact_hashes: Mapping[str, str] | None = None,
        expected_retry_intent_sha256: str = "",
    ) -> Mapping[str, str]:
        """Persist one immutable retry and finish with a hash-bound record.json."""
        if request.get("page_id") not in {None, page_id}:
            raise PageEvidenceError("retry request is bound to another page_id")
        if verification.get("page_id") not in {None, page_id}:
            raise PageEvidenceError("retry verification is bound to another page_id")
        normalized_parent = dict(
            _normalized_artifact_hashes(parent_artifact_hashes or {})
        )
        durable_intent = (
            request.get("schema_version") == PAGE_RETRY_INTENT_SCHEMA_VERSION
        )
        if durable_intent:
            # A production retry commits this exact wrapper before invoking the
            # provider.  The terminal bundle must reuse that append-only
            # artifact, never replace it with the nested provider request.
            loaded_intent = dict(self.load_retry_intent(
                page_id,
                retry_id,
                expected_sha256=expected_retry_intent_sha256,
            ))
            if loaded_intent != dict(request):
                raise PageEvidenceIntegrityError(
                    "terminal retry request differs from durable retry intent"
                )
            if dict(loaded_intent["parent_artifact_hashes"]) != normalized_parent:
                raise PageEvidenceIntegrityError(
                    "terminal retry parent differs from durable retry intent"
                )
            request_path = self._retry_path(page_id, retry_id, "request.json")
            request_data = request_path.read_bytes()
            request_artifact = self._artifact(
                request_path,
                f"retries/{retry_id}/request.json",
                request_data,
            )
        else:
            # Compatibility path for already-supported legacy callers whose
            # retry request itself is the append-only request.json artifact.
            if expected_retry_intent_sha256:
                raise PageEvidenceIntegrityError(
                    "durable retry intent digest supplied for a legacy request"
                )
            request_artifact = self.write_retry_artifact(
                page_id, retry_id, "request.json", request
            )
        raw_artifact = self.write_retry_artifact(
            page_id, retry_id, "raw-response.json", raw_response
        )
        _json_object(raw_artifact.path.read_bytes(), "retry raw-response.json")
        tex_artifact = self.write_retry_artifact(
            page_id, retry_id, "page.tex", str(page_tex).encode("utf-8")
        )
        if durable_intent:
            candidate_artifact_sha256 = normalized_parent.get("candidate.json")
            if candidate_artifact_sha256 is None:
                raise PageEvidenceIntegrityError(
                    "durable retry parent has no candidate.json binding"
                )
            verification_value = dict(verification)
            embedded_page_id = verification_value.get("page_id")
            if embedded_page_id is not None and str(embedded_page_id) != page_id:
                raise PageEvidenceError(
                    "retry verification is bound to another page_id"
                )
            verification_payload = {
                "schema_version": PAGE_VERIFICATION_SCHEMA_VERSION,
                "run_id": self.run_id,
                "page_id": page_id,
                "source_sha256": self.source_sha256,
                "candidate_artifact_sha256": candidate_artifact_sha256,
                "raw_response_sha256": raw_artifact.sha256,
                "final_page_tex_sha256": tex_artifact.sha256,
                "verification": verification_value,
            }
            retry_record_schema = PAGE_RETRY_RECORD_SCHEMA_VERSION
        else:
            # Explicit compatibility format for pre-intent retry callers.
            verification_payload = dict(verification)
            retry_record_schema = LEGACY_PAGE_RETRY_RECORD_SCHEMA_VERSION
        verification_artifact = self.write_retry_artifact(
            page_id, retry_id, "verification.json", verification_payload
        )
        artifact_hashes = {
            "request.json": request_artifact.sha256,
            "verification.json": verification_artifact.sha256,
            "raw-response.json": raw_artifact.sha256,
            "page.tex": tex_artifact.sha256,
        }
        record = {
            "schema_version": retry_record_schema,
            "run_id": self.run_id,
            "page_id": page_id,
            "retry_id": retry_id,
            "source_sha256": self.source_sha256,
            "artifact_hashes": artifact_hashes,
            "parent_artifact_hashes": normalized_parent,
        }
        self.write_retry_artifact(page_id, retry_id, "record.json", record)
        return self.verify_retry_artifacts(page_id, retry_id)

    def verify_retry_artifacts(self, page_id: str, retry_id: str) -> Mapping[str, str]:
        names = {"request.json", "verification.json", "raw-response.json", "page.tex"}
        record_path = self._retry_path(page_id, retry_id, "record.json")
        if not record_path.is_file() or record_path.is_symlink():
            raise PageEvidenceIntegrityError("retry evidence has no immutable record.json")
        record_data = record_path.read_bytes()
        record = _json_object(record_data, "retry record.json")
        _strict_keys(
            record,
            {
                "schema_version", "run_id", "page_id", "retry_id", "source_sha256",
                "artifact_hashes", "parent_artifact_hashes",
            },
            "retry record",
        )
        retry_record_schema = record["schema_version"]
        if (
            retry_record_schema not in {
                LEGACY_PAGE_RETRY_RECORD_SCHEMA_VERSION,
                PAGE_RETRY_RECORD_SCHEMA_VERSION,
            }
            or record["run_id"] != self.run_id
            or record["page_id"] != page_id
            or record["retry_id"] != retry_id
            or record["source_sha256"] != self.source_sha256
        ):
            raise PageEvidenceIntegrityError("retry record identity/source binding mismatch")
        recorded_hashes = record["artifact_hashes"]
        parent_hashes = record["parent_artifact_hashes"]
        if not isinstance(recorded_hashes, Mapping) or set(recorded_hashes) != names:
            raise PageEvidenceIntegrityError("retry record artifact hash coverage mismatch")
        if not isinstance(parent_hashes, Mapping):
            raise PageEvidenceIntegrityError("retry parent_artifact_hashes must be an object")
        try:
            normalized_recorded = _normalized_artifact_hashes(
                {str(key): str(value) for key, value in recorded_hashes.items()}
            )
            _normalized_artifact_hashes(
                {str(key): str(value) for key, value in parent_hashes.items()}
            )
        except ValueError as exc:
            raise PageEvidenceIntegrityError("retry record contains an invalid digest") from exc
        actual: dict[str, str] = {}
        for name in names:
            path = self._retry_path(page_id, retry_id, name)
            if not path.is_file() or path.is_symlink():
                raise PageEvidenceIntegrityError(f"retry evidence is missing {name}")
            actual[name] = _sha256(path.read_bytes())
        if dict(normalized_recorded) != dict(sorted(actual.items())):
            raise PageEvidenceIntegrityError("retry evidence artifact hash binding mismatch")
        verification_value = _json_object(
            self._retry_path(page_id, retry_id, "verification.json").read_bytes(),
            "retry verification.json",
        )
        if retry_record_schema == PAGE_RETRY_RECORD_SCHEMA_VERSION:
            _strict_keys(
                verification_value,
                {
                    "schema_version",
                    "run_id",
                    "page_id",
                    "source_sha256",
                    "candidate_artifact_sha256",
                    "raw_response_sha256",
                    "final_page_tex_sha256",
                    "verification",
                },
                "retry verification",
            )
            candidate_sha256 = dict(parent_hashes).get("candidate.json")
            if (
                verification_value["schema_version"]
                != PAGE_VERIFICATION_SCHEMA_VERSION
                or verification_value["run_id"] != self.run_id
                or verification_value["page_id"] != page_id
                or verification_value["source_sha256"] != self.source_sha256
                or verification_value["candidate_artifact_sha256"]
                != candidate_sha256
                or verification_value["raw_response_sha256"]
                != actual["raw-response.json"]
                or verification_value["final_page_tex_sha256"]
                != actual["page.tex"]
            ):
                raise PageEvidenceIntegrityError(
                    "retry verification dependency binding mismatch"
                )
            embedded = verification_value["verification"]
            if not isinstance(embedded, Mapping):
                raise PageEvidenceIntegrityError(
                    "retry verification payload must be an object"
                )
            if embedded.get("page_id") not in {None, page_id}:
                raise PageEvidenceIntegrityError(
                    "retry verification payload page_id mismatch"
                )
        actual["record.json"] = _sha256(record_data)
        return MappingProxyType(dict(sorted(actual.items())))

    def _verified_coverage_heads(
        self, page_id: str
    ) -> tuple[tuple[Mapping[str, str], str | None], ...]:
        """Return the base evidence and every hash-chained retry head."""

        base = dict(self.verify_page_artifacts(page_id))
        heads: list[tuple[Mapping[str, str], str | None]] = [
            (MappingProxyType(dict(sorted(base.items()))), None)
        ]
        retry_root = self._ensure_safe(self.page_dir(page_id) / "retries")
        if not retry_root.exists():
            return tuple(heads)
        if retry_root.is_symlink() or not retry_root.is_dir():
            raise PageEvidenceIntegrityError("retry evidence root is not a directory")
        pending = []
        for path in sorted(retry_root.iterdir(), key=lambda item: item.name):
            if path.is_symlink() or not path.is_dir():
                raise PageEvidenceIntegrityError("retry evidence contains an unsafe entry")
            retry_id = path.name
            record_path = self._retry_path(page_id, retry_id, "record.json")
            if not record_path.exists():
                # record.json is the retry commit marker.  A crash before it
                # appears leaves harmless append-only fragments that are not
                # eligible to become a coverage head.
                continue
            if record_path.is_symlink() or not record_path.is_file():
                raise PageEvidenceIntegrityError(
                    "retry evidence commit marker is not a plain file"
                )
            verified = dict(self.verify_retry_artifacts(page_id, retry_id))
            record = _json_object(
                record_path.read_bytes(),
                "retry record.json",
            )
            parent = record.get("parent_artifact_hashes")
            if not isinstance(parent, Mapping):
                raise PageEvidenceIntegrityError(
                    "retry parent artifact hashes are malformed"
                )
            pending.append((retry_id, verified, dict(parent)))
        while pending:
            advanced = False
            for retry_id, verified, parent in tuple(pending):
                parent_head = next(
                    (
                        dict(head)
                        for head, _head_retry_id in heads
                        if dict(head) == dict(sorted(parent.items()))
                    ),
                    None,
                )
                if parent_head is None:
                    continue
                combined = dict(parent_head)
                combined.update({
                    "verification.json": verified["verification.json"],
                    "raw-response.json": verified["raw-response.json"],
                    "page.tex": verified["page.tex"],
                    "retry-record.json": verified["record.json"],
                })
                heads.append((
                    MappingProxyType(dict(sorted(combined.items()))),
                    retry_id,
                ))
                pending.remove((retry_id, verified, parent))
                advanced = True
            if not advanced:
                raise PageEvidenceIntegrityError(
                    "retry evidence parent hash chain is disconnected"
                )
        return tuple(heads)

    def verify_coverage_artifact_hashes(
        self,
        page_id: str,
        artifact_hashes: Mapping[str, str],
    ) -> Mapping[str, str]:
        """Verify that coverage points at the base bundle or a retry head."""

        expected = dict(_normalized_artifact_hashes(artifact_hashes))
        for head, _retry_id in self._verified_coverage_heads(page_id):
            if dict(head) == expected:
                return head
        raise PageEvidenceIntegrityError(
            "page coverage artifact hashes do not identify a verified evidence head"
        )

    def persist_retry_coverage_bundle(
        self,
        page_id: str,
        retry_id: str,
        *,
        request: Mapping[str, object],
        verification: Mapping[str, object],
        raw_response: bytes | bytearray | memoryview | Mapping[str, object],
        page_tex: str,
        parent_artifact_hashes: Mapping[str, str],
        expected_retry_intent_sha256: str = "",
    ) -> Mapping[str, str]:
        """Persist a retry and return the verified coverage-head hash map."""

        parent = dict(
            self.verify_coverage_artifact_hashes(
                page_id, parent_artifact_hashes
            )
        )
        retry = dict(self.persist_retry_bundle(
            page_id,
            retry_id,
            request=request,
            verification=verification,
            raw_response=raw_response,
            page_tex=page_tex,
            parent_artifact_hashes=parent,
            expected_retry_intent_sha256=expected_retry_intent_sha256,
        ))
        combined = dict(parent)
        combined.update({
            "verification.json": retry["verification.json"],
            "raw-response.json": retry["raw-response.json"],
            "page.tex": retry["page.tex"],
            "retry-record.json": retry["record.json"],
        })
        return self.verify_coverage_artifact_hashes(page_id, combined)

    def verify_terminal_page_artifacts(
        self,
        page_id: str,
        *,
        raw_response: Mapping[str, object],
        page_tex: str,
    ) -> Mapping[str, object]:
        """Resolve the immutable evidence head matching one terminal record."""

        expected_response = dict(raw_response)
        expected_tex = str(page_tex)
        for hashes, retry_id in reversed(self._verified_coverage_heads(page_id)):
            if retry_id is None:
                raw_path = self._artifact_path(page_id, "raw-response.json")
                tex_path = self._artifact_path(page_id, "page.tex")
                verification_path = self._artifact_path(
                    page_id, "verification.json"
                )
            else:
                raw_path = self._retry_path(page_id, retry_id, "raw-response.json")
                tex_path = self._retry_path(page_id, retry_id, "page.tex")
                verification_path = self._retry_path(
                    page_id, retry_id, "verification.json"
                )
            raw_value = _json_object(raw_path.read_bytes(), "terminal raw-response.json")
            if raw_value != expected_response or tex_path.read_text(
                encoding="utf-8"
            ) != expected_tex:
                continue
            verification_value = _json_object(
                verification_path.read_bytes(), "terminal verification.json"
            )
            if retry_id is not None:
                retry_record = _json_object(
                    self._retry_path(page_id, retry_id, "record.json").read_bytes(),
                    "retry record.json",
                )
                if (
                    retry_record.get("schema_version")
                    == LEGACY_PAGE_RETRY_RECORD_SCHEMA_VERSION
                ):
                    # Pre-intent retry artifacts stored the verified payload
                    # directly.  Normalize only after the legacy record and
                    # its full artifact hash set have passed strict checks.
                    verification_value = {"verification": verification_value}
            return MappingProxyType({
                "artifact_hashes": hashes,
                "verification": verification_value,
                "retry_id": retry_id,
            })
        raise PageEvidenceIntegrityError(
            "no immutable page evidence head matches the terminal runtime record"
        )

    def persist_source(
        self,
        candidate_or_classification: PageCandidate | PageClassification,
    ) -> StoredPageArtifact:
        candidate = _candidate(candidate_or_classification)
        value = {
            "schema_version": PAGE_SOURCE_SCHEMA_VERSION,
            "run_id": self.run_id,
            "page_id": candidate.page_id,
            "selected_index": candidate.selected_index,
            "source_page_number": candidate.source_page_number,
            "source_sha256": self.source_sha256,
            "source_page_object_hash": candidate.source_page_object_hash,
            "source_text_layer_sha256": candidate.source_text_layer_sha256,
        }
        return self.write_artifact(candidate.page_id, "source.json", _canonical_json_bytes(value))

    def persist_candidate(
        self,
        candidate_or_classification: PageCandidate | PageClassification,
        *,
        source_artifact_sha256: str | None = None,
    ) -> StoredPageArtifact:
        candidate = _candidate(candidate_or_classification)
        source_hash = source_artifact_sha256
        if source_hash is None:
            source_hash = _sha256(self._artifact_path(candidate.page_id, "source.json").read_bytes())
        payload = candidate_or_classification.to_dict()
        value = {
            "schema_version": PAGE_CANDIDATE_SCHEMA_VERSION,
            "run_id": self.run_id,
            "page_id": candidate.page_id,
            "source_sha256": self.source_sha256,
            "source_artifact_sha256": _digest(source_hash, "source_artifact_sha256"),
            "candidate_sha256": _sha256(_canonical_json_bytes(payload)),
            "candidate": payload,
        }
        return self.write_artifact(candidate.page_id, "candidate.json", _canonical_json_bytes(value))

    def persist_raw_response(
        self,
        page_id: str,
        response: bytes | bytearray | memoryview | Mapping[str, object],
    ) -> StoredPageArtifact:
        payload = _canonical_json_bytes(response) if isinstance(response, Mapping) else bytes(response)
        _json_object(payload, "raw-response.json")
        return self.write_artifact(page_id, "raw-response.json", payload)

    def persist_page_tex(self, page_id: str, page_tex: str) -> StoredPageArtifact:
        return self.write_artifact(page_id, "page.tex", str(page_tex).encode("utf-8"))

    def persist_verification(
        self,
        page_id: str,
        verification: PageVisualVerification | Mapping[str, object],
        *,
        candidate_artifact_sha256: str,
        raw_response_sha256: str,
        final_page_tex_sha256: str,
    ) -> StoredPageArtifact:
        if isinstance(verification, PageVisualVerification):
            verification_value = verification.to_dict()
        elif isinstance(verification, Mapping):
            verification_value = dict(verification)
        else:
            raise TypeError("verification must be PageVisualVerification or a mapping")
        embedded_page_id = verification_value.get("page_id")
        if embedded_page_id is not None and str(embedded_page_id) != page_id:
            raise PageEvidenceError("verification is bound to another page_id")
        value = {
            "schema_version": PAGE_VERIFICATION_SCHEMA_VERSION,
            "run_id": self.run_id,
            "page_id": page_id,
            "source_sha256": self.source_sha256,
            "candidate_artifact_sha256": _digest(
                candidate_artifact_sha256, "candidate_artifact_sha256"
            ),
            "raw_response_sha256": _digest(raw_response_sha256, "raw_response_sha256"),
            "final_page_tex_sha256": _digest(
                final_page_tex_sha256, "final_page_tex_sha256"
            ),
            "verification": verification_value,
        }
        return self.write_artifact(page_id, "verification.json", _canonical_json_bytes(value))

    def persist_page_bundle(
        self,
        candidate_or_classification: PageCandidate | PageClassification,
        *,
        verification: PageVisualVerification | Mapping[str, object],
        raw_response: bytes | bytearray | memoryview | Mapping[str, object],
        page_tex: str,
    ) -> Mapping[str, str]:
        """Persist a page in dependency order; verification is the commit marker."""
        candidate = _candidate(candidate_or_classification)
        source = self.persist_source(candidate_or_classification)
        candidate_artifact = self.persist_candidate(
            candidate_or_classification,
            source_artifact_sha256=source.sha256,
        )
        raw = self.persist_raw_response(candidate.page_id, raw_response)
        tex = self.persist_page_tex(candidate.page_id, page_tex)
        self.persist_verification(
            candidate.page_id,
            verification,
            candidate_artifact_sha256=candidate_artifact.sha256,
            raw_response_sha256=raw.sha256,
            final_page_tex_sha256=tex.sha256,
        )
        return self.verify_page_artifacts(candidate.page_id)

    def verify_page_artifacts(self, page_id: str) -> Mapping[str, str]:
        paths = {name: self._artifact_path(page_id, name) for name in _FIXED_PAGE_ARTIFACTS}
        if any(not path.is_file() or path.is_symlink() for path in paths.values()):
            raise PageEvidenceIntegrityError(f"page evidence is incomplete: {page_id}")
        data = {name: path.read_bytes() for name, path in paths.items()}
        hashes = {name: _sha256(payload) for name, payload in data.items()}
        source = _json_object(data["source.json"], "source.json")
        candidate = _json_object(data["candidate.json"], "candidate.json")
        verification = _json_object(data["verification.json"], "verification.json")
        _json_object(data["raw-response.json"], "raw-response.json")
        _strict_keys(
            source,
            {
                "schema_version", "run_id", "page_id", "selected_index",
                "source_page_number", "source_sha256", "source_page_object_hash",
                "source_text_layer_sha256",
            },
            "source evidence",
        )
        _strict_keys(
            candidate,
            {
                "schema_version", "run_id", "page_id", "source_sha256",
                "source_artifact_sha256", "candidate_sha256", "candidate",
            },
            "candidate evidence",
        )
        _strict_keys(
            verification,
            {
                "schema_version", "run_id", "page_id", "source_sha256",
                "candidate_artifact_sha256", "raw_response_sha256",
                "final_page_tex_sha256", "verification",
            },
            "verification evidence",
        )
        expected_identity = {"run_id": self.run_id, "page_id": page_id, "source_sha256": self.source_sha256}
        for label, value in (("source", source), ("candidate", candidate), ("verification", verification)):
            if any(value[key] != expected for key, expected in expected_identity.items()):
                raise PageEvidenceIntegrityError(f"{label} evidence identity/source binding mismatch")
        if source["schema_version"] != PAGE_SOURCE_SCHEMA_VERSION:
            raise PageEvidenceIntegrityError("source evidence schema mismatch")
        if candidate["schema_version"] != PAGE_CANDIDATE_SCHEMA_VERSION:
            raise PageEvidenceIntegrityError("candidate evidence schema mismatch")
        if verification["schema_version"] != PAGE_VERIFICATION_SCHEMA_VERSION:
            raise PageEvidenceIntegrityError("verification evidence schema mismatch")
        if source["selected_index"] != _page_index(page_id):
            raise PageEvidenceIntegrityError("source evidence selected_index mismatch")
        try:
            _digest(str(source["source_page_object_hash"]), "source_page_object_hash")
            _digest(str(source["source_text_layer_sha256"]), "source_text_layer_sha256")
        except ValueError as exc:
            raise PageEvidenceIntegrityError("source evidence contains an invalid digest") from exc
        if not isinstance(source["source_page_number"], int) or source["source_page_number"] < 1:
            raise PageEvidenceIntegrityError("source evidence page number is invalid")
        candidate_payload = candidate["candidate"]
        if not isinstance(candidate_payload, Mapping):
            raise PageEvidenceIntegrityError("candidate evidence payload must be an object")
        if (
            candidate["source_artifact_sha256"] != hashes["source.json"]
            or candidate["candidate_sha256"] != _sha256(_canonical_json_bytes(candidate_payload))
            or candidate_payload.get("page_id") != page_id
            or candidate_payload.get("selected_index") != source["selected_index"]
            or candidate_payload.get("source_page_number") != source["source_page_number"]
            or candidate_payload.get("source_page_object_hash") != source["source_page_object_hash"]
        ):
            raise PageEvidenceIntegrityError("candidate evidence hash/page binding mismatch")
        if (
            verification["candidate_artifact_sha256"] != hashes["candidate.json"]
            or verification["raw_response_sha256"] != hashes["raw-response.json"]
            or verification["final_page_tex_sha256"] != hashes["page.tex"]
        ):
            raise PageEvidenceIntegrityError("verification evidence artifact binding mismatch")
        verification_payload = verification["verification"]
        if not isinstance(verification_payload, Mapping):
            raise PageEvidenceIntegrityError("verification payload must be an object")
        embedded_page_id = verification_payload.get("page_id")
        if embedded_page_id is not None and embedded_page_id != page_id:
            raise PageEvidenceIntegrityError("verification payload page_id mismatch")
        return MappingProxyType(dict(sorted(hashes.items())))

    def build_coverage_record(
        self,
        candidate_or_classification: PageCandidate | PageClassification,
        facts: PageCoverageFacts,
    ) -> PageCoverageRecord:
        candidate = _candidate(candidate_or_classification)
        artifacts = self.verify_page_artifacts(candidate.page_id)
        source = _json_object(
            self._artifact_path(candidate.page_id, "source.json").read_bytes(),
            "source.json",
        )
        if (
            source.get("source_page_number") != candidate.source_page_number
            or source.get("source_page_object_hash") != candidate.source_page_object_hash
        ):
            raise PageEvidenceIntegrityError("persisted source evidence differs from candidate")
        bound_facts = replace(facts, persisted=True, artifact_hashes=artifacts)
        return build_page_coverage_record(
            candidate_or_classification,
            bound_facts,
            expected_source_sha256=self.source_sha256,
        )

    def persist_summaries(
        self,
        records: Sequence[PageCoverageRecord],
        *,
        expected_source_pages: Sequence[int],
    ) -> PageSummaryBundle:
        bundle = build_page_summaries(
            records,
            run_id=self.run_id,
            source_sha256=self.source_sha256,
            expected_source_pages=expected_source_pages,
        )
        for record in bundle.records:
            actual = self.verify_coverage_artifact_hashes(
                record.page_id, record.artifact_hashes
            )
            if dict(actual) != dict(record.artifact_hashes):
                raise PageEvidenceIntegrityError(
                    f"page record artifact hashes differ from stored bytes: {record.page_id}"
                )
        self._atomic_write_once(
            self.pages_dir / "page_records.json",
            bundle.page_records_bytes,
            "pages/page_records.json",
        )
        self._atomic_write_once(
            self.pages_dir / "coverage.json",
            bundle.coverage_bytes,
            "pages/coverage.json",
        )
        return bundle

    def verify_summaries(
        self,
        *,
        expected_source_pages: Sequence[int],
    ) -> PageSummaryBundle:
        page_records_path = self._ensure_safe(self.pages_dir / "page_records.json")
        coverage_path = self._ensure_safe(self.pages_dir / "coverage.json")
        if not page_records_path.is_file() or not coverage_path.is_file():
            raise PageEvidenceIntegrityError("page summary artifacts are incomplete")
        bundle = verify_page_summaries(
            page_records_path.read_bytes(),
            coverage_path.read_bytes(),
            expected_source_pages=expected_source_pages,
        )
        if bundle.records and (
            bundle.records[0].source_sha256 != self.source_sha256
            or json.loads(bundle.page_records_bytes)["run_id"] != self.run_id
        ):
            raise PageEvidenceIntegrityError("page summaries are bound to another run/source")
        for record in bundle.records:
            actual = self.verify_coverage_artifact_hashes(
                record.page_id, record.artifact_hashes
            )
            if dict(actual) != dict(record.artifact_hashes):
                raise PageEvidenceIntegrityError(
                    f"persisted page artifact was modified: {record.page_id}"
                )
        return bundle


__all__ = [
    "COVERAGE_CHECK_NAMES",
    "COVERAGE_SUMMARY_SCHEMA_VERSION",
    "CoverageCheck",
    "FinalPageStatus",
    "PAGE_CANDIDATE_SCHEMA_VERSION",
    "PAGE_COVERAGE_SCHEMA_VERSION",
    "PAGE_RETRY_RECORD_SCHEMA_VERSION",
    "PAGE_RECORDS_SCHEMA_VERSION",
    "PAGE_SOURCE_SCHEMA_VERSION",
    "PAGE_VERIFICATION_SCHEMA_VERSION",
    "PageCoverageChecks",
    "PageCoverageFacts",
    "PageCoverageRecord",
    "PageEvidenceConflictError",
    "PageEvidenceError",
    "PageEvidenceIntegrityError",
    "PageEvidenceStore",
    "PageSummaryBundle",
    "StoredPageArtifact",
    "VisualMode",
    "build_page_coverage_record",
    "build_page_summaries",
    "parse_page_records",
    "verify_page_summaries",
]
