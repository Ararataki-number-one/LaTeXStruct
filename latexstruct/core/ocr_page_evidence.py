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
PAGE_RETRY_RECORD_SCHEMA_VERSION = "latexstruct-ocr-page-retry-record-v1"
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
_FIXED_PAGE_ARTIFACTS = frozenset(
    {"source.json", "candidate.json", "verification.json", "raw-response.json", "page.tex"}
)
_RETRY_FILENAMES = frozenset(
    {"request.json", "verification.json", "raw-response.json", "record.json", "page.tex"}
)


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
    ) -> Mapping[str, str]:
        """Persist one immutable retry and finish with a hash-bound record.json."""
        if request.get("page_id") not in {None, page_id}:
            raise PageEvidenceError("retry request is bound to another page_id")
        if verification.get("page_id") not in {None, page_id}:
            raise PageEvidenceError("retry verification is bound to another page_id")
        request_artifact = self.write_retry_artifact(
            page_id, retry_id, "request.json", request
        )
        raw_artifact = self.write_retry_artifact(
            page_id, retry_id, "raw-response.json", raw_response
        )
        _json_object(raw_artifact.path.read_bytes(), "retry raw-response.json")
        verification_artifact = self.write_retry_artifact(
            page_id, retry_id, "verification.json", verification
        )
        tex_artifact = self.write_retry_artifact(
            page_id, retry_id, "page.tex", str(page_tex).encode("utf-8")
        )
        artifact_hashes = {
            "request.json": request_artifact.sha256,
            "verification.json": verification_artifact.sha256,
            "raw-response.json": raw_artifact.sha256,
            "page.tex": tex_artifact.sha256,
        }
        record = {
            "schema_version": PAGE_RETRY_RECORD_SCHEMA_VERSION,
            "run_id": self.run_id,
            "page_id": page_id,
            "retry_id": retry_id,
            "source_sha256": self.source_sha256,
            "artifact_hashes": artifact_hashes,
            "parent_artifact_hashes": dict(
                _normalized_artifact_hashes(parent_artifact_hashes or {})
            ),
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
        if (
            record["schema_version"] != PAGE_RETRY_RECORD_SCHEMA_VERSION
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
        actual["record.json"] = _sha256(record_data)
        return MappingProxyType(dict(sorted(actual.items())))

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
            actual = self.verify_page_artifacts(record.page_id)
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
            actual = self.verify_page_artifacts(record.page_id)
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
