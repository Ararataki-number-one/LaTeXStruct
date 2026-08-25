"""Public, hash-only projections of private per-page OCR evidence.

The OCR run store and :mod:`ocr_page_evidence` directory intentionally retain
provider responses and TeX so a local auditor can reproduce a page decision.
Those bytes must not be copied into a public release attestation.  This module
verifies the private records first and then emits a closed-schema projection
containing only stable identities, enums, counters and SHA-256 digests.

The projection is also an independent bridge between the terminal runtime page
records and the scheduler lane routes.  In particular, a terminal visual route
must bind the exact visual-verifier response saved in its host envelope, while
a full-OCR terminal deliberately has no visual-response binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


OCR_PAGE_EVIDENCE_BINDINGS_SCHEMA = (
    "latexstruct-ocr-page-evidence-bindings-v1"
)

_RUN_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_PAGE_ID_RE = re.compile(r"^ocr-page-(?P<index>[0-9]{6})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_TOP_LEVEL_KEYS = frozenset({
    "schema_version",
    "run_id",
    "source_sha256",
    "selected_pages",
    "pages",
})
_PAGE_KEYS = frozenset({
    "page_id",
    "source_page",
    "selected_index",
    "terminal_mode",
    "terminal_status",
    "initial_candidate_tex_sha256",
    "visual_verification_response_sha256",
    "terminal_cleaned_tex_sha256",
    "runtime_record_sha256",
    "runtime_source_evidence_sha256",
    "runtime_raw_response_sha256",
    "page_evidence_source_sha256",
    "page_evidence_candidate_sha256",
    "page_evidence_verification_sha256",
    "page_evidence_raw_response_sha256",
    "page_evidence_tex_sha256",
})


class OcrPageEvidenceBindingsError(ValueError):
    """Raised when the public projection is incomplete or not reproducible."""


class OcrPageTerminalMode(str, Enum):
    VISUAL = "VISUAL"
    FULL_OCR = "FULL_OCR"
    FULL_OCR_WITH_CROPS = "FULL_OCR_WITH_CROPS"


def _fail(message: str) -> None:
    raise OcrPageEvidenceBindingsError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _digest(value: object, label: str) -> str:
    text = str(value or "").lower()
    if _SHA256_RE.fullmatch(text) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return text


def canonical_page_evidence_bindings_json_bytes(value: object) -> bytes:
    """Return the sole accepted byte encoding for the public artifact."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _canonical_runtime_json_bytes(value: object) -> bytes:
    """Match the no-trailing-newline encoding used by ``OcrRunStore``."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_duplicate_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(data: bytes, label: str) -> dict[str, Any]:
    if not isinstance(data, bytes | bytearray | memoryview) or not data:
        _fail(f"{label} must contain non-empty JSON bytes")
    try:
        value = json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda item: _fail(
                f"{label} contains non-finite {item}"
            ),
        )
    except OcrPageEvidenceBindingsError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrPageEvidenceBindingsError(
            f"{label} is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class OcrPageEvidenceBinding:
    page_id: str
    source_page: int
    selected_index: int
    terminal_mode: OcrPageTerminalMode
    terminal_status: str
    initial_candidate_tex_sha256: str
    visual_verification_response_sha256: str | None
    terminal_cleaned_tex_sha256: str
    runtime_record_sha256: str
    runtime_source_evidence_sha256: str
    runtime_raw_response_sha256: str
    page_evidence_source_sha256: str
    page_evidence_candidate_sha256: str
    page_evidence_verification_sha256: str
    page_evidence_raw_response_sha256: str
    page_evidence_tex_sha256: str

    def __post_init__(self) -> None:
        match = _PAGE_ID_RE.fullmatch(str(self.page_id or ""))
        selected_index = _positive_int(self.selected_index, "selected_index")
        if match is None or int(match.group("index")) != selected_index:
            _fail("page_id must be derived from selected_index")
        _positive_int(self.source_page, "source_page")
        mode = OcrPageTerminalMode(self.terminal_mode)
        status = str(self.terminal_status or "")
        if status not in {"SUCCESS", "NEEDS_REVIEW"}:
            _fail("terminal_status must be SUCCESS or NEEDS_REVIEW")
        visual_hash = self.visual_verification_response_sha256
        if mode is OcrPageTerminalMode.VISUAL:
            visual_hash = _digest(
                visual_hash, "visual_verification_response_sha256"
            )
        elif visual_hash is not None:
            _fail("full OCR must not claim a visual verification response hash")
        digest_fields = (
            "initial_candidate_tex_sha256",
            "terminal_cleaned_tex_sha256",
            "runtime_record_sha256",
            "runtime_source_evidence_sha256",
            "runtime_raw_response_sha256",
            "page_evidence_source_sha256",
            "page_evidence_candidate_sha256",
            "page_evidence_verification_sha256",
            "page_evidence_raw_response_sha256",
            "page_evidence_tex_sha256",
        )
        for name in digest_fields:
            object.__setattr__(self, name, _digest(getattr(self, name), name))
        if not hmac.compare_digest(
            self.terminal_cleaned_tex_sha256,
            self.page_evidence_tex_sha256,
        ):
            _fail("terminal cleaned TeX hash differs from page.tex evidence")
        object.__setattr__(self, "terminal_mode", mode)
        object.__setattr__(self, "terminal_status", status)
        object.__setattr__(
            self, "visual_verification_response_sha256", visual_hash
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "selected_index": self.selected_index,
            "terminal_mode": self.terminal_mode.value,
            "terminal_status": self.terminal_status,
            "initial_candidate_tex_sha256": self.initial_candidate_tex_sha256,
            "visual_verification_response_sha256": (
                self.visual_verification_response_sha256
            ),
            "terminal_cleaned_tex_sha256": self.terminal_cleaned_tex_sha256,
            "runtime_record_sha256": self.runtime_record_sha256,
            "runtime_source_evidence_sha256": (
                self.runtime_source_evidence_sha256
            ),
            "runtime_raw_response_sha256": self.runtime_raw_response_sha256,
            "page_evidence_source_sha256": self.page_evidence_source_sha256,
            "page_evidence_candidate_sha256": (
                self.page_evidence_candidate_sha256
            ),
            "page_evidence_verification_sha256": (
                self.page_evidence_verification_sha256
            ),
            "page_evidence_raw_response_sha256": (
                self.page_evidence_raw_response_sha256
            ),
            "page_evidence_tex_sha256": self.page_evidence_tex_sha256,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, object]
    ) -> "OcrPageEvidenceBinding":
        if set(value) != _PAGE_KEYS:
            _fail("OCR page evidence binding keys mismatch")
        try:
            return cls(
                page_id=str(value["page_id"]),
                source_page=value["source_page"],
                selected_index=value["selected_index"],
                terminal_mode=OcrPageTerminalMode(str(value["terminal_mode"])),
                terminal_status=str(value["terminal_status"]),
                initial_candidate_tex_sha256=str(
                    value["initial_candidate_tex_sha256"]
                ),
                visual_verification_response_sha256=(
                    None
                    if value["visual_verification_response_sha256"] is None
                    else str(value["visual_verification_response_sha256"])
                ),
                terminal_cleaned_tex_sha256=str(
                    value["terminal_cleaned_tex_sha256"]
                ),
                runtime_record_sha256=str(value["runtime_record_sha256"]),
                runtime_source_evidence_sha256=str(
                    value["runtime_source_evidence_sha256"]
                ),
                runtime_raw_response_sha256=str(
                    value["runtime_raw_response_sha256"]
                ),
                page_evidence_source_sha256=str(
                    value["page_evidence_source_sha256"]
                ),
                page_evidence_candidate_sha256=str(
                    value["page_evidence_candidate_sha256"]
                ),
                page_evidence_verification_sha256=str(
                    value["page_evidence_verification_sha256"]
                ),
                page_evidence_raw_response_sha256=str(
                    value["page_evidence_raw_response_sha256"]
                ),
                page_evidence_tex_sha256=str(
                    value["page_evidence_tex_sha256"]
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, OcrPageEvidenceBindingsError):
                raise
            raise OcrPageEvidenceBindingsError(
                "OCR page evidence binding is malformed"
            ) from exc


def build_ocr_page_evidence_bindings(
    *,
    run_id: str,
    source_sha256: str,
    selected_pages: Sequence[int],
    pages: Sequence[OcrPageEvidenceBinding],
) -> bytes:
    """Build a canonical, hash-only projection from already verified rows."""

    normalized_run_id = str(run_id or "")
    if _RUN_ID_RE.fullmatch(normalized_run_id) is None:
        _fail("OCR page evidence bindings run_id is invalid")
    source = _digest(source_sha256, "source_sha256")
    expected_pages = tuple(
        _positive_int(value, "selected page") for value in selected_pages
    )
    if not expected_pages or len(set(expected_pages)) != len(expected_pages):
        _fail("selected_pages must contain unique positive pages")
    rows = tuple(pages)
    if len(rows) != len(expected_pages):
        _fail("OCR page evidence bindings do not cover every selected page")
    for index, (source_page, row) in enumerate(
        zip(expected_pages, rows, strict=True), start=1
    ):
        if (
            not isinstance(row, OcrPageEvidenceBinding)
            or row.selected_index != index
            or row.page_id != f"ocr-page-{index:06d}"
            or row.source_page != source_page
        ):
            _fail("OCR page evidence binding order/identity is stale")
    return canonical_page_evidence_bindings_json_bytes({
        "schema_version": OCR_PAGE_EVIDENCE_BINDINGS_SCHEMA,
        "run_id": normalized_run_id,
        "source_sha256": source,
        "selected_pages": list(expected_pages),
        "pages": [row.to_dict() for row in rows],
    })


def parse_ocr_page_evidence_bindings(
    data: bytes,
    *,
    expected_run_id: str,
    expected_source_sha256: str,
    expected_selected_pages: Sequence[int],
) -> tuple[OcrPageEvidenceBinding, ...]:
    """Parse and fully recompute one canonical public projection."""

    value = _load_json_object(data, "OCR page evidence bindings")
    if set(value) != _TOP_LEVEL_KEYS:
        _fail("OCR page evidence bindings top-level keys mismatch")
    if value.get("schema_version") != OCR_PAGE_EVIDENCE_BINDINGS_SCHEMA:
        _fail("unsupported OCR page evidence bindings schema")
    raw_pages = value.get("pages")
    if not isinstance(raw_pages, list) or any(
        not isinstance(item, Mapping) for item in raw_pages
    ):
        _fail("OCR page evidence bindings pages must be objects")
    rows = tuple(OcrPageEvidenceBinding.from_dict(item) for item in raw_pages)
    rebuilt = build_ocr_page_evidence_bindings(
        run_id=str(expected_run_id),
        source_sha256=str(expected_source_sha256),
        selected_pages=tuple(expected_selected_pages),
        pages=rows,
    )
    if (
        value.get("run_id") != str(expected_run_id)
        or value.get("source_sha256") != str(expected_source_sha256).lower()
        or value.get("selected_pages")
        != [int(item) for item in expected_selected_pages]
        or bytes(data) != rebuilt
    ):
        _fail("OCR page evidence bindings differ from the expected run/source")
    return rows


def _read_plain_file(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            _fail(f"{label} is missing or is not a plain file")
        return path.read_bytes()
    except OcrPageEvidenceBindingsError:
        raise
    except OSError as exc:
        raise OcrPageEvidenceBindingsError(f"{label} cannot be read") from exc


def build_ocr_page_evidence_bindings_from_store(
    store: object,
    run_id: str,
) -> bytes:
    """Verify private page evidence and return its safe public projection.

    ``store`` is intentionally duck-typed to avoid making the manifest module
    import the runtime eagerly.  A real :class:`OcrRunStore` is still required:
    all of its source, record, source-evidence and response verifiers are
    invoked before a digest is emitted.
    """

    from .ocr_page_evidence import PageEvidenceStore
    from .ocr_runtime import OcrPageStatus, OcrRunStore

    if not isinstance(store, OcrRunStore):
        raise TypeError("store must be an OcrRunStore")
    snapshot = store.load_snapshot(run_id)
    store.verify_source(run_id)
    records = store.list_records(run_id)
    page_store = PageEvidenceStore(
        store.root,
        snapshot.run_id,
        snapshot.source_sha256,
    )
    rows: list[OcrPageEvidenceBinding] = []
    for selected_index, record in enumerate(records, start=1):
        if record.status not in {
            OcrPageStatus.SUCCESS,
            OcrPageStatus.NEEDS_REVIEW,
        }:
            _fail(f"page has no terminal OCR evidence: {record.page_id}")
        if (
            record.task_index != selected_index
            or record.source_page != snapshot.selected_pages[selected_index - 1]
        ):
            _fail("runtime page record order differs from the snapshot")

        # These calls verify the record-to-file hash, envelope schema, raw and
        # cleaned layers, source evidence and page identity before projection.
        store.load_page_source_evidence(snapshot.run_id, record)
        store.verify_saved_response(snapshot.run_id, record)
        envelope = store.load_raw_response(snapshot.run_id, record)
        if not isinstance(envelope, Mapping):
            _fail("terminal OCR response envelope must be an object")

        record_path = (
            store.run_dir(snapshot.run_id) / "pages" / f"{record.page_id}.json"
        )
        record_bytes = _read_plain_file(record_path, "runtime page record")
        canonical_record = _canonical_runtime_json_bytes(record.to_dict())
        if record_bytes != canonical_record:
            _fail("runtime page record is not in canonical encoding")

        terminal_artifacts = page_store.verify_terminal_page_artifacts(
            record.page_id,
            raw_response=envelope,
            page_tex=record.cleaned_tex,
        )
        artifact_hashes = dict(terminal_artifacts["artifact_hashes"])
        page_dir = page_store.page_dir(record.page_id)
        retry_id = terminal_artifacts["retry_id"]
        terminal_dir = (
            page_dir
            if retry_id is None
            else page_dir / "retries" / str(retry_id)
        )
        source_bytes = _read_plain_file(
            page_dir / "source.json", "page source evidence"
        )
        candidate_bytes = _read_plain_file(
            page_dir / "candidate.json", "page candidate evidence"
        )
        verification_bytes = _read_plain_file(
            terminal_dir / "verification.json", "page verification evidence"
        )
        raw_response_bytes = _read_plain_file(
            terminal_dir / "raw-response.json", "page raw-response evidence"
        )
        page_tex_bytes = _read_plain_file(
            terminal_dir / "page.tex", "page TeX evidence"
        )
        source_value = _load_json_object(source_bytes, "page source evidence")
        candidate_value = _load_json_object(
            candidate_bytes, "page candidate evidence"
        )
        verification_value = _load_json_object(
            verification_bytes, "page verification evidence"
        )
        raw_response_value = _load_json_object(
            raw_response_bytes, "page raw-response evidence"
        )
        for value, raw, label in (
            (source_value, source_bytes, "page source evidence"),
            (candidate_value, candidate_bytes, "page candidate evidence"),
            (verification_value, verification_bytes, "page verification evidence"),
            (raw_response_value, raw_response_bytes, "page raw-response evidence"),
        ):
            if canonical_page_evidence_bindings_json_bytes(value) != raw:
                _fail(f"{label} is not in canonical encoding")

        candidate_payload = candidate_value.get("candidate")
        verification_payload = verification_value.get("verification")
        if not isinstance(candidate_payload, Mapping) or not isinstance(
            verification_payload, Mapping
        ):
            _fail("page candidate/verification payload is malformed")
        candidate_tex = candidate_payload.get("candidate_tex")
        if not isinstance(candidate_tex, str):
            _fail("page candidate lacks its initial candidate_tex")
        if any(
            actual != expected
            for actual, expected in (
                (source_value.get("run_id"), snapshot.run_id),
                (source_value.get("source_sha256"), snapshot.source_sha256),
                (source_value.get("page_id"), record.page_id),
                (source_value.get("selected_index"), record.task_index),
                (source_value.get("source_page_number"), record.source_page),
                (candidate_payload.get("page_id"), record.page_id),
                (candidate_payload.get("selected_index"), record.task_index),
                (candidate_payload.get("source_page_number"), record.source_page),
            )
        ):
            _fail("page evidence identity differs from the runtime record")
        if raw_response_value != dict(envelope):
            _fail("page raw-response evidence differs from the runtime envelope")
        cleaned_bytes = record.cleaned_tex.encode("utf-8")
        cleaned_sha = _sha256(cleaned_bytes)
        if (
            page_tex_bytes != cleaned_bytes
            or not hmac.compare_digest(record.tex_sha256, cleaned_sha)
            or not hmac.compare_digest(
                artifact_hashes["page.tex"], cleaned_sha
            )
        ):
            _fail("terminal cleaned TeX differs from page.tex/record bindings")

        schema = str(envelope.get("schema_version") or "")
        visual_hash: str | None
        if schema == "latexstruct-ocr-visual-response-v1":
            mode = OcrPageTerminalMode.VISUAL
            if verification_payload.get("visual_mode") != "VERIFIER":
                _fail("visual response is not bound to VERIFIER page evidence")
            if verification_payload.get("visual_verification") != envelope.get(
                "verification_page"
            ):
                _fail("visual page verdict differs between evidence stores")
            candidate_hash = _sha256(candidate_tex.encode("utf-8"))
            if (
                envelope.get("candidate_tex_sha256") != candidate_hash
                or envelope.get("candidate_tex") != candidate_tex
            ):
                _fail("visual envelope initial candidate binding is stale")
            visual_hash = _digest(
                envelope.get("verification_response_sha256"),
                "visual verification response hash",
            )
        elif schema == "latexstruct-ocr-host-response-v1":
            raw_mode = str(verification_payload.get("visual_mode") or "")
            if raw_mode not in {"FULL_OCR", "FULL_OCR_WITH_CROPS"}:
                _fail("full OCR envelope lacks full-page verification semantics")
            mode = OcrPageTerminalMode(raw_mode)
            # A page may have passed through the visual lane before escalation,
            # but the terminal full-OCR envelope is not that verifier response.
            visual_hash = None
        else:
            _fail("exact page evidence requires a visual/full-OCR host envelope")

        rows.append(OcrPageEvidenceBinding(
            page_id=record.page_id,
            source_page=record.source_page,
            selected_index=record.task_index,
            terminal_mode=mode,
            terminal_status=record.status.value,
            initial_candidate_tex_sha256=_sha256(candidate_tex.encode("utf-8")),
            visual_verification_response_sha256=visual_hash,
            terminal_cleaned_tex_sha256=cleaned_sha,
            runtime_record_sha256=_sha256(record_bytes),
            runtime_source_evidence_sha256=record.source_evidence_sha256,
            runtime_raw_response_sha256=record.raw_response_sha256,
            page_evidence_source_sha256=artifact_hashes["source.json"],
            page_evidence_candidate_sha256=artifact_hashes["candidate.json"],
            page_evidence_verification_sha256=artifact_hashes[
                "verification.json"
            ],
            page_evidence_raw_response_sha256=artifact_hashes[
                "raw-response.json"
            ],
            page_evidence_tex_sha256=artifact_hashes["page.tex"],
        ))
    return build_ocr_page_evidence_bindings(
        run_id=snapshot.run_id,
        source_sha256=snapshot.source_sha256,
        selected_pages=snapshot.selected_pages,
        pages=rows,
    )


__all__ = [
    "OCR_PAGE_EVIDENCE_BINDINGS_SCHEMA",
    "OcrPageEvidenceBinding",
    "OcrPageEvidenceBindingsError",
    "OcrPageTerminalMode",
    "build_ocr_page_evidence_bindings",
    "build_ocr_page_evidence_bindings_from_store",
    "canonical_page_evidence_bindings_json_bytes",
    "parse_ocr_page_evidence_bindings",
]
