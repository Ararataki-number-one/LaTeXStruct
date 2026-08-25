"""Frozen, fail-closed native OCR input for production analysis.

The analysis pipeline must consume the exact OCR-only package copied to a
project's ``evidence/ocr-baseline`` directory.  It must not reconstruct its
authority from editable TeX comments or from a legacy pipeline result.  This
module freezes every package file once, delegates the cryptographic and
semantic manifest checks to :mod:`latexstruct.core.ocr_manifest`, and exposes a
small typed input whose page map, snapshot, compile closure, and page evidence
all come from those verified bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping, Sequence

from .compilecheck import build_compile_input_manifest
from .ocr_artifacts import (
    VerifiedOcrBaselineArtifact,
    VerifiedOcrBaselineBundle,
    load_verified_ocr_baseline_directory,
)
from .ocr_evidence_correction import verify_evidence_correction_report_bytes
from .ocr_block_inventory import OcrBlockInventory, parse_ocr_block_inventory
from .ocr_manifest import (
    ROLE_BASELINE_PDF,
    ROLE_BASELINE_TEX,
    ROLE_BLOCK_INVENTORY,
    ROLE_EVIDENCE_BASELINE_TEX,
    ROLE_EVIDENCE_CORRECTION_REPORT,
    ROLE_LANE_ROUTES,
    ROLE_PAGE_MAP,
    ROLE_PAGE_RECORDS,
    ROLE_RAW_OCR_TEX,
    ROLE_RUN_SNAPSHOT,
    ROLE_RUNTIME_PAGE_RECORDS,
    ROLE_SYNTAX_BASELINE_TEX,
)
from .ocr_page_evidence import PageCoverageRecord, parse_page_records
from .ocr_page_map import (
    OcrPageMapError,
    OcrPdfPageMap,
    extract_page_anchors,
    verify_page_map_json,
)
from .ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    OcrRunSnapshot,
    OcrStoreError,
    _path_is_reparse_point,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_PRODUCER_KEYS = frozenset({"app_version", "git_commit", "build_id"})


class OcrAnalysisInputError(ValueError):
    """Native OCR evidence cannot safely authorize a production analysis."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OcrAnalysisInputError(f"duplicate JSON key in native OCR evidence: {key}")
        result[key] = value
    return result


def _json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                OcrAnalysisInputError(f"{label} contains non-finite {token}")
            ),
        )
    except OcrAnalysisInputError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrAnalysisInputError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise OcrAnalysisInputError(f"{label} must be a JSON object")
    return value


def _validated_digest(value: object, label: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise OcrAnalysisInputError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _decode_tex(artifact: VerifiedOcrBaselineArtifact, label: str) -> str:
    try:
        text = artifact.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OcrAnalysisInputError(f"{label} is not valid UTF-8") from exc
    if not text.strip():
        raise OcrAnalysisInputError(f"{label} is empty")
    return text


@dataclass(frozen=True, slots=True)
class OcrAnalysisCompileInputFile:
    """One exact file materialized for a measured OCR compile invocation."""

    path: str
    byte_count: int
    sha256: str
    data: bytes
    artifact_role: str

    def __post_init__(self) -> None:
        path = str(self.path or "")
        pure = PurePosixPath(path)
        if (
            not path
            or "\\" in path
            or pure.is_absolute()
            or pure.as_posix() != path
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise ValueError("compile input path must be a normalized relative POSIX path")
        data = bytes(self.data)
        digest = _validated_digest(self.sha256, "compile input sha256")
        if (
            not isinstance(self.byte_count, int)
            or isinstance(self.byte_count, bool)
            or self.byte_count != len(data)
            or not hmac.compare_digest(digest, _sha256(data))
        ):
            raise ValueError("compile input bytes differ from their measured inventory")
        role = str(self.artifact_role or "")
        if not role:
            raise ValueError("compile input artifact role is required")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "data", data)
        object.__setattr__(self, "artifact_role", role)


@dataclass(frozen=True, slots=True)
class OcrAnalysisCompilePass:
    """One hash-bound, measured compile invocation from the OCR package."""

    index: int
    exit_code: int
    input_tex_sha256: str
    output_pdf_sha256: str | None
    log_role: str
    log_path: str
    log_bytes: bytes
    command: tuple[str, ...]
    command_history: tuple[tuple[str, ...], ...]
    compile_workdir: str
    compile_input_sha256: str
    input_files: tuple[OcrAnalysisCompileInputFile, ...]

    @property
    def log_sha256(self) -> str:
        return _sha256(self.log_bytes)

    @property
    def log_text(self) -> str:
        return self.log_bytes.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class OcrAnalysisInput:
    """Immutable native authority used to seed analysis v2."""

    package_root: Path
    manifest_path: Path
    manifest_sha256: str
    run_id: str
    snapshot: OcrRunSnapshot
    block_inventory: OcrBlockInventory
    native_source_blocks: tuple[Mapping[str, object], ...]
    source_pdf: bytes
    raw_ocr_tex: str
    syntax_baseline_tex: str
    evidence_corrected_baseline_tex: str | None
    selected_baseline_role: str
    evidence_correction_report: Mapping[str, object] | None
    baseline_tex: str
    baseline_pdf: bytes
    page_map: OcrPdfPageMap
    source_page_map: Mapping[int, tuple[int, ...]]
    page_records: tuple[PageCoverageRecord, ...]
    runtime_page_records: tuple[OcrPageRecord, ...]
    coverage: Mapping[str, object]
    producer: Mapping[str, object]
    performance: Mapping[str, object]
    cost: Mapping[str, object]
    compile_engine: str
    compile_successful_passes: int
    compile_passes: tuple[OcrAnalysisCompilePass, ...]
    compile_input_manifest: Mapping[str, object]
    compile_extra_files: Mapping[str, bytes]
    artifacts_by_role: Mapping[str, VerifiedOcrBaselineArtifact]
    artifact_sha256s: Mapping[str, str]

    @property
    def source_sha256(self) -> str:
        return _sha256(self.source_pdf)

    @property
    def raw_ocr_sha256(self) -> str:
        return _sha256(self.raw_ocr_tex.encode("utf-8"))

    @property
    def baseline_tex_sha256(self) -> str:
        return _sha256(self.baseline_tex.encode("utf-8"))

    @property
    def syntax_baseline_sha256(self) -> str:
        return _sha256(self.syntax_baseline_tex.encode("utf-8"))

    @property
    def evidence_corrected_baseline_sha256(self) -> str | None:
        if self.evidence_corrected_baseline_tex is None:
            return None
        return _sha256(self.evidence_corrected_baseline_tex.encode("utf-8"))

    @property
    def evidence_correction_report_sha256(self) -> str | None:
        return self.artifact_sha256s.get(ROLE_EVIDENCE_CORRECTION_REPORT)

    @property
    def evidence_correction_status(self) -> str | None:
        if self.evidence_correction_report is None:
            return None
        return str(self.evidence_correction_report.get("status") or "") or None

    @property
    def baseline_pdf_sha256(self) -> str:
        return _sha256(self.baseline_pdf)

    @property
    def page_map_sha256(self) -> str:
        return self.artifact_sha256s[ROLE_PAGE_MAP]

    @property
    def page_records_sha256(self) -> str:
        return self.artifact_sha256s[ROLE_PAGE_RECORDS]

    @property
    def runtime_page_records_sha256(self) -> str:
        return self.artifact_sha256s[ROLE_RUNTIME_PAGE_RECORDS]

    @property
    def lane_routes_sha256(self) -> str | None:
        return self.artifact_sha256s.get(ROLE_LANE_ROUTES)

    @property
    def block_inventory_sha256(self) -> str:
        return self.artifact_sha256s[ROLE_BLOCK_INVENTORY]

    @property
    def block_inventory_by_page(self):
        """Frozen page-id mapping for host-owned source structure evidence."""
        return self.block_inventory.pages_by_id

    @property
    def compile_input_sha256(self) -> str:
        return str(self.compile_input_manifest["manifest_sha256"])

    @property
    def compile_log_sha256s(self) -> tuple[str, ...]:
        return tuple(item.log_sha256 for item in self.compile_passes)

    def evidence_summary(self) -> dict[str, object]:
        """Return a JSON-safe summary without copying large artifact bytes."""
        return {
            "schema": "latexstruct-native-ocr-analysis-input-v1",
            "run_id": self.run_id,
            "source_sha256": self.source_sha256,
            "selected_pages": list(self.snapshot.selected_pages),
            "manifest_sha256": self.manifest_sha256,
            "raw_ocr_sha256": self.raw_ocr_sha256,
            "syntax_baseline_sha256": self.syntax_baseline_sha256,
            "evidence_corrected_baseline_sha256": (
                self.evidence_corrected_baseline_sha256
            ),
            "selected_baseline_role": self.selected_baseline_role,
            "evidence_correction_status": self.evidence_correction_status,
            "evidence_correction_report_sha256": (
                self.evidence_correction_report_sha256
            ),
            "evidence_correction_report": (
                _thaw_json(self.evidence_correction_report)
                if self.evidence_correction_report is not None
                else None
            ),
            "baseline_tex_sha256": self.baseline_tex_sha256,
            "baseline_pdf_sha256": self.baseline_pdf_sha256,
            "page_map_sha256": self.page_map_sha256,
            "page_records_sha256": self.page_records_sha256,
            "runtime_page_records_sha256": self.runtime_page_records_sha256,
            "lane_routes_sha256": self.lane_routes_sha256,
            "block_inventory_sha256": self.block_inventory_sha256,
            "block_inventory_page_count": len(self.block_inventory.pages),
            "native_source_block_count": len(self.native_source_blocks),
            "compile_input_sha256": self.compile_input_sha256,
            "compile_log_sha256s": list(self.compile_log_sha256s),
            "compile_successful_passes": self.compile_successful_passes,
            "producer": _thaw_json(self.producer),
        }


def _compile_passes(
    bundle: VerifiedOcrBaselineBundle,
    payload: Mapping[str, object],
    *,
    baseline_tex: str,
    baseline_pdf: bytes,
) -> tuple[tuple[OcrAnalysisCompilePass, ...], Mapping[str, bytes], Mapping[str, object]]:
    compile_value = payload.get("compile")
    if not isinstance(compile_value, Mapping):
        raise OcrAnalysisInputError("native OCR compile evidence is missing")
    raw_passes = compile_value.get("passes")
    if not isinstance(raw_passes, list) or len(raw_passes) < 2:
        raise OcrAnalysisInputError("native OCR baseline lacks two compile invocations")
    successful_passes = compile_value.get("successful_passes")
    if (
        not isinstance(successful_passes, int)
        or isinstance(successful_passes, bool)
        or successful_passes < 2
    ):
        raise OcrAnalysisInputError("native OCR baseline lacks two successful compile passes")

    parsed: list[OcrAnalysisCompilePass] = []
    for expected_index, raw_pass in enumerate(raw_passes, start=1):
        if not isinstance(raw_pass, Mapping):
            raise OcrAnalysisInputError("native OCR compile pass is not an object")
        index = raw_pass.get("index")
        if index != expected_index:
            raise OcrAnalysisInputError("native OCR compile pass order is invalid")
        inventory = raw_pass.get("input_inventory")
        input_roles = raw_pass.get("input_artifact_roles")
        if (
            not isinstance(inventory, list)
            or not inventory
            or not isinstance(input_roles, list)
            or len(input_roles) != len(inventory)
        ):
            raise OcrAnalysisInputError(
                "native OCR compile evidence is not a complete measured input closure"
            )
        files: list[OcrAnalysisCompileInputFile] = []
        for raw_inventory, raw_role in zip(inventory, input_roles, strict=True):
            if not isinstance(raw_inventory, Mapping) or not isinstance(raw_role, str):
                raise OcrAnalysisInputError("native OCR compile input binding is invalid")
            artifact = bundle.require_role(raw_role)
            files.append(OcrAnalysisCompileInputFile(
                path=str(raw_inventory.get("path") or ""),
                byte_count=raw_inventory.get("bytes"),
                sha256=str(raw_inventory.get("sha256") or ""),
                data=artifact.data,
                artifact_role=raw_role,
            ))
        command = raw_pass.get("command")
        history = raw_pass.get("command_history")
        workdir = str(raw_pass.get("compile_workdir") or "")
        compile_input_sha = _validated_digest(
            raw_pass.get("compile_input_sha256"),
            f"compile pass {expected_index} input digest",
        )
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) and item for item in command)
            or not isinstance(history, list)
            or not history
            or any(
                not isinstance(item, list)
                or not item
                or not all(isinstance(token, str) and token for token in item)
                for item in history
            )
            or not workdir
        ):
            raise OcrAnalysisInputError(
                "native OCR compile execution evidence is incomplete"
            )
        log_role = str(raw_pass.get("log_role") or "")
        log_artifact = bundle.require_role(log_role)
        parsed.append(OcrAnalysisCompilePass(
            index=expected_index,
            exit_code=int(raw_pass.get("exit_code")),
            input_tex_sha256=_validated_digest(
                raw_pass.get("input_tex_sha256"),
                f"compile pass {expected_index} TEX digest",
            ),
            output_pdf_sha256=(
                _validated_digest(
                    raw_pass.get("output_pdf_sha256"),
                    f"compile pass {expected_index} PDF digest",
                )
                if raw_pass.get("output_pdf_sha256") is not None
                else None
            ),
            log_role=log_role,
            log_path=log_artifact.logical_path,
            log_bytes=log_artifact.data,
            command=tuple(command),
            command_history=tuple(tuple(item) for item in history),
            compile_workdir=workdir,
            compile_input_sha256=compile_input_sha,
            input_files=tuple(files),
        ))

    final_two = tuple(parsed[-2:])
    baseline_tex_sha = _sha256(baseline_tex.encode("utf-8"))
    baseline_pdf_sha = _sha256(baseline_pdf)
    if any(
        item.exit_code != 0 or item.input_tex_sha256 != baseline_tex_sha
        for item in final_two
    ):
        raise OcrAnalysisInputError(
            "native OCR final compile passes do not bind the exact baseline TEX"
        )
    if final_two[-1].output_pdf_sha256 != baseline_pdf_sha:
        raise OcrAnalysisInputError(
            "native OCR final compile pass does not bind the baseline PDF"
        )
    if final_two[0].compile_input_sha256 != final_two[1].compile_input_sha256:
        raise OcrAnalysisInputError(
            "native OCR final compile passes used different input closures"
        )

    final_inputs = {item.path: item.data for item in final_two[-1].input_files}
    if final_inputs.get("main.tex") != baseline_tex.encode("utf-8"):
        raise OcrAnalysisInputError(
            "native OCR final compile closure does not contain the exact baseline TEX"
        )
    extras = {path: data for path, data in final_inputs.items() if path != "main.tex"}
    recomputed_manifest = build_compile_input_manifest(baseline_tex, extras)
    if recomputed_manifest.get("manifest_sha256") != final_two[-1].compile_input_sha256:
        raise OcrAnalysisInputError(
            "native OCR final compile input closure is not recomputable"
        )
    return (
        tuple(parsed),
        MappingProxyType(dict(sorted(extras.items()))),
        _freeze_json(recomputed_manifest),
    )


def _build_analysis_input(
    bundle: VerifiedOcrBaselineBundle,
    *,
    expected_manifest_sha256: str | None,
    expected_run_id: str | None,
    expected_selected_pages: Sequence[int] | None,
    expected_producer: Mapping[str, object] | None,
) -> OcrAnalysisInput:
    payload = bundle.manifest.to_dict()
    if expected_manifest_sha256 is not None:
        expected_manifest = _validated_digest(
            expected_manifest_sha256,
            "expected native OCR manifest digest",
        )
        if not hmac.compare_digest(expected_manifest, bundle.manifest.sha256):
            raise OcrAnalysisInputError("native OCR manifest differs from project lineage")
    status = payload.get("status")
    if status != {
        "run_status": "SUCCESS",
        "ocr_status": "COMPLETED",
        "compile_status": "COMPILED",
    }:
        raise OcrAnalysisInputError(
            "native OCR analysis requires a SUCCESS/COMPLETED/COMPILED baseline"
        )

    snapshot_artifact = bundle.require_role(ROLE_RUN_SNAPSHOT)
    snapshot_value = _json_object(snapshot_artifact.data, "native OCR run snapshot")
    try:
        snapshot = OcrRunSnapshot.from_dict(snapshot_value)
    except (TypeError, ValueError) as exc:
        raise OcrAnalysisInputError("native OCR run snapshot is invalid") from exc
    run_id = str(payload.get("run_id") or "")
    if snapshot.run_id != run_id:
        raise OcrAnalysisInputError("native OCR snapshot belongs to a different run")
    if expected_run_id is not None and run_id != str(expected_run_id):
        raise OcrAnalysisInputError("native OCR run_id differs from project lineage")
    if (
        expected_selected_pages is not None
        and tuple(expected_selected_pages) != snapshot.selected_pages
    ):
        raise OcrAnalysisInputError("native OCR selected pages differ from analysis input")

    block_inventory_artifact = bundle.artifacts_by_role.get(ROLE_BLOCK_INVENTORY)
    if block_inventory_artifact is None:
        raise OcrAnalysisInputError(
            "native OCR analysis requires the host-owned source block inventory"
        )
    contract = snapshot.pipeline_contract
    snapshot_pages = (
        contract.get("page_strategies")
        if isinstance(contract, Mapping)
        else None
    )
    try:
        block_inventory = parse_ocr_block_inventory(
            block_inventory_artifact.data,
            expected_run_id=run_id,
            expected_source_sha256=snapshot.source_sha256,
            expected_selected_pages=snapshot.selected_pages,
            expected_snapshot_pages=snapshot_pages or None,
        )
    except (TypeError, ValueError) as exc:
        raise OcrAnalysisInputError(
            "native OCR source block inventory is invalid or stale"
        ) from exc
    native_source_blocks = block_inventory.native_source_block_projection()

    producer = payload.get("producer")
    if not isinstance(producer, Mapping):
        raise OcrAnalysisInputError("native OCR producer identity is missing")
    if expected_producer is not None:
        unsupported = set(expected_producer) - _EXPECTED_PRODUCER_KEYS
        if unsupported:
            raise OcrAnalysisInputError(
                f"unsupported expected producer identity field: {sorted(unsupported)[0]}"
            )
        if any(producer.get(key) != value for key, value in expected_producer.items()):
            raise OcrAnalysisInputError(
                "native OCR producer differs from the expected executable identity"
            )

    source_artifact = bundle.require_role("SOURCE")
    source_pdf = bytes(source_artifact.data)
    if snapshot.source_type != "pdf" or not source_pdf.startswith(b"%PDF-"):
        raise OcrAnalysisInputError("native OCR analysis input is not a source PDF")
    raw_ocr_tex = _decode_tex(bundle.require_role(ROLE_RAW_OCR_TEX), "raw OCR TEX")
    syntax_baseline_tex = _decode_tex(
        bundle.require_role(ROLE_SYNTAX_BASELINE_TEX),
        "syntax baseline TEX",
    )
    evidence_artifact = bundle.artifacts_by_role.get(ROLE_EVIDENCE_BASELINE_TEX)
    evidence_corrected_baseline_tex = (
        _decode_tex(evidence_artifact, "evidence-corrected baseline TEX")
        if evidence_artifact is not None
        else None
    )
    baseline_tex = _decode_tex(bundle.require_role(ROLE_BASELINE_TEX), "baseline TEX")
    compile_value = payload.get("compile")
    if not isinstance(compile_value, Mapping):
        raise OcrAnalysisInputError("native OCR compile evidence is missing")
    selected_baseline_role = str(compile_value.get("selected_baseline") or "")
    if selected_baseline_role == ROLE_SYNTAX_BASELINE_TEX:
        selected_baseline_tex = syntax_baseline_tex
    elif selected_baseline_role == ROLE_EVIDENCE_BASELINE_TEX:
        if evidence_corrected_baseline_tex is None:
            raise OcrAnalysisInputError(
                "native OCR selected evidence baseline artifact is missing"
            )
        selected_baseline_tex = evidence_corrected_baseline_tex
    else:
        raise OcrAnalysisInputError("native OCR selected baseline role is invalid")
    if baseline_tex != selected_baseline_tex:
        raise OcrAnalysisInputError(
            "native OCR baseline TEX differs from its selected baseline role"
        )

    correction_artifact = bundle.artifacts_by_role.get(
        ROLE_EVIDENCE_CORRECTION_REPORT
    )
    correction_report: Mapping[str, object] | None = None
    if correction_artifact is not None:
        try:
            verified_correction = verify_evidence_correction_report_bytes(
                correction_artifact.data,
                raw_ocr_tex=raw_ocr_tex,
                syntax_baseline_tex=syntax_baseline_tex,
                evidence_tex=evidence_corrected_baseline_tex,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OcrAnalysisInputError(
                "native OCR evidence correction report is invalid or stale"
            ) from exc
        correction_status = str(verified_correction.get("status") or "")
        expected_selected_role = (
            ROLE_EVIDENCE_BASELINE_TEX
            if correction_status == "PASS"
            else ROLE_SYNTAX_BASELINE_TEX
            if correction_status == "NOT_APPLICABLE"
            else ""
        )
        if selected_baseline_role != expected_selected_role:
            raise OcrAnalysisInputError(
                "native OCR selected baseline contradicts its correction report"
            )
        frozen_correction = _freeze_json(verified_correction)
        assert isinstance(frozen_correction, Mapping)
        correction_report = frozen_correction
    elif evidence_corrected_baseline_tex is not None:
        raise OcrAnalysisInputError(
            "native OCR evidence baseline lacks a correction report"
        )
    baseline_pdf = bytes(bundle.require_role(ROLE_BASELINE_PDF).data)
    if not baseline_pdf.startswith(b"%PDF-"):
        raise OcrAnalysisInputError("native OCR baseline PDF is missing or corrupt")

    page_map_artifact = bundle.require_role(ROLE_PAGE_MAP)
    try:
        anchors = extract_page_anchors(
            raw_ocr_tex,
            expected_selected_pages=snapshot.selected_pages,
        )
        page_map = verify_page_map_json(
            page_map_artifact.data,
            baseline_pdf,
            anchors,
        )
    except (OcrPageMapError, TypeError, ValueError) as exc:
        raise OcrAnalysisInputError("native OCR page map is not recomputable") from exc
    source_page_map = MappingProxyType({
        entry.source_page: tuple(entry.baseline_pdf_pages) for entry in page_map.entries
    })
    if tuple(source_page_map) != snapshot.selected_pages:
        raise OcrAnalysisInputError("native OCR page map does not cover selected pages")

    page_records_artifact = bundle.require_role(ROLE_PAGE_RECORDS)
    try:
        records_run_id, records_source_sha, page_records = parse_page_records(
            page_records_artifact.data
        )
    except (TypeError, ValueError) as exc:
        raise OcrAnalysisInputError("native OCR page coverage records are invalid") from exc
    if (
        records_run_id != run_id
        or records_source_sha != snapshot.source_sha256
        or tuple(item.source_page_number for item in page_records)
        != snapshot.selected_pages
    ):
        raise OcrAnalysisInputError(
            "native OCR page coverage records differ from the run snapshot"
        )

    runtime_artifact = bundle.require_role(ROLE_RUNTIME_PAGE_RECORDS)
    runtime_wrapper = _json_object(runtime_artifact.data, "native OCR runtime page records")
    raw_runtime_pages = runtime_wrapper.get("pages")
    if (
        runtime_wrapper.get("run_id") != run_id
        or not isinstance(raw_runtime_pages, list)
    ):
        raise OcrAnalysisInputError("native OCR runtime page record wrapper is invalid")
    try:
        runtime_page_records = tuple(
            OcrPageRecord.from_dict(item) for item in raw_runtime_pages
        )
    except (TypeError, ValueError) as exc:
        raise OcrAnalysisInputError("native OCR runtime page records are invalid") from exc
    if len(page_records) != len(runtime_page_records):
        raise OcrAnalysisInputError("native OCR page evidence counts differ")
    for selected_index, (coverage_record, runtime_record) in enumerate(
        zip(page_records, runtime_page_records, strict=True),
        start=1,
    ):
        expected_page_id, expected_source_page = snapshot.page_identity(selected_index)
        if (
            coverage_record.page_id != expected_page_id
            or coverage_record.source_page_number != expected_source_page
            or runtime_record.page_id != expected_page_id
            or runtime_record.task_index != selected_index
            or runtime_record.source_page != expected_source_page
            or runtime_record.status is not OcrPageStatus.SUCCESS
            or not coverage_record.completed
            or coverage_record.unresolved_region_hashes
        ):
            raise OcrAnalysisInputError(
                f"native OCR page {expected_source_page} is incomplete or stale"
            )

    compile_passes, compile_extras, compile_input_manifest = _compile_passes(
        bundle,
        payload,
        baseline_tex=baseline_tex,
        baseline_pdf=baseline_pdf,
    )
    artifacts_by_role = MappingProxyType(dict(bundle.artifacts_by_role))
    artifact_sha256s = MappingProxyType({
        role: artifact.sha256 for role, artifact in artifacts_by_role.items()
    })
    coverage = payload.get("coverage")
    performance = payload.get("performance")
    cost = payload.get("cost")
    if not all(isinstance(item, Mapping) for item in (coverage, performance, cost)):
        raise OcrAnalysisInputError("native OCR summary evidence is missing")
    return OcrAnalysisInput(
        package_root=bundle.root,
        manifest_path=bundle.manifest_path,
        manifest_sha256=bundle.manifest.sha256,
        run_id=run_id,
        snapshot=snapshot,
        block_inventory=block_inventory,
        native_source_blocks=native_source_blocks,
        source_pdf=source_pdf,
        raw_ocr_tex=raw_ocr_tex,
        syntax_baseline_tex=syntax_baseline_tex,
        evidence_corrected_baseline_tex=evidence_corrected_baseline_tex,
        selected_baseline_role=selected_baseline_role,
        evidence_correction_report=correction_report,
        baseline_tex=baseline_tex,
        baseline_pdf=baseline_pdf,
        page_map=page_map,
        source_page_map=source_page_map,
        page_records=tuple(page_records),
        runtime_page_records=runtime_page_records,
        coverage=_freeze_json(coverage),
        producer=_freeze_json(producer),
        performance=_freeze_json(performance),
        cost=_freeze_json(cost),
        compile_engine=str(compile_value.get("engine") or ""),
        compile_successful_passes=int(compile_value.get("successful_passes") or 0),
        compile_passes=compile_passes,
        compile_input_manifest=compile_input_manifest,
        compile_extra_files=compile_extras,
        artifacts_by_role=artifacts_by_role,
        artifact_sha256s=artifact_sha256s,
    )


def load_ocr_analysis_input_package(
    package_root: str | Path,
    *,
    expected_source_sha256: str,
    expected_manifest_sha256: str | None = None,
    expected_run_id: str | None = None,
    expected_selected_pages: Sequence[int] | None = None,
    expected_producer: Mapping[str, object] | None = None,
) -> OcrAnalysisInput:
    """Load one standalone package using an independent source hash anchor."""
    source_sha = _validated_digest(expected_source_sha256, "expected source digest")
    try:
        bundle = load_verified_ocr_baseline_directory(
            package_root,
            expected_source_sha256=source_sha,
        )
        return _build_analysis_input(
            bundle,
            expected_manifest_sha256=expected_manifest_sha256,
            expected_run_id=expected_run_id,
            expected_selected_pages=expected_selected_pages,
            expected_producer=expected_producer,
        )
    except OcrAnalysisInputError:
        raise
    except (OcrStoreError, KeyError, TypeError, ValueError) as exc:
        raise OcrAnalysisInputError("native OCR analysis package failed verification") from exc


def load_native_ocr_analysis_input(
    project_dir: str | Path,
    *,
    expected_source_sha256: str,
    expected_manifest_sha256: str | None = None,
    expected_run_id: str | None = None,
    expected_selected_pages: Sequence[int] | None = None,
    expected_producer: Mapping[str, object] | None = None,
) -> OcrAnalysisInput:
    """Load ``<project>/evidence/ocr-baseline`` without following links."""
    project = Path(project_dir)
    evidence_root = project / "evidence"
    package_root = evidence_root / "ocr-baseline"
    for path, label in (
        (project, "project root"),
        (evidence_root, "project evidence root"),
        (package_root, "native OCR evidence root"),
    ):
        if not path.is_dir() or _path_is_reparse_point(path):
            raise OcrAnalysisInputError(f"{label} is missing or not a plain directory")
    return load_ocr_analysis_input_package(
        package_root,
        expected_source_sha256=expected_source_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_run_id=expected_run_id,
        expected_selected_pages=expected_selected_pages,
        expected_producer=expected_producer,
    )


def build_native_ocr_pipeline_seed(
    analysis_input: OcrAnalysisInput,
    *,
    mode: str = "ai",
):
    """Build an explicitly unverified ``PipelineResult`` for analysis v2.

    The seed retains the native twice-compiled candidate and its exact compile
    closure, but deliberately grants no analysis verification or export
    authority.  A later host state machine must independently reach VERIFIED.
    """
    from .pipeline import PipelineResult

    baseline_tex = analysis_input.baseline_tex
    tex_sha = analysis_input.baseline_tex_sha256
    pdf_sha = analysis_input.baseline_pdf_sha256
    page_count = analysis_input.page_map.baseline_pdf_page_count
    input_manifest = _thaw_json(analysis_input.compile_input_manifest)
    final_two = analysis_input.compile_passes[-2:]
    compile_log = "\n".join(
        f"[native OCR compile pass {item.index}]\n{item.log_text}" for item in final_two
    )
    compile_record = {
        "engine": analysis_input.compile_engine,
        "available": True,
        "ok": True,
        "pages": page_count,
        "page_count": page_count,
        "errors": [],
        "fatal_error": "",
        "fatal_line": None,
        "log": compile_log,
        "log_paths": [item.log_path for item in final_two],
        "preview_status": "COMPILED",
        "process_status": "success",
        "pdf_sha256": pdf_sha,
        "return_code": 0,
        "exit_code": 0,
        "timed_out": False,
        "passes_requested": 2,
        "passes_attempted": 2,
        "passes_completed": 2,
        "compile_workdirs": [item.compile_workdir for item in final_two],
        "same_workdir_verified": False,
        "input_manifest": input_manifest,
        "compile_input_sha256": analysis_input.compile_input_sha256,
    }
    preview_record = {
        "status": "COMPILED",
        "kind": "compiled-pdf",
        "display_filename": "native-ocr-baseline.pdf",
        "filename": "native-ocr-baseline.pdf",
        "sha256": pdf_sha,
        "bytes": len(analysis_input.baseline_pdf),
        "engine": analysis_input.compile_engine,
        "passes_attempted": 2,
        "exit_code": 0,
        "page_count": page_count,
        "pdf_sha256": pdf_sha,
        "compile_input_sha256": analysis_input.compile_input_sha256,
        "fatal_line": None,
        "fatal_error": "",
        "log_paths": [item.log_path for item in final_two],
        "tex_sha256": tex_sha,
        "tex_lf_normalized_sha256": _sha256(
            baseline_tex.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        ),
        "compile_inputs": input_manifest,
    }
    verification = {
        "ok": False,
        "safe_to_export": False,
        "export_blocked": True,
        "run_status": "NOT_RUN",
        "verification_status": "NOT_RUN",
        "result_status": "NONE",
        "packaging_status": "NOT_RUN",
        "preview_state": "COMPILED",
        "preview_artifact": preview_record,
        "compile_after": compile_record,
        "ocr_native_input": analysis_input.evidence_summary(),
        "analysis_v2": {
            "schema": "latexstruct-production-analysis-v2",
            "required": True,
            "executed": False,
            "ok": None,
            "verified": False,
            "status": "NOT_RUN",
            "reason": "native OCR baseline loaded; analysis v2 has not run",
        },
    }
    if "\r\n" in baseline_tex:
        newline = "\r\n"
    elif "\r" in baseline_tex:
        newline = "\r"
    else:
        newline = "\n"
    return PipelineResult(
        ok=False,
        original=analysis_input.raw_ocr_tex,
        result=baseline_tex,
        export_text=baseline_tex,
        newline=newline,
        decisions=[],
        applied=[],
        rejected=[],
        ambiguous=[],
        verification=verification,
        report_md=(
            "# Native OCR analysis baseline\n\n"
            "The immutable OCR baseline is loaded and twice compiled. "
            "Analysis v2 has not run; this seed is **UNVERIFIED** and export-blocked.\n"
        ),
        mode=str(mode or "ai"),
        compiled_pdf=analysis_input.baseline_pdf,
        compiled_pdf_name="native-ocr-baseline.pdf",
        compiled_tex=baseline_tex,
        compiled_snapshot=baseline_tex,
        compiled_extra_files=dict(analysis_input.compile_extra_files),
        raw_compiled_tex=analysis_input.raw_ocr_tex,
    )


__all__ = [
    "OcrAnalysisCompileInputFile",
    "OcrAnalysisCompilePass",
    "OcrAnalysisInput",
    "OcrAnalysisInputError",
    "build_native_ocr_pipeline_seed",
    "load_native_ocr_analysis_input",
    "load_ocr_analysis_input_package",
]
