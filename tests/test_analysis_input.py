# -*- coding: utf-8 -*-
"""Native OCR package loading for the production analysis boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from latexstruct.core.analysis_input import (
    OcrAnalysisInputError,
    build_native_ocr_pipeline_seed,
    load_native_ocr_analysis_input,
)
from latexstruct.core.analysis_inventory import coerce_analysis_native_source_blocks
from latexstruct.core.ocr_block_inventory import build_ocr_block_inventory
from latexstruct.core.ocr_evidence_correction import produce_evidence_corrected_baseline
from latexstruct.core.ocr_manifest import (
    ArtifactInput,
    DEFAULT_MANIFEST_PATH,
    ROLE_BASELINE_PDF,
    ROLE_BASELINE_TEX,
    ROLE_BLOCK_INVENTORY,
    ROLE_EVIDENCE_BASELINE_TEX,
    ROLE_EVIDENCE_CORRECTION_REPORT,
    ROLE_PAGE_MAP,
    ROLE_PAGE_RECORDS,
    ROLE_RAW_OCR_TEX,
    ROLE_RUN_SNAPSHOT,
    ROLE_RUNTIME_PAGE_RECORDS,
    build_ocr_baseline_manifest,
    canonical_json_bytes,
)
from tests.test_ocr_manifest import (
    RUN_ID,
    _fixture,
    _evidence_correction_pass,
    _with_measured_compile_evidence,
)
from tests.test_ocr_block_inventory import source_classification


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prepared_project(
    tmp_path: Path,
    *,
    measured: bool = True,
    compile_status: str = "COMPILED",
    evidence_correction: str | None = None,
    block_inventory: bool = True,
) -> SimpleNamespace:
    values = _fixture(compile_status=compile_status)
    if evidence_correction == "NOT_APPLICABLE":
        result = produce_evidence_corrected_baseline(
            raw_ocr_tex=values["raw_ocr"].data.decode("utf-8"),
            syntax_baseline_tex=values["syntax_baseline"].data.decode("utf-8"),
        )
        values["evidence_correction_report"] = ArtifactInput(
            ROLE_EVIDENCE_CORRECTION_REPORT,
            "evidence/evidence-correction-report.json",
            result.report.canonical_json_bytes(),
        )
    elif evidence_correction == "PASS":
        _evidence_correction_pass(values)
    elif evidence_correction is not None:
        raise ValueError("unsupported evidence correction fixture status")
    if measured:
        values = _with_measured_compile_evidence(values)
    if block_inventory:
        classification = source_classification(
            source_sha256=_sha(values["source"].data),
            selected_pages=(1, 2),
        )
        values["block_inventory"] = ArtifactInput(
            ROLE_BLOCK_INVENTORY,
            "evidence/ocr-block-inventory.json",
            build_ocr_block_inventory(
                run_id=RUN_ID,
                source_classification=classification,
                selected_pages=(1, 2),
            ),
        )
    bundle = build_ocr_baseline_manifest(**values)
    project = tmp_path / "project"
    package = project / "evidence" / "ocr-baseline"
    for logical_path, data in bundle.files().items():
        target = package.joinpath(*logical_path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest = bundle.manifest.to_dict()
    descriptors = {item["role"]: item for item in manifest["artifacts"]}
    return SimpleNamespace(
        bundle=bundle,
        descriptors=descriptors,
        manifest=manifest,
        package=package,
        project=project,
        source_sha256=_sha(values["source"].data),
    )


def _load(prepared: SimpleNamespace, **overrides):
    arguments = {
        "expected_source_sha256": prepared.source_sha256,
        "expected_manifest_sha256": prepared.bundle.manifest.sha256,
        "expected_run_id": RUN_ID,
        "expected_selected_pages": (1, 2),
        "expected_producer": {
            "app_version": "2.0.0",
            "git_commit": "c" * 40,
            "build_id": "32690000000",
        },
    }
    arguments.update(overrides)
    return load_native_ocr_analysis_input(prepared.project, **arguments)


def _rewrite_bound_artifact(
    prepared: SimpleNamespace,
    role: str,
    data: bytes,
) -> None:
    payload = prepared.bundle.manifest.to_dict()
    descriptor = next(item for item in payload["artifacts"] if item["role"] == role)
    descriptor["bytes"] = len(data)
    descriptor["sha256"] = _sha(data)
    artifact_path = prepared.package.joinpath(*str(descriptor["path"]).split("/"))
    artifact_path.write_bytes(data)
    manifest_path = prepared.package.joinpath(*DEFAULT_MANIFEST_PATH.split("/"))
    manifest_path.write_bytes(canonical_json_bytes(payload))


def test_native_input_loads_exact_package_without_embedded_metadata(tmp_path: Path):
    prepared = _prepared_project(tmp_path)

    native = _load(prepared)

    assert native.run_id == RUN_ID
    assert native.snapshot.selected_pages == (1, 2)
    assert native.source_sha256 == prepared.source_sha256
    assert "LaTeXStruct-OCR-Metadata" not in native.raw_ocr_tex
    assert native.source_page_map == {1: (1,), 2: (2,)}
    assert tuple(record.source_page_number for record in native.page_records) == (1, 2)
    assert tuple(record.source_page for record in native.runtime_page_records) == (1, 2)
    assert native.compile_successful_passes == 2
    assert native.compile_input_sha256 == native.compile_passes[-1].compile_input_sha256
    assert native.compile_extra_files == {"figures/plot.pdf": b"exact figure bytes"}
    assert native.baseline_pdf.startswith(b"%PDF-")
    assert native.page_map.baseline_pdf_page_count == 2
    assert native.artifact_sha256s[ROLE_BASELINE_TEX] == native.baseline_tex_sha256
    assert native.block_inventory_sha256 == native.artifact_sha256s[
        ROLE_BLOCK_INVENTORY
    ]
    assert tuple(native.block_inventory_by_page) == (
        "ocr-page-000001", "ocr-page-000002"
    )
    typed_blocks = coerce_analysis_native_source_blocks(native.native_source_blocks)
    assert [item.plain_text for item in typed_blocks] == [
        "1. ordinary numbered list item", "1. Introduction", "Body text"
    ]
    assert typed_blocks[0].block_type == "LIST_ITEM"
    with pytest.raises(TypeError):
        native.source_page_map[1] = (2,)
    with pytest.raises(TypeError):
        native.compile_extra_files["extra"] = b"data"


@pytest.mark.parametrize(
    ("correction_status", "selected_role", "has_evidence_tex"),
    [
        ("NOT_APPLICABLE", "SYNTAX_BASELINE_TEX", False),
        ("PASS", ROLE_EVIDENCE_BASELINE_TEX, True),
    ],
)
def test_native_input_exposes_selected_baseline_and_bound_correction_report(
    tmp_path: Path,
    correction_status: str,
    selected_role: str,
    has_evidence_tex: bool,
):
    native = _load(_prepared_project(
        tmp_path,
        evidence_correction=correction_status,
    ))

    assert native.selected_baseline_role == selected_role
    assert native.evidence_correction_status == correction_status
    assert native.evidence_correction_report is not None
    assert native.evidence_correction_report["status"] == correction_status
    assert (native.evidence_corrected_baseline_tex is not None) is has_evidence_tex
    assert native.baseline_tex == (
        native.evidence_corrected_baseline_tex
        if has_evidence_tex
        else native.syntax_baseline_tex
    )
    summary = native.evidence_summary()
    assert summary["selected_baseline_role"] == selected_role
    assert summary["evidence_correction_status"] == correction_status
    assert summary["evidence_correction_report"]["status"] == correction_status
    assert summary["evidence_correction_report"]["report_sha256"] == (
        native.evidence_correction_report["report_sha256"]
    )
    assert summary["evidence_correction_report_sha256"] == (
        native.artifact_sha256s[ROLE_EVIDENCE_CORRECTION_REPORT]
    )


def test_native_input_builds_export_blocked_pipeline_seed(tmp_path: Path):
    native = _load(_prepared_project(tmp_path))

    seed = build_native_ocr_pipeline_seed(native)

    assert seed.ok is False
    assert seed.original == native.raw_ocr_tex
    assert seed.result == native.baseline_tex
    assert seed.compiled_snapshot == native.baseline_tex
    assert seed.compiled_pdf == native.baseline_pdf
    assert seed.compiled_extra_files == {"figures/plot.pdf": b"exact figure bytes"}
    assert seed.verification["safe_to_export"] is False
    assert seed.verification["export_blocked"] is True
    assert seed.verification["verification_status"] == "NOT_RUN"
    assert seed.verification["result_status"] == "NONE"
    assert seed.verification["analysis_v2"]["verified"] is False
    assert seed.verification["preview_artifact"]["tex_sha256"] == (
        native.baseline_tex_sha256
    )
    assert seed.verification["preview_artifact"]["pdf_sha256"] == (
        native.baseline_pdf_sha256
    )
    assert seed.verification["compile_after"]["compile_input_sha256"] == (
        native.compile_input_sha256
    )


@pytest.mark.parametrize(
    "role",
    [
        ROLE_RUN_SNAPSHOT,
        ROLE_RAW_OCR_TEX,
        ROLE_BASELINE_TEX,
        ROLE_BLOCK_INVENTORY,
        ROLE_BASELINE_PDF,
        ROLE_PAGE_MAP,
        ROLE_PAGE_RECORDS,
        ROLE_RUNTIME_PAGE_RECORDS,
        "COMPILE_LOG_PASS_02",
    ],
)
def test_native_input_rejects_hash_tampering_for_every_critical_role(
    tmp_path: Path,
    role: str,
):
    prepared = _prepared_project(tmp_path)
    descriptor = prepared.descriptors[role]
    target = prepared.package.joinpath(*str(descriptor["path"]).split("/"))
    target.write_bytes(target.read_bytes() + b"tampered")

    with pytest.raises(OcrAnalysisInputError):
        _load(prepared)


def test_native_input_rejects_missing_and_extra_package_files(tmp_path: Path):
    missing = _prepared_project(tmp_path / "missing")
    descriptor = missing.descriptors[ROLE_PAGE_RECORDS]
    missing.package.joinpath(*str(descriptor["path"]).split("/")).unlink()
    with pytest.raises(OcrAnalysisInputError):
        _load(missing)

    extra = _prepared_project(tmp_path / "extra")
    unexpected = extra.package / "unexpected.txt"
    unexpected.write_text("not in manifest", encoding="utf-8")
    with pytest.raises(OcrAnalysisInputError):
        _load(extra)


def test_native_input_rejects_semantic_page_map_tamper_with_rewritten_hash(
    tmp_path: Path,
):
    prepared = _prepared_project(tmp_path)
    page_map_path = prepared.package.joinpath(
        *str(prepared.descriptors[ROLE_PAGE_MAP]["path"]).split("/")
    )
    page_map = json.loads(page_map_path.read_text(encoding="utf-8"))
    page_map["pages"][0]["baseline_pdf_pages"] = [2]
    tampered = (
        json.dumps(page_map, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    _rewrite_bound_artifact(prepared, ROLE_PAGE_MAP, tampered)

    with pytest.raises(OcrAnalysisInputError):
        _load(prepared, expected_manifest_sha256=None)


def test_native_input_rejects_semantic_runtime_tamper_with_rewritten_hash(
    tmp_path: Path,
):
    prepared = _prepared_project(tmp_path)
    runtime_path = prepared.package.joinpath(
        *str(prepared.descriptors[ROLE_RUNTIME_PAGE_RECORDS]["path"]).split("/")
    )
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime["pages"][0]["status"] = "FAILED"
    tampered = canonical_json_bytes(runtime)
    _rewrite_bound_artifact(prepared, ROLE_RUNTIME_PAGE_RECORDS, tampered)

    with pytest.raises(OcrAnalysisInputError):
        _load(prepared, expected_manifest_sha256=None)


def test_native_input_requires_measured_twice_compiled_success(tmp_path: Path):
    unmeasured = _prepared_project(tmp_path / "unmeasured", measured=False)
    with pytest.raises(OcrAnalysisInputError, match="measured input closure"):
        _load(unmeasured)

    source_preview = _prepared_project(
        tmp_path / "preview",
        measured=False,
        compile_status="SOURCE_PREVIEW",
    )
    with pytest.raises(OcrAnalysisInputError, match="SUCCESS/COMPLETED/COMPILED"):
        _load(source_preview)


def test_native_input_rejects_legacy_manifest_without_block_inventory(tmp_path: Path):
    legacy = _prepared_project(tmp_path, block_inventory=False)

    with pytest.raises(OcrAnalysisInputError, match="block inventory"):
        _load(legacy)


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("expected_source_sha256", "0" * 64),
        ("expected_manifest_sha256", "1" * 64),
        ("expected_run_id", "b" * 32),
        ("expected_selected_pages", (1,)),
        ("expected_producer", {"build_id": "different-build"}),
    ],
)
def test_native_input_rejects_independent_authority_mismatch(
    tmp_path: Path,
    override: str,
    value: object,
):
    prepared = _prepared_project(tmp_path)
    with pytest.raises(OcrAnalysisInputError):
        _load(prepared, **{override: value})


def test_native_input_reads_each_package_file_once(tmp_path: Path, monkeypatch):
    prepared = _prepared_project(tmp_path)
    original_read_bytes = Path.read_bytes
    reads: dict[str, int] = {}

    def tracked_read_bytes(path: Path) -> bytes:
        try:
            logical_path = path.relative_to(prepared.package).as_posix()
        except ValueError:
            return original_read_bytes(path)
        reads[logical_path] = reads.get(logical_path, 0) + 1
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)

    _load(prepared)

    assert set(reads) == set(prepared.bundle.files())
    assert set(reads.values()) == {1}
