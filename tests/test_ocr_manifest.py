# -*- coding: utf-8 -*-
"""Recomputable OCR-only baseline manifest tests."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pymupdf
import pytest

from latexstruct.core.compilecheck import (
    COMPILE_INPUT_MANIFEST_SCHEMA,
    COMPILE_WORKDIR_ID_PREFIX,
    build_compile_input_manifest,
    prepare_compile_inputs,
)
from latexstruct.core.ocr_manifest import (
    ArtifactInput,
    CompilePassInput,
    OCR_PAGE_MAP_SCHEMA,
    OCR_PAGE_RECORDS_SCHEMA,
    OCR_PRODUCER_SCHEMA,
    OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
    OcrBaselineManifestError,
    build_ocr_baseline_manifest,
    canonical_json_bytes,
    verify_ocr_baseline_manifest,
)
from latexstruct.core.ocr_metrics import (
    OcrMetricsCollector,
    OcrStrategy,
    PageFinalStatus as MetricsPageFinalStatus,
    RequestKind,
)
from latexstruct.core.ocr_page_evidence import (
    COVERAGE_SUMMARY_SCHEMA_VERSION,
    FinalPageStatus,
    PageCoverageChecks,
    PageCoverageRecord,
    VisualMode,
    build_page_summaries,
)
from latexstruct.core.ocr_page_map import build_pdf_page_map, extract_page_anchors
from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    make_page_id,
    make_run_snapshot,
)


RUN_ID = "a" * 32
CREATED_AT = "2026-08-24T06:00:00.000Z"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inventory_sha256(files) -> str:
    body = {
        "schema": COMPILE_INPUT_MANIFEST_SCHEMA,
        "file_count": len(files),
        "files": files,
    }
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _sha(encoded)


def _compile_execution_metadata(
    tex_bytes: bytes,
    *,
    marker: int,
    extra_files: dict[str, bytes] | None = None,
):
    manifest = build_compile_input_manifest(
        tex_bytes.decode("utf-8"),
        extra_files,
    )
    command = (
        "xelatex.exe",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "main.tex",
    )
    return {
        "command": command,
        "command_history": (command,),
        "compile_workdir": COMPILE_WORKDIR_ID_PREFIX + f"{marker:064x}",
        "input_inventory": tuple(manifest["files"]),
        "compile_input_sha256": manifest["manifest_sha256"],
        "input_files": tuple(sorted(
            prepare_compile_inputs(tex_bytes.decode("utf-8"), extra_files).items()
        )),
    }


def _compiled_pdf_with_host_destinations(page_count: int = 2) -> bytes:
    document = pymupdf.open()
    try:
        for _ in range(page_count):
            document.new_page()
        destinations = []
        for index in range(1, page_count + 1):
            page_xref = document.page_xref(index - 1)
            destinations.append(
                f"/ocr-page-{index:06d} [{page_xref} 0 R /XYZ 0 800 0]"
            )
        document.xref_set_key(
            document.pdf_catalog(),
            "Dests",
            f"<< {' '.join(destinations)} >>",
        )
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _source_pdf_bytes(page_count: int = 2) -> bytes:
    document = pymupdf.open()
    try:
        for index in range(page_count):
            page = document.new_page()
            page.insert_text((72, 72), f"source page {index + 1}")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _record(index: int, status: OcrPageStatus = OcrPageStatus.SUCCESS) -> OcrPageRecord:
    latex = f"Page {index} with $x_{index}$."
    common = {
        "page_id": make_page_id(index),
        "source_page": index,
        "task_index": index,
        "status": status,
        "raw_response_sha256": "b" * 64 if status in {
            OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW,
        } else "",
        "raw_tex": latex if status in {
            OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW,
        } else "",
        "cleaned_tex": latex if status in {
            OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW,
        } else "",
        "retry_count": 1 if status == OcrPageStatus.NEEDS_REVIEW else 0,
        "error_reason": "page failed" if status == OcrPageStatus.FAILED else "",
    }
    return OcrPageRecord(**common)


def _coverage_record(
    index: int,
    runtime_record: OcrPageRecord,
    *,
    source_sha256: str,
    check_failure: str | None = None,
) -> PageCoverageRecord:
    check_values = {
        "source_hash_bound": True,
        "candidate_created": True,
        "visual_authority_checked": True,
        "reading_order_checked": True,
        "text_coverage_checked": True,
        "math_region_coverage_checked": True,
        "syntax_checked": True,
        "persisted": True,
    }
    if check_failure is not None:
        check_values[check_failure] = False
    page_tex_sha = runtime_record.tex_sha256 or _sha(f"failed page {index}".encode())
    return PageCoverageRecord(
        page_id=runtime_record.page_id,
        source_page_number=runtime_record.source_page,
        source_sha256=source_sha256,
        source_page_object_hash=_sha(f"source object {index}".encode()),
        checks=PageCoverageChecks.from_bools(**check_values),
        visual_mode=VisualMode.VERIFIER,
        final_status=FinalPageStatus(runtime_record.status.value),
        artifact_hashes={
            "source.json": _sha(f"source {index}".encode()),
            "candidate.json": _sha(f"candidate {index}".encode()),
            "verification.json": _sha(f"verification {index}".encode()),
            "raw-response.json": _sha(f"response {index}".encode()),
            "page.tex": page_tex_sha,
        },
    )


def _fixture(
    *,
    statuses=(OcrPageStatus.SUCCESS, OcrPageStatus.SUCCESS),
    compile_status="COMPILED",
    absolute_source_path: str | None = None,
    coverage_check_failure: str | None = None,
    unknown_metrics: bool = False,
    actual_source_pages: int = 2,
):
    source_bytes = _source_pdf_bytes(actual_source_pages)
    snapshot = make_run_snapshot(
        source_bytes=source_bytes,
        source_type="pdf",
        original_filename="37页 数学.pdf",
        source_total_pages=2,
        selected_pages=(1, 2),
        ocr_model="gpt-test",
        api_backend="codex_cli",
        app_version="2.0.0",
        quality_tier="high",
        run_id=RUN_ID,
        started_at="2026-08-24T05:00:00.000Z",
    )
    snapshot_bytes = canonical_json_bytes(snapshot.to_dict())
    records = [_record(index, status) for index, status in enumerate(statuses, start=1)]
    runtime_page_records_bytes = canonical_json_bytes({
        "schema_version": OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
        "run_id": RUN_ID,
        "pages": [record.to_dict() for record in records],
    })
    coverage_records = [
        _coverage_record(
            index,
            record,
            source_sha256=snapshot.source_sha256,
            check_failure=coverage_check_failure if index == 2 else None,
        )
        for index, record in enumerate(records, start=1)
    ]
    page_records_bytes = build_page_summaries(
        coverage_records,
        run_id=RUN_ID,
        source_sha256=snapshot.source_sha256,
        expected_source_pages=(1, 2),
    ).page_records_bytes
    raw_bytes = (
        "% Page 1\n"
        "% LaTeXStruct-Page: page_id=ocr-page-000001 source_page=1\n"
        "Page 1 with $x_1$.\n\n"
        "% Page 2\n"
        "% LaTeXStruct-Page: page_id=ocr-page-000002 source_page=2\n"
        "Page 2 with $x_2$.\n"
    ).encode()
    raw_freeze_bytes = canonical_json_bytes({
        "schema_version": "latexstruct-raw-ocr-freeze-v1",
        "run_id": RUN_ID,
        "created_at": CREATED_AT,
        "raw_ocr_sha256": _sha(raw_bytes),
        "selected_pages": [1, 2],
        "page_records": [
            {
                "page_id": record.page_id,
                "source_page": record.source_page,
                "status": record.status.value,
                "tex_sha256": record.tex_sha256 or None,
                "raw_response_sha256": record.raw_response_sha256 or None,
            }
            for record in records
        ],
        "ocr_model": "gpt-test",
        "api_backend": "codex_cli",
        "usage": {"calls": 2, "input_tokens": 100, "output_tokens": 40},
        "unresolved_regions": [],
        "error_pages": [
            record.source_page
            for record in records
            if record.status in {OcrPageStatus.FAILED, OcrPageStatus.CANCELLED}
        ],
        "merge_version": "1",
    })
    metrics = OcrMetricsCollector(
        RUN_ID,
        selected_pages=2,
        started_at_seconds=0.0,
        clock=lambda: 60.0,
    )
    for index, status in enumerate(statuses, start=1):
        if status in {
            OcrPageStatus.SUCCESS,
            OcrPageStatus.NEEDS_REVIEW,
            OcrPageStatus.FAILED,
        }:
            metrics.record_page_result(
                make_page_id(index),
                status=MetricsPageFinalStatus(status.value),
                strategy=OcrStrategy.OBJECT_LAYER_VERIFIED,
                completed_at_seconds=20.0 * index,
                dpi_history=(160,),
            )
    for index in (1, 2):
        request_values = {}
        if not unknown_metrics:
            request_values = {
                "status_code": 200,
                "input_tokens": 50,
                "output_tokens": 20,
                "cost": "0.125",
                "currency": "USD",
                "retry": False,
                "truncated": False,
                "strong_model": False,
            }
        metrics.record_request(
            f"call-{index}",
            kind=RequestKind.VISUAL_VERIFICATION,
            latency_ms=100.0 * index,
            dpi=160,
            **request_values,
        )
    if not unknown_metrics:
        metrics.record_resource_sample(memory_bytes=1024)
    metric_reports = metrics.canonical_reports(now_seconds=60.0)
    performance_bytes = metric_reports["performance_metrics"]
    cost_bytes = metric_reports["cost_report"]
    syntax_bytes = b"\\documentclass{article}\n\\begin{document}\nBaseline\\end{document}\n"
    producer = {
        "schema_version": OCR_PRODUCER_SCHEMA,
        "app_version": "2.0.0",
        "git_commit": "c" * 40,
        "build_id": "32690000000",
        "ocr_model": "gpt-test",
        "verification_model": "gpt-test",
        "prompt_version": "ocr-v3",
        "api_backend": "codex_cli",
    }
    baseline_pdf = None
    page_map = None
    compile_passes = [CompilePassInput("logs/pass-01.log", b"pass 1 failed\n", 1)]
    fatal_error = "deterministic compile failure"
    pdf_count = 0
    if compile_status == "COMPILED":
        baseline_pdf_bytes = _compiled_pdf_with_host_destinations()
        baseline_pdf = ArtifactInput(
            "BASELINE_PDF", "baseline/baseline.pdf", baseline_pdf_bytes,
        )
        page_map_bytes = build_pdf_page_map(
            baseline_pdf_bytes,
            extract_page_anchors(
                raw_bytes.decode("utf-8"), expected_selected_pages=(1, 2),
            ),
        ).to_json_bytes()
        page_map = ArtifactInput("PAGE_MAP", "baseline/page_map.json", page_map_bytes)
        compile_passes = [
            CompilePassInput("logs/pass-01.log", b"pass 1 exit 0\n", 0),
            CompilePassInput("logs/pass-02.log", b"pass 2 exit 0\n", 0),
        ]
        fatal_error = ""
        pdf_count = 2
    elif compile_status == "PARTIAL_COMPILED":
        baseline_pdf = ArtifactInput("BASELINE_PDF", "baseline/partial-baseline.pdf", b"%PDF-1.7\npartial\n")
        pdf_count = 1

    return {
        "snapshot": ArtifactInput("RUN_SNAPSHOT", "control/run-snapshot.json", snapshot_bytes),
        "source": ArtifactInput(
            "SOURCE",
            absolute_source_path or "inputs/source.pdf",
            source_bytes,
        ),
        "raw_ocr": ArtifactInput("RAW_OCR_TEX", "baseline/raw_ocr.tex", raw_bytes),
        "raw_freeze": ArtifactInput("RAW_OCR_FREEZE", "baseline/raw_ocr_manifest.json", raw_freeze_bytes),
        "syntax_baseline": ArtifactInput("SYNTAX_BASELINE_TEX", "baseline/syntax_baseline.tex", syntax_bytes),
        "baseline_tex": ArtifactInput("BASELINE_TEX", "baseline/baseline.tex", syntax_bytes),
        "baseline_pdf": baseline_pdf,
        "page_map": page_map,
        "page_records": ArtifactInput("PAGE_RECORDS", "baseline/page_records.json", page_records_bytes),
        "runtime_page_records": ArtifactInput(
            "RUNTIME_PAGE_RECORDS",
            "control/runtime-page-records.json",
            runtime_page_records_bytes,
        ),
        "performance_metrics": ArtifactInput("PERFORMANCE_METRICS", "audit/performance_metrics.json", performance_bytes),
        "cost_metrics": ArtifactInput("COST_METRICS", "audit/cost_metrics.json", cost_bytes),
        "compile_passes": compile_passes,
        "compile_status": compile_status,
        "compile_engine": "xelatex",
        "pdf_page_count": pdf_count,
        "producer": producer,
        "created_at": CREATED_AT,
        "strategies": {
            "born_digital_verified": 2,
            "full_visual_ocr": 0,
            "high_resolution_retry": 0,
            "crop_review": 0,
        },
        "fatal_error": fatal_error,
    }


def _with_measured_compile_evidence(values):
    baseline_bytes = values["baseline_tex"].data
    measured = []
    for index, compile_pass in enumerate(values["compile_passes"], start=1):
        measured.append(CompilePassInput(
            log_path=compile_pass.log_path,
            log_bytes=compile_pass.log_bytes,
            exit_code=compile_pass.exit_code,
            input_tex_sha256=compile_pass.input_tex_sha256,
            output_pdf_sha256=compile_pass.output_pdf_sha256,
            **_compile_execution_metadata(
                baseline_bytes,
                marker=index,
                extra_files={"figures/plot.pdf": b"exact figure bytes"},
            ),
        ))
    values["compile_passes"] = measured
    return values


def _rewrite_artifact(payload, old_artifacts, role, data, *, new_path=None):
    artifacts = dict(old_artifacts)
    descriptor = next(item for item in payload["artifacts"] if item["role"] == role)
    old_path = descriptor["path"]
    path = new_path or old_path
    descriptor["path"] = path
    descriptor["bytes"] = len(data)
    descriptor["sha256"] = _sha(data)
    del artifacts[old_path]
    artifacts[path] = data
    return artifacts


def test_manifest_is_canonical_and_fully_recomputable_from_exact_bytes():
    bundle = build_ocr_baseline_manifest(**_fixture())
    manifest = bundle.manifest.to_dict()

    assert manifest["status"] == {
        "run_status": "SUCCESS",
        "ocr_status": "COMPLETED",
        "compile_status": "COMPILED",
    }
    assert OCR_PAGE_RECORDS_SCHEMA == json.loads(
        bundle.artifact_bytes()["baseline/page_records.json"]
    )["schema_version"]
    assert manifest["bindings"]["page_records"] == "PAGE_RECORDS"
    assert manifest["bindings"]["runtime_page_records"] == "RUNTIME_PAGE_RECORDS"
    assert manifest["coverage"] == {
        "schema_version": COVERAGE_SUMMARY_SCHEMA_VERSION,
        "run_id": RUN_ID,
        "source_sha256": manifest["source"]["sha256"],
        "page_records_sha256": _sha(bundle.artifact_bytes()["baseline/page_records.json"]),
        "selected": 2,
        "completed": 2,
        "success": 2,
        "needs_review": 0,
        "failed": 0,
        "cancelled": 0,
        "incomplete": 0,
        "unresolved_pages": 0,
        "all_selected_pages_present": True,
    }
    assert manifest["compile"]["successful_passes"] == 2
    page_map = json.loads(bundle.artifact_bytes()["baseline/page_map.json"])
    assert set(page_map) == {
        "schema_version",
        "baseline_pdf_sha256",
        "baseline_pdf_page_count",
        "pages",
    }
    assert page_map["schema_version"] == OCR_PAGE_MAP_SCHEMA
    assert "run_id" not in page_map
    assert page_map["baseline_pdf_sha256"] == _sha(
        bundle.artifact_bytes()["baseline/baseline.pdf"]
    )
    assert page_map["baseline_pdf_page_count"] == 2
    assert bundle.manifest.canonical_bytes == canonical_json_bytes(manifest)
    verified = verify_ocr_baseline_manifest(
        bundle.manifest.canonical_bytes,
        bundle.artifact_bytes(),
        expected_source_sha256=manifest["source"]["sha256"],
    )
    assert verified.sha256 == bundle.manifest.sha256
    assert set(bundle.files()) == set(bundle.artifact_bytes()) | {
        "baseline/ocr_baseline_manifest.json"
    }


@pytest.mark.parametrize(
    ("compile_status", "expected_run", "expected_pdf_role"),
    [
        ("PARTIAL_COMPILED", "PARTIAL", "BASELINE_PDF"),
        ("SOURCE_PREVIEW", "PARTIAL", None),
    ],
)
def test_partial_and_source_preview_states_bind_only_truthful_pdf_evidence(
    compile_status, expected_run, expected_pdf_role,
):
    bundle = build_ocr_baseline_manifest(**_fixture(compile_status=compile_status))
    manifest = bundle.manifest.to_dict()

    assert manifest["status"]["run_status"] == expected_run
    assert manifest["status"]["compile_status"] == compile_status
    assert manifest["bindings"]["baseline_pdf"] == expected_pdf_role
    assert manifest["bindings"]["page_map"] is None
    assert all(item["role"] != "PAGE_MAP" for item in manifest["artifacts"])
    if compile_status == "PARTIAL_COMPILED":
        path = next(
            item["path"] for item in manifest["artifacts"] if item["role"] == "BASELINE_PDF"
        )
        assert bundle.artifact_bytes()[path].startswith(b"%PDF-")
    else:
        assert all(item["role"] != "BASELINE_PDF" for item in manifest["artifacts"])


@pytest.mark.parametrize("compile_status", ["PARTIAL_COMPILED", "SOURCE_PREVIEW"])
def test_noncompiled_states_reject_even_a_well_formed_page_map(compile_status):
    values = _fixture(compile_status=compile_status)
    values["page_map"] = _fixture()["page_map"]

    with pytest.raises(OcrBaselineManifestError, match="cannot accept a page map"):
        build_ocr_baseline_manifest(**values)


def test_compiled_requires_page_map_and_complete_raw_host_anchors():
    missing_map = _fixture()
    missing_map["page_map"] = None
    with pytest.raises(OcrBaselineManifestError, match="requires role PAGE_MAP"):
        build_ocr_baseline_manifest(**missing_map)

    missing_anchors = _fixture()
    raw = missing_anchors["raw_ocr"].data
    raw_without_anchors = b"\n".join(
        line for line in raw.splitlines()
        if not line.startswith(b"% LaTeXStruct-Page:")
    ) + b"\n"
    missing_anchors["raw_ocr"] = ArtifactInput(
        "RAW_OCR_TEX", "baseline/raw_ocr.tex", raw_without_anchors,
    )
    freeze = json.loads(missing_anchors["raw_freeze"].data)
    freeze["raw_ocr_sha256"] = _sha(raw_without_anchors)
    missing_anchors["raw_freeze"] = ArtifactInput(
        "RAW_OCR_FREEZE",
        "baseline/raw_ocr_manifest.json",
        canonical_json_bytes(freeze),
    )
    with pytest.raises(OcrBaselineManifestError, match="one host anchor"):
        build_ocr_baseline_manifest(**missing_anchors)


def test_compiled_page_map_is_recomputed_not_structurally_trusted():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    page_map = json.loads(bundle.artifact_bytes()["baseline/page_map.json"])
    page_map["pages"][0]["baseline_pdf_pages"] = [1, 2]
    tampered = canonical_json_bytes(page_map)
    artifacts = _rewrite_artifact(
        payload,
        bundle.artifact_bytes(),
        "PAGE_MAP",
        tampered,
    )

    with pytest.raises(OcrBaselineManifestError, match="differs from the recomputed"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_page_map_cannot_reintroduce_a_fake_run_id_wrapper():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    page_map = json.loads(bundle.artifact_bytes()["baseline/page_map.json"])
    page_map["run_id"] = RUN_ID
    artifacts = _rewrite_artifact(
        payload,
        bundle.artifact_bytes(),
        "PAGE_MAP",
        canonical_json_bytes(page_map),
    )

    with pytest.raises(OcrBaselineManifestError, match="differs from the recomputed"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_compile_page_count_must_match_the_opened_pdf_map():
    values = _fixture()
    values["pdf_page_count"] = 1

    with pytest.raises(OcrBaselineManifestError, match="pdf_page_count differs"):
        build_ocr_baseline_manifest(**values)


def test_pre_repair_compile_invocation_preserves_its_actual_candidate_hashes():
    values = _fixture()
    pre_repair_input = "d" * 64
    pre_repair_output = "e" * 64
    values["compile_passes"] = [
        CompilePassInput(
            "logs/pre-repair.log",
            b"syntax failure before deterministic repair\n",
            1,
            input_tex_sha256=pre_repair_input,
            output_pdf_sha256=pre_repair_output,
        ),
        *values["compile_passes"],
    ]

    manifest = build_ocr_baseline_manifest(**values).manifest.to_dict()
    passes = manifest["compile"]["passes"]
    final_hash = manifest["lineage"]["baseline_tex_sha256"]

    assert passes[0]["input_tex_sha256"] == pre_repair_input
    assert passes[0]["output_pdf_sha256"] == pre_repair_output
    assert [item["input_tex_sha256"] for item in passes[-2:]] == [
        final_hash,
        final_hash,
    ]
    assert manifest["compile"]["successful_passes"] == 2


def test_compiled_rejects_successes_on_two_different_candidate_hashes():
    values = _fixture()
    values["compile_passes"] = [
        CompilePassInput(
            "logs/pass-01.log",
            b"different candidate exit 0\n",
            0,
            input_tex_sha256="d" * 64,
        ),
        CompilePassInput("logs/pass-02.log", b"final candidate exit 0\n", 0),
    ]

    with pytest.raises(OcrBaselineManifestError, match="exact final BASELINE_TEX"):
        build_ocr_baseline_manifest(**values)


def test_compile_pass_defaults_are_explicitly_unmeasured_and_legacy_verifies():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    evidence_keys = {
        "command",
        "command_history",
        "compile_workdir",
        "input_inventory",
        "compile_input_sha256",
        "input_artifact_roles",
    }

    for compile_pass in payload["compile"]["passes"]:
        assert compile_pass["command"] == []
        assert compile_pass["command_history"] == []
        assert compile_pass["compile_workdir"] is None
        assert compile_pass["input_inventory"] == []
        assert compile_pass["compile_input_sha256"] is None
        assert compile_pass["input_artifact_roles"] == []
        for key in evidence_keys:
            del compile_pass[key]

    verified = verify_ocr_baseline_manifest(
        canonical_json_bytes(payload),
        bundle.artifact_bytes(),
    )
    assert verified.to_dict()["compile"]["passes"][0]["exit_code"] == 0


def test_measured_compile_execution_evidence_is_canonical_and_recomputable():
    bundle = build_ocr_baseline_manifest(
        **_with_measured_compile_evidence(_fixture())
    )
    compile_passes = bundle.manifest.to_dict()["compile"]["passes"]

    assert len(compile_passes) == 2
    for index, compile_pass in enumerate(compile_passes, start=1):
        assert compile_pass["command"] == [
            "xelatex.exe",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "main.tex",
        ]
        assert compile_pass["command_history"] == [compile_pass["command"]]
        assert compile_pass["compile_workdir"] == (
            COMPILE_WORKDIR_ID_PREFIX + f"{index:064x}"
        )
        assert compile_pass["compile_input_sha256"] == _inventory_sha256(
            compile_pass["input_inventory"]
        )
        main_tex = next(
            item for item in compile_pass["input_inventory"]
            if item["path"] == "main.tex"
        )
        assert main_tex["sha256"] == compile_pass["input_tex_sha256"]
        assert {item["path"] for item in compile_pass["input_inventory"]} == {
            "figures/plot.pdf",
            "main.tex",
        }


def test_compile_execution_evidence_tampering_fails_reverification():
    bundle = build_ocr_baseline_manifest(
        **_with_measured_compile_evidence(_fixture())
    )
    payload = copy.deepcopy(bundle.manifest.to_dict())
    payload["compile"]["passes"][0]["input_inventory"][0]["bytes"] += 1

    with pytest.raises(OcrBaselineManifestError, match="inventory digest"):
        verify_ocr_baseline_manifest(
            canonical_json_bytes(payload),
            bundle.artifact_bytes(),
        )

    payload = copy.deepcopy(bundle.manifest.to_dict())
    del payload["compile"]["passes"][0]["compile_input_sha256"]
    with pytest.raises(OcrBaselineManifestError, match="keys mismatch"):
        verify_ocr_baseline_manifest(
            canonical_json_bytes(payload),
            bundle.artifact_bytes(),
        )


def test_compile_execution_evidence_rejects_paths_workdirs_and_partial_coverage():
    values = _with_measured_compile_evidence(_fixture())
    first, second = values["compile_passes"]
    absolute_command = (
        r"C:\private\xelatex.exe",
        "-halt-on-error",
        "main.tex",
    )
    values["compile_passes"] = [
        replace(
            first,
            command=absolute_command,
            command_history=(absolute_command,),
        ),
        second,
    ]
    with pytest.raises(OcrBaselineManifestError, match="absolute path|basename"):
        build_ocr_baseline_manifest(**values)

    values = _with_measured_compile_evidence(_fixture())
    values["compile_passes"] = [
        replace(values["compile_passes"][0], compile_workdir="C:/private/compile"),
        values["compile_passes"][1],
    ]
    with pytest.raises(OcrBaselineManifestError, match="workdir identifier"):
        build_ocr_baseline_manifest(**values)

    values = _with_measured_compile_evidence(_fixture())
    values["compile_passes"] = [
        values["compile_passes"][0],
        CompilePassInput("logs/pass-02.log", b"pass 2 exit 0\n", 0),
    ]
    with pytest.raises(OcrBaselineManifestError, match="cover every pass"):
        build_ocr_baseline_manifest(**values)


def test_compile_input_inventory_rejects_unsafe_duplicate_and_unbound_entries():
    values = _with_measured_compile_evidence(_fixture())
    first, second = values["compile_passes"]
    unsafe = [dict(item) for item in first.input_inventory]
    unsafe[0]["path"] = "../private.pdf"
    values["compile_passes"] = [replace(first, input_inventory=unsafe), second]
    with pytest.raises(OcrBaselineManifestError, match="relative POSIX"):
        build_ocr_baseline_manifest(**values)

    values = _with_measured_compile_evidence(_fixture())
    first, second = values["compile_passes"]
    duplicate = [dict(item) for item in first.input_inventory]
    duplicate.append(dict(duplicate[-1]))
    values["compile_passes"] = [replace(first, input_inventory=duplicate), second]
    with pytest.raises(OcrBaselineManifestError, match="unique"):
        build_ocr_baseline_manifest(**values)

    values = _with_measured_compile_evidence(_fixture())
    first, second = values["compile_passes"]
    unbound = [dict(item) for item in first.input_inventory]
    main_tex = next(item for item in unbound if item["path"] == "main.tex")
    main_tex["sha256"] = "d" * 64
    values["compile_passes"] = [
        replace(
            first,
            input_inventory=unbound,
            compile_input_sha256=_inventory_sha256(unbound),
        ),
        second,
    ]
    with pytest.raises(OcrBaselineManifestError, match="exact input bytes"):
        build_ocr_baseline_manifest(**values)


@pytest.mark.parametrize(
    ("field", "bad_value", "message"),
    [
        ("bytes", -1, "non-negative integer"),
        ("bytes", True, "non-negative integer"),
        ("sha256", "not-a-sha256", "sha256 is invalid"),
    ],
)
def test_compile_input_inventory_rejects_invalid_bytes_and_sha(
    field,
    bad_value,
    message,
):
    values = _with_measured_compile_evidence(_fixture())
    first, second = values["compile_passes"]
    inventory = [dict(item) for item in first.input_inventory]
    inventory[0][field] = bad_value
    values["compile_passes"] = [replace(first, input_inventory=inventory), second]

    with pytest.raises(OcrBaselineManifestError, match=message):
        build_ocr_baseline_manifest(**values)


def test_needs_review_is_completed_work_but_never_full_success():
    bundle = build_ocr_baseline_manifest(**_fixture(
        statuses=(OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW),
    ))
    manifest = bundle.manifest.to_dict()

    assert manifest["coverage"]["completed"] == 2
    assert manifest["coverage"]["success"] == 1
    assert manifest["coverage"]["needs_review"] == 1
    assert manifest["status"]["ocr_status"] == "COMPLETED_WITH_REVIEW"
    assert manifest["status"]["run_status"] == "PARTIAL"
    with pytest.raises(OcrBaselineManifestError, match="requested run_status"):
        build_ocr_baseline_manifest(
            **_fixture(statuses=(OcrPageStatus.SUCCESS, OcrPageStatus.NEEDS_REVIEW)),
            run_status="SUCCESS",
        )


def test_failed_page_is_not_counted_as_completed_or_successful():
    bundle = build_ocr_baseline_manifest(**_fixture(
        statuses=(OcrPageStatus.SUCCESS, OcrPageStatus.FAILED),
    ))
    manifest = bundle.manifest.to_dict()

    assert manifest["coverage"]["completed"] == 1
    assert manifest["coverage"]["failed"] == 1
    assert manifest["status"]["ocr_status"] == "INCOMPLETE"
    assert manifest["status"]["run_status"] == "PARTIAL"


def test_runtime_success_cannot_bypass_a_failed_eight_check_coverage_gate():
    bundle = build_ocr_baseline_manifest(**_fixture(
        coverage_check_failure="syntax_checked",
    ))
    manifest = bundle.manifest.to_dict()

    assert manifest["coverage"]["completed"] == 1
    assert manifest["coverage"]["success"] == 1
    assert manifest["coverage"]["incomplete"] == 1
    assert manifest["status"]["ocr_status"] == "INCOMPLETE"
    assert manifest["status"]["run_status"] == "PARTIAL"


def test_runtime_records_remain_bound_but_cannot_disagree_with_coverage_status():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    runtime_records = json.loads(
        bundle.artifact_bytes()["control/runtime-page-records.json"]
    )
    runtime_records["pages"][1]["status"] = "NEEDS_REVIEW"
    rewritten = canonical_json_bytes(runtime_records)
    artifacts = _rewrite_artifact(
        payload,
        bundle.artifact_bytes(),
        "RUNTIME_PAGE_RECORDS",
        rewritten,
    )

    with pytest.raises(OcrBaselineManifestError, match="terminal statuses differ"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_strategies_are_recomputed_from_bound_performance_distribution():
    bundle = build_ocr_baseline_manifest(**_fixture())
    manifest = bundle.manifest.to_dict()
    assert manifest["strategies"] == {
        "born_digital_verified": 2,
        "full_visual_ocr": 0,
        "high_resolution_retry": 0,
        "crop_review": 0,
    }

    contradictory = _fixture()
    contradictory["strategies"] = {
        "born_digital_verified": 1,
        "full_visual_ocr": 1,
        "high_resolution_retry": 0,
        "crop_review": 0,
    }
    with pytest.raises(OcrBaselineManifestError, match="strategy_distribution"):
        build_ocr_baseline_manifest(**contradictory)

    payload = copy.deepcopy(bundle.manifest.to_dict())
    payload["strategies"]["born_digital_verified"] = 1
    payload["strategies"]["full_visual_ocr"] = 1
    with pytest.raises(OcrBaselineManifestError, match="strategy_distribution"):
        verify_ocr_baseline_manifest(
            canonical_json_bytes(payload),
            bundle.artifact_bytes(),
        )


def test_pdf_source_page_count_is_recomputed_from_exact_readable_bytes():
    values = _fixture()
    with pymupdf.open(stream=values["source"].data, filetype="pdf") as document:
        assert document.page_count == 2
    build_ocr_baseline_manifest(**values)

    with pytest.raises(OcrBaselineManifestError, match="source page count differs"):
        build_ocr_baseline_manifest(**_fixture(actual_source_pages=1))


def test_unknown_collector_usage_cost_and_memory_remain_null():
    bundle = build_ocr_baseline_manifest(**_fixture(unknown_metrics=True))
    manifest = bundle.manifest.to_dict()

    assert manifest["performance"]["usage"]["input_tokens"] is None
    assert manifest["performance"]["usage"]["output_tokens"] is None
    assert manifest["performance"]["usage"]["cost"] is None
    assert manifest["performance"]["resources"]["peak_memory_bytes"] is None
    assert manifest["cost"]["actual"]["input_tokens"] is None
    assert manifest["cost"]["actual"]["output_tokens"] is None
    assert manifest["cost"]["actual"]["cost"] is None


def test_unknown_metric_cannot_be_rewritten_as_zero_even_with_new_hash_claims():
    bundle = build_ocr_baseline_manifest(**_fixture(unknown_metrics=True))
    payload = copy.deepcopy(bundle.manifest.to_dict())
    performance = json.loads(
        bundle.artifact_bytes()["audit/performance_metrics.json"]
    )
    performance["usage"]["input_tokens"] = 0
    rewritten = canonical_json_bytes(performance)
    artifacts = _rewrite_artifact(
        payload,
        bundle.artifact_bytes(),
        "PERFORMANCE_METRICS",
        rewritten,
    )
    payload["performance"] = performance

    with pytest.raises(OcrBaselineManifestError, match="must remain null"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_verifier_rejects_tampered_artifact_bytes():
    bundle = build_ocr_baseline_manifest(**_fixture())
    artifacts = dict(bundle.artifact_bytes())
    artifacts["baseline/raw_ocr.tex"] += b"tampered"

    with pytest.raises(OcrBaselineManifestError, match="bytes/hash mismatch"):
        verify_ocr_baseline_manifest(bundle.manifest.canonical_bytes, artifacts)


def test_verifier_rejects_missing_page_even_if_attacker_rewrites_descriptor_hash():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    records = json.loads(bundle.artifact_bytes()["baseline/page_records.json"])
    records["pages"].pop()
    rewritten = canonical_json_bytes(records)
    artifacts = _rewrite_artifact(
        payload, bundle.artifact_bytes(), "PAGE_RECORDS", rewritten,
    )

    with pytest.raises(OcrBaselineManifestError, match="page coverage contract"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_verifier_rejects_fake_pdf_even_with_rewritten_hash_claims():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    fake_pdf = b"this is not a PDF"
    artifacts = _rewrite_artifact(
        payload, bundle.artifact_bytes(), "BASELINE_PDF", fake_pdf,
    )
    payload["compile"]["passes"][-1]["output_pdf_sha256"] = _sha(fake_pdf)

    with pytest.raises(OcrBaselineManifestError, match="PDF magic"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_absolute_artifact_paths_are_rejected_at_build_and_verify():
    with pytest.raises(OcrBaselineManifestError, match="relative POSIX"):
        build_ocr_baseline_manifest(**_fixture(absolute_source_path="C:/private/source.pdf"))

    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    source = bundle.artifact_bytes()["inputs/source.pdf"]
    artifacts = _rewrite_artifact(
        payload,
        bundle.artifact_bytes(),
        "SOURCE",
        source,
        new_path="C:/private/source.pdf",
    )
    with pytest.raises(OcrBaselineManifestError, match="relative POSIX"):
        verify_ocr_baseline_manifest(canonical_json_bytes(payload), artifacts)


def test_status_contradictions_and_secret_producer_fields_fail_closed():
    bundle = build_ocr_baseline_manifest(**_fixture())
    payload = copy.deepcopy(bundle.manifest.to_dict())
    payload["status"]["ocr_status"] = "INCOMPLETE"
    with pytest.raises(OcrBaselineManifestError, match="terminal statuses contradict"):
        verify_ocr_baseline_manifest(
            canonical_json_bytes(payload), bundle.artifact_bytes(),
        )

    values = _fixture()
    values["producer"] = {**values["producer"], "build_id": "Bearer secret-token-value"}
    with pytest.raises(OcrBaselineManifestError, match="secret-like"):
        build_ocr_baseline_manifest(**values)


def test_noncanonical_manifest_encoding_is_rejected():
    bundle = build_ocr_baseline_manifest(**_fixture())
    pretty = json.dumps(bundle.manifest.to_dict(), indent=2).encode()
    with pytest.raises(OcrBaselineManifestError, match="not in canonical"):
        verify_ocr_baseline_manifest(pretty, bundle.artifact_bytes())
