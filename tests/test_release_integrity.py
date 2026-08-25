from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import pymupdf

from latexstruct.core.compilecheck import (
    COMPILE_WORKDIR_ID_PREFIX,
    build_compile_input_manifest,
)
from latexstruct.core.analysis_input import load_ocr_analysis_input_package
from latexstruct.core.analysis_inventory import (
    build_analysis_inventory_bundle,
    build_host_inventory_authorizations,
    evaluate_analysis_inventory_gate,
)
from latexstruct.core.ocr_manifest import (
    OCR_PRODUCER_SCHEMA,
    OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
    ArtifactInput,
    CompilePassInput,
    build_ocr_baseline_manifest,
    canonical_json_bytes,
)
from latexstruct.core.ocr_block_inventory import (
    OcrBlockInventory,
    OcrBlockInventoryBlock,
    OcrBlockInventoryPage,
)
from latexstruct.core.ocr_evidence_correction import (
    produce_evidence_corrected_baseline,
)
from latexstruct.core.ocr_lane_routes import (
    OcrLaneOwner,
    OcrLaneRoute,
    build_lane_routes_artifact,
    parse_lane_routes_artifact,
)
from latexstruct.core.ocr_page_evidence_bindings import (
    OcrPageEvidenceBinding,
    OcrPageTerminalMode,
    build_ocr_page_evidence_bindings,
    parse_ocr_page_evidence_bindings,
)
from latexstruct.core.ocr_metrics import (
    OcrMetricsCollector,
    OcrStrategy,
    PageFinalStatus as MetricsPageFinalStatus,
    RequestKind,
)
from latexstruct.core.ocr_page_evidence import (
    FinalPageStatus,
    PageCoverageChecks,
    PageCoverageRecord,
    VisualMode,
    build_page_summaries,
    parse_page_records,
)
from latexstruct.core.ocr_page_map import build_pdf_page_map, extract_page_anchors
from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    make_page_id,
    make_run_snapshot,
)
from latexstruct.core.ocr_schema import PageBlockType


SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "release_integrity.py"
SPEC = importlib.util.spec_from_file_location("release_integrity", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VERSION = "2.0.0"
COMMIT = "d" * 40
RUNNER_LABEL = "latexstruct-acceptance-" + "a" * 32
PRIVATE_SOURCE_FILENAME_SENTINEL = "PRIVATE-SOURCE-NAME-DO-NOT-PUBLISH.pdf"
PRIVATE_PAGE_RISK_SENTINEL = (
    r"C:\Users\private-user\secret-page-risk-evidence.json"
)


def test_release_integrity_direct_script_entrypoint_loads_project_package():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=SCRIPT.parents[1],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "verify-attestation" in result.stdout


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_pdf_bytes(page_count: int) -> bytes:
    document = pymupdf.open()
    try:
        for index in range(page_count):
            page = document.new_page()
            page.insert_text((72, 72), f"release fixture source page {index + 1}")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _compiled_pdf_bytes(page_count: int) -> bytes:
    document = pymupdf.open()
    try:
        for _ in range(page_count):
            document.new_page()
        destinations = []
        for index in range(1, page_count + 1):
            xref = document.page_xref(index - 1)
            destinations.append(
                f"/ocr-page-{index:06d} [{xref} 0 R /XYZ 0 800 0]"
            )
        document.xref_set_key(
            document.pdf_catalog(),
            "Dests",
            f"<< {' '.join(destinations)} >>",
        )
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


PRODUCTION_RAMSEY_37_SOURCE_SHA256 = MODULE.RAMSEY_37_SOURCE_SHA256
TEST_SOURCE_PDF_BYTES = _source_pdf_bytes(37)
TEST_SOURCE_SHA256 = _sha(TEST_SOURCE_PDF_BYTES)
TEST_RUN_ID = "a" * 32


def _fixture_page_tex(index: int) -> str:
    source_text = f"release fixture source page {index}"
    if index <= 16:
        return source_text
    if index <= 31:
        return f"{source_text} \\(x\\)"
    return source_text + " " + " ".join("\\(x\\)" for _ in range(8))


def _fixture_syntax_tex_bytes(pages: int) -> bytes:
    body_rows: list[str] = []
    for index in range(1, pages + 1):
        body_rows.extend((
            f"% Page {index}",
            (
                "% LaTeXStruct-Page: "
                f"page_id={make_page_id(index)} source_page={index}"
            ),
            _fixture_page_tex(index),
            "",
        ))
    return (
        b"\\documentclass{article}\n\\begin{document}\n"
        + ("\n".join(body_rows).rstrip() + "\n").encode("utf-8")
        + b"\\end{document}\n"
    )


@pytest.fixture(autouse=True)
def _use_recomputable_test_source_anchor(monkeypatch: pytest.MonkeyPatch):
    """Use a constructible PDF digest while retaining the production constant."""

    monkeypatch.setattr(MODULE, "RAMSEY_37_SOURCE_SHA256", TEST_SOURCE_SHA256)


def _valid_ocr_baseline_package(
    run_dir: Path,
    *,
    pages: int,
    source_filename: str,
    runtime: dict,
    model: dict,
) -> tuple[dict, str, str]:
    source_bytes = TEST_SOURCE_PDF_BYTES
    snapshot = make_run_snapshot(
        source_bytes=source_bytes,
        source_type="pdf",
        original_filename=source_filename,
        source_total_pages=pages,
        selected_pages=tuple(range(1, pages + 1)),
        ocr_model=model["id"],
        api_backend=model["backend"],
        app_version=runtime["version"],
        quality_tier="high",
        run_id=TEST_RUN_ID,
        started_at="2026-08-24T00:00:00.000Z",
        pipeline_contract={
            "project_id": "release-fixture",
            "document_strategy": "NATIVE_PAGE_RECONSTRUCTION",
            "page_strategies": [
                {
                    "page_id": make_page_id(index),
                    "source_page": index,
                    "strategy": "OBJECT_LAYER_VERIFIED",
                    "source_page_object_hash": _sha(
                        f"source object {index}".encode()
                    ),
                    "source_text_layer_sha256": _sha(
                        _fixture_page_tex(index).encode("utf-8")
                    ),
                    "candidate_tex_sha256": _sha(
                        _fixture_page_tex(index).encode("utf-8")
                    ),
                    "block_count": 1,
                }
                for index in range(1, pages + 1)
            ],
            "verification_model": model["id"],
            "prompt_version": "ocr-v3",
            "git_commit": runtime["commit"],
            "build_id": runtime["build_id"],
            "dirty": False,
            "latex_engine": "xelatex",
        },
    )
    records: list[OcrPageRecord] = []
    coverage_records: list[PageCoverageRecord] = []
    raw_parts: list[str] = []
    for index in range(1, pages + 1):
        page_id = make_page_id(index)
        page_tex = _fixture_page_tex(index)
        record = OcrPageRecord(
            page_id=page_id,
            source_page=index,
            task_index=index,
            status=OcrPageStatus.SUCCESS,
            raw_response_sha256=_sha(f"response {index}".encode()),
            source_evidence_sha256=_sha(
                f"source evidence {index}".encode()
            ),
            raw_tex=page_tex,
            cleaned_tex=page_tex,
            quality_issues=(
                ({"code": "fixture-quality", "severity": "warning"},)
                if index == 32
                else ()
            ),
            host_quality_flags=(
                ({"code": "fixture-host-flag", "source": "host"},)
                if index == 32
                else ()
            ),
        )
        records.append(record)
        coverage_records.append(
            PageCoverageRecord(
                page_id=page_id,
                source_page_number=index,
                source_sha256=snapshot.source_sha256,
                source_page_object_hash=_sha(f"source object {index}".encode()),
                checks=PageCoverageChecks.from_bools(
                    source_hash_bound=True,
                    candidate_created=True,
                    visual_authority_checked=True,
                    reading_order_checked=True,
                    text_coverage_checked=True,
                    math_region_coverage_checked=True,
                    syntax_checked=True,
                    persisted=True,
                ),
                visual_mode=VisualMode.VERIFIER,
                final_status=FinalPageStatus.SUCCESS,
                artifact_hashes={
                    "source.json": _sha(f"source {index}".encode()),
                    "candidate.json": _sha(f"candidate {index}".encode()),
                    "verification.json": _sha(f"verification {index}".encode()),
                    "raw-response.json": record.raw_response_sha256,
                    "page.tex": record.tex_sha256,
                },
            )
        )
        raw_parts.extend(
            [
                f"% Page {index}",
                (
                    "% LaTeXStruct-Page: "
                    f"page_id={page_id} source_page={index}"
                ),
                page_tex,
                "",
            ]
        )
    raw_bytes = ("\n".join(raw_parts).rstrip() + "\n").encode()
    created_at = "2026-08-24T00:01:00.000Z"
    raw_freeze_bytes = canonical_json_bytes(
        {
            "schema_version": "latexstruct-raw-ocr-freeze-v1",
            "run_id": TEST_RUN_ID,
            "created_at": created_at,
            "raw_ocr_sha256": _sha(raw_bytes),
            "selected_pages": list(range(1, pages + 1)),
            "page_records": [
                {
                    "page_id": record.page_id,
                    "source_page": record.source_page,
                    "status": record.status.value,
                    "tex_sha256": record.tex_sha256,
                    "raw_response_sha256": record.raw_response_sha256,
                }
                for record in records
            ],
            "ocr_model": model["id"],
            "api_backend": model["backend"],
            "usage": {
                "calls": pages,
                "input_tokens": pages * 10,
                "output_tokens": pages * 5,
            },
            "unresolved_regions": [],
            "error_pages": [],
            "merge_version": "1",
        }
    )
    page_records_bytes = build_page_summaries(
        coverage_records,
        run_id=TEST_RUN_ID,
        source_sha256=snapshot.source_sha256,
        expected_source_pages=tuple(range(1, pages + 1)),
    ).page_records_bytes
    runtime_page_records_bytes = canonical_json_bytes(
        {
            "schema_version": OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
            "run_id": TEST_RUN_ID,
            "pages": [record.to_dict() for record in records],
        }
    )
    metrics = OcrMetricsCollector(
        TEST_RUN_ID,
        selected_pages=pages,
        started_at_seconds=0.0,
        clock=lambda: 60.0,
    )
    for index in range(1, pages + 1):
        metrics.record_page_result(
            make_page_id(index),
            status=MetricsPageFinalStatus.SUCCESS,
            strategy=OcrStrategy.OBJECT_LAYER_VERIFIED,
            completed_at_seconds=float(index),
            dpi_history=(160,),
        )
        metrics.record_request(
            f"verify-{index}",
            kind=RequestKind.VISUAL_VERIFICATION,
            latency_ms=10.0 + index,
            dpi=160,
            status_code=200,
            input_tokens=10,
            output_tokens=5,
            cost="0.01",
            currency="USD",
            retry=False,
            truncated=False,
            strong_model=False,
        )
    metrics.record_resource_sample(memory_bytes=1024)
    metric_reports = metrics.canonical_reports(now_seconds=60.0)
    syntax_bytes = (
        b"\\documentclass{article}\n\\begin{document}\n"
        + raw_bytes
        + b"\\end{document}\n"
    )
    assert syntax_bytes == _fixture_syntax_tex_bytes(pages)
    baseline_pdf_bytes = _compiled_pdf_bytes(pages)
    page_map_bytes = build_pdf_page_map(
        baseline_pdf_bytes,
        extract_page_anchors(
            raw_bytes.decode("utf-8"),
            expected_selected_pages=tuple(range(1, pages + 1)),
        ),
    ).to_json_bytes()
    compile_inputs = build_compile_input_manifest(syntax_bytes.decode("utf-8"))
    command = (
        "xelatex.exe",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "main.tex",
    )
    compile_passes = tuple(
        CompilePassInput(
            log_path=f"compile/pass-{index:02d}.log",
            log_bytes=f"XeLaTeX measured pass {index}: exit 0\n".encode(),
            exit_code=0,
            input_tex_sha256=_sha(syntax_bytes),
            output_pdf_sha256=(
                _sha(baseline_pdf_bytes) if index == 2 else None
            ),
            command=command,
            command_history=(command,),
            compile_workdir=COMPILE_WORKDIR_ID_PREFIX + f"{index:064x}",
            input_inventory=tuple(compile_inputs["files"]),
            compile_input_sha256=compile_inputs["manifest_sha256"],
            input_files=(("main.tex", syntax_bytes),),
        )
        for index in (1, 2)
    )
    correction_report_bytes = produce_evidence_corrected_baseline(
        raw_ocr_tex=raw_bytes.decode("utf-8"),
        syntax_baseline_tex=syntax_bytes.decode("utf-8"),
    ).report.canonical_json_bytes()
    lane_routes_bytes = build_lane_routes_artifact(
        run_id=TEST_RUN_ID,
        selected_pages=tuple(range(1, pages + 1)),
        routes=tuple(
            OcrLaneRoute(
                run_id=TEST_RUN_ID,
                page_id=record.page_id,
                source_page=record.source_page,
                selected_index=record.task_index,
                candidate_sha256=record.tex_sha256,
                owner=OcrLaneOwner.TERMINAL_VISUAL,
                verifier_response_sha256=record.raw_response_sha256,
                reason="fixture verifier PASS",
            )
            for record in records
        ),
    )
    page_evidence_bindings_bytes = build_ocr_page_evidence_bindings(
        run_id=TEST_RUN_ID,
        source_sha256=snapshot.source_sha256,
        selected_pages=tuple(range(1, pages + 1)),
        pages=tuple(
            OcrPageEvidenceBinding(
                page_id=record.page_id,
                source_page=record.source_page,
                selected_index=record.task_index,
                terminal_mode=OcrPageTerminalMode.VISUAL,
                terminal_status=record.status.value,
                initial_candidate_tex_sha256=record.tex_sha256,
                visual_verification_response_sha256=(
                    record.raw_response_sha256
                ),
                terminal_cleaned_tex_sha256=record.tex_sha256,
                runtime_record_sha256=_sha(json.dumps(
                    record.to_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")),
                runtime_source_evidence_sha256=(
                    record.source_evidence_sha256
                ),
                runtime_raw_response_sha256=record.raw_response_sha256,
                page_evidence_source_sha256=(
                    coverage_records[index - 1].artifact_hashes["source.json"]
                ),
                page_evidence_candidate_sha256=(
                    coverage_records[index - 1].artifact_hashes["candidate.json"]
                ),
                page_evidence_verification_sha256=(
                    coverage_records[index - 1].artifact_hashes[
                        "verification.json"
                    ]
                ),
                page_evidence_raw_response_sha256=(
                    coverage_records[index - 1].artifact_hashes[
                        "raw-response.json"
                    ]
                ),
                page_evidence_tex_sha256=(
                    coverage_records[index - 1].artifact_hashes["page.tex"]
                ),
            )
            for index, record in enumerate(records, 1)
        ),
    )
    block_inventory_bytes = OcrBlockInventory(
        run_id=TEST_RUN_ID,
        source_sha256=snapshot.source_sha256,
        selected_pages=tuple(range(1, pages + 1)),
        pages=tuple(
            OcrBlockInventoryPage(
                page_id=record.page_id,
                source_page=record.source_page,
                selected_index=record.task_index,
                source_page_object_hash=_sha(
                    f"source object {record.source_page}".encode()
                ),
                source_text_layer_sha256=_sha(
                    record.cleaned_tex.encode("utf-8")
                ),
                blocks=(OcrBlockInventoryBlock(
                    block_id=(
                        f"{record.page_id}-block-0001-"
                        f"{record.source_page:012x}"
                    ),
                    block_type=PageBlockType.TEXT,
                    reading_order=1,
                    plain_text=record.cleaned_tex,
                    style_features={},
                    bbox=(72.0, 72.0, 500.0, 90.0),
                    source_object_hash=_sha(
                        f"source object {record.source_page}".encode()
                    ),
                ),),
            )
            for record in records
        ),
    ).to_json_bytes()
    bundle = build_ocr_baseline_manifest(
        snapshot=ArtifactInput(
            "RUN_SNAPSHOT",
            "inputs/run-snapshot.json",
            canonical_json_bytes(snapshot.to_dict()),
        ),
        source=ArtifactInput("SOURCE", "inputs/source.pdf", source_bytes),
        raw_ocr=ArtifactInput("RAW_OCR_TEX", "baseline/raw-ocr.tex", raw_bytes),
        raw_freeze=ArtifactInput(
            "RAW_OCR_FREEZE",
            "baseline/raw-ocr-freeze.json",
            raw_freeze_bytes,
        ),
        syntax_baseline=ArtifactInput(
            "SYNTAX_BASELINE_TEX",
            "baseline/syntax-baseline.tex",
            syntax_bytes,
        ),
        baseline_tex=ArtifactInput(
            "BASELINE_TEX", "baseline/baseline.tex", syntax_bytes
        ),
        evidence_correction_report=ArtifactInput(
            "EVIDENCE_CORRECTION_REPORT",
            "evidence/evidence-correction-report.json",
            correction_report_bytes,
        ),
        lane_routes=ArtifactInput(
            "LANE_ROUTES",
            "evidence/lane-routes.json",
            lane_routes_bytes,
        ),
        page_evidence_bindings=ArtifactInput(
            "OCR_PAGE_EVIDENCE_BINDINGS",
            "evidence/ocr-page-evidence-bindings.json",
            page_evidence_bindings_bytes,
        ),
        block_inventory=ArtifactInput(
            "OCR_BLOCK_INVENTORY",
            "evidence/ocr-block-inventory.json",
            block_inventory_bytes,
        ),
        baseline_pdf=ArtifactInput(
            "BASELINE_PDF", "baseline/baseline.pdf", baseline_pdf_bytes
        ),
        page_map=ArtifactInput("PAGE_MAP", "baseline/page-map.json", page_map_bytes),
        page_records=ArtifactInput(
            "PAGE_RECORDS", "evidence/page-records.json", page_records_bytes
        ),
        runtime_page_records=ArtifactInput(
            "RUNTIME_PAGE_RECORDS",
            "evidence/runtime-page-records.json",
            runtime_page_records_bytes,
        ),
        performance_metrics=ArtifactInput(
            "PERFORMANCE_METRICS",
            "metrics/performance-metrics.json",
            metric_reports["performance_metrics"],
        ),
        cost_metrics=ArtifactInput(
            "COST_METRICS",
            "metrics/cost-report.json",
            metric_reports["cost_report"],
        ),
        compile_passes=compile_passes,
        compile_status="COMPILED",
        compile_engine="xelatex",
        pdf_page_count=pages,
        producer={
            "schema_version": OCR_PRODUCER_SCHEMA,
            "app_version": runtime["version"],
            "git_commit": runtime["commit"],
            "build_id": runtime["build_id"],
            "ocr_model": model["id"],
            "verification_model": model["id"],
            "prompt_version": "ocr-v3",
            "api_backend": model["backend"],
        },
        created_at=created_at,
    )
    package_root = run_dir / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY
    for logical_path, data in bundle.files().items():
        target = package_root.joinpath(*logical_path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest_filename = (
        f"{MODULE.OCR_BASELINE_PACKAGE_DIRECTORY}/"
        f"{MODULE.OCR_BASELINE_MANIFEST_MEMBER}"
    )
    binding = {
        "package_directory": MODULE.OCR_BASELINE_PACKAGE_DIRECTORY,
        "manifest_filename": manifest_filename,
        "manifest_sha256": bundle.manifest.sha256,
        "run_id": TEST_RUN_ID,
    }
    return binding, _sha(compile_passes[-1].log_bytes), _sha(baseline_pdf_bytes)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _inject_private_publication_sentinels(run_dir: Path) -> None:
    """Place valid private-only values where a public projection must not copy."""

    for name in (
        "analysis-attestation.json",
        "analysis-performance.json",
        "analysis-validation-report.json",
    ):
        path = run_dir / name
        payload = json.loads(path.read_text(encoding="utf-8"))
        if name == "analysis-attestation.json":
            risk = payload["page_risk_admission"]
            preflight = risk["preflight"]
            preflight["inputs"][0]["machine_visual_evidence"][
                "private_diagnostic_path"
            ] = PRIVATE_PAGE_RISK_SENTINEL
            preflight_body = {
                key: value
                for key, value in preflight.items()
                if key != "preflight_sha256"
            }
            digest = MODULE._canonical_json_sha256(preflight_body)
            preflight["preflight_sha256"] = digest
            risk["preflight_sha256"] = digest
        _write_json(path, payload)


def _rewrite_private_analysis_audit(
    run_dir: Path,
    mutator,
    *,
    rebind_internal_hashes: bool,
) -> None:
    """Rewrite the private audit fixture and always rebind its outer record."""

    audit_path = run_dir / "analysis-audit-submission.zip"
    with zipfile.ZipFile(audit_path, "r") as archive:
        members = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if not info.is_dir()
        }
    manifest = json.loads(members["submission_manifest.json"])
    mutator(members, manifest)
    if rebind_internal_hashes:
        for record in manifest["artifacts"]:
            member = record["path"]
            if member in members:
                record["byte_count"] = len(members[member])
                record["bytes_sha256"] = _sha(members[member])
        members["submission_manifest.json"] = canonical_json_bytes(manifest)
        members.pop("audit/SHA256SUMS", None)
        members["audit/SHA256SUMS"] = "".join(
            f"{_sha(payload)}  {member}\n"
            for member, payload in sorted(members.items())
        ).encode("utf-8")
    buffer_path = audit_path.with_suffix(".replacement.zip")
    with zipfile.ZipFile(
        buffer_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for member, payload in sorted(members.items()):
            archive.writestr(member, payload)
    buffer_path.replace(audit_path)
    attestation_path = run_dir / "analysis-attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["audit_submission"]["bytes"] = audit_path.stat().st_size
    attestation["audit_submission"]["sha256"] = _sha(audit_path.read_bytes())
    _write_json(attestation_path, attestation)


def _rewrite_ocr_manifest(run_dir: Path, mutator) -> None:
    manifest_path = (
        run_dir
        / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY
        / MODULE.OCR_BASELINE_MANIFEST_MEMBER
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutator(payload)
    manifest_bytes = canonical_json_bytes(payload)
    manifest_path.write_bytes(manifest_bytes)
    attestation_path = run_dir / "acceptance-attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["ocr_baseline"]["manifest_sha256"] = _sha(manifest_bytes)
    _write_json(attestation_path, attestation)


def _valid_run(
    root: Path,
    pages: int,
    *,
    real_execution: bool = True,
    executable_sha256: str = "e" * 64,
    source_sha256: str | None = None,
    build_id: str = "200",
    run_dir_name: str | None = None,
) -> Path:
    run_dir = root / (run_dir_name or f"run-{pages}")
    source_sha256 = source_sha256 or MODULE.RAMSEY_37_SOURCE_SHA256
    runtime = {
        "version": VERSION,
        "commit": COMMIT,
        "build_id": build_id,
        "executable_filename": "LaTeXStruct.exe",
        "executable_sha256": executable_sha256,
    }
    model = {"id": "qwen-vl-real", "backend": "dashscope", "calls": pages}
    source = {
        "filename": PRIVATE_SOURCE_FILENAME_SENTINEL,
        "sha256": source_sha256,
        "total_pages": pages,
    }
    selected = {"start_page": 1, "end_page": pages, "expected_pages": pages}
    page_evidence = {
        "successful": pages,
        "needs_review": 0,
        "failed": 0,
        "pending": 0,
        "failed_page_numbers": [],
        "needs_review_page_numbers": [],
    }
    performance = {
        "schema_version": "latexstruct-v2-ocr-acceptance/2",
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "model": model,
        "source": source,
        "selected_range": selected,
        "pages": page_evidence,
        "wall_time_seconds": 60,
        "successful_pages_per_minute": pages,
        "thresholds": {
            "minimum_successful_pages_per_minute": None,
            "maximum_wall_time_seconds": None,
        },
    }
    validation = {
        "schema_version": "latexstruct-v2-ocr-acceptance/2",
        "result": "PASS",
        "acceptance_passed": True,
        "job_id": TEST_RUN_ID,
        "runtime_identity": runtime,
        "model": model,
        "execution": {
            "real_execution": real_execution,
            "test_double": not real_execution,
            "simulated": not real_execution,
            "api_client": "LocalHttpApi",
            "ui_driver": "PlaywrightUiDriver",
        },
    }
    performance_path = run_dir / "performance.json"
    validation_path = run_dir / "validation-report.json"
    _write_json(performance_path, performance)
    _write_json(validation_path, validation)
    ocr_baseline = None
    compile_log_sha256 = "b" * 64
    baseline_pdf_sha256 = "c" * 64
    if (
        pages == 37
        and real_execution
        and source_sha256 == MODULE.RAMSEY_37_SOURCE_SHA256
        and source_sha256 == TEST_SOURCE_SHA256
        and MODULE.GITHUB_RUN_ID_RE.fullmatch(build_id) is not None
    ):
        (
            ocr_baseline,
            compile_log_sha256,
            baseline_pdf_sha256,
        ) = _valid_ocr_baseline_package(
            run_dir,
            pages=pages,
            source_filename=source["filename"],
            runtime=runtime,
            model=model,
        )
    attestation = {
        "schema_version": MODULE.RUN_ATTESTATION_SCHEMA,
        "profile_kind": "ocr",
        "result": "PASS",
        "acceptance_passed": True,
        "generated_at": "2026-08-24T00:00:00Z",
        "execution": validation["execution"],
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "pages": page_evidence,
        "model": model,
        "compilation": {
            "status": "COMPILED",
            "successful_passes": 2,
            "exit_code": 0,
            "compile_log_sha256": compile_log_sha256,
            "baseline_pdf_sha256": baseline_pdf_sha256,
        },
        "timing": {
            "measurement": (
                "external monotonic wall clock started before browser upload/start "
                "click and stopped only after terminal compile"
            ),
            "started_at": "2026-08-24T00:00:00Z",
            "ended_at": "2026-08-24T00:30:00Z",
            "wall_time_seconds": 1800,
            "successful_pages_per_minute": pages / 30,
            "timed_out": False,
            "completed_terminal_run": True,
        },
        "reports": {
            "performance": {
                "filename": "performance.json",
                "sha256": MODULE._sha256_file(performance_path),
            },
            "validation": {
                "filename": "validation-report.json",
                "sha256": MODULE._sha256_file(validation_path),
            },
        },
    }
    if ocr_baseline is not None:
        attestation["ocr_baseline"] = ocr_baseline
    _write_json(run_dir / "acceptance-attestation.json", attestation)
    return run_dir


def _valid_analysis_run(
    root: Path,
    pages: int,
    *,
    real_execution: bool = True,
    terminal_status: str = "VERIFIED",
    executable_sha256: str = "e" * 64,
    source_sha256: str | None = None,
    build_id: str = "200",
) -> Path:
    run_dir = root / f"analysis-run-{pages}"
    source_sha256 = source_sha256 or MODULE.RAMSEY_37_SOURCE_SHA256
    runtime = {
        "version": VERSION,
        "commit": COMMIT,
        "build_id": build_id,
        "executable_filename": "LaTeXStruct.exe",
        "executable_sha256": executable_sha256,
    }
    source = {
        "filename": PRIVATE_SOURCE_FILENAME_SENTINEL,
        "sha256": source_sha256,
        "total_pages": pages,
    }
    selected = {"start_page": 1, "end_page": pages, "expected_pages": pages}
    page_ids = [
        f"src-{source_sha256[:12]}-p{page:06d}" for page in range(1, pages + 1)
    ]
    models = {
        "calls_total": pages * 5,
        "roles": [
            {
                "role": "structure",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": pages,
            },
            {
                "role": "analysis",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": pages,
            },
            {
                "role": "visual_review",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": pages,
            },
            {
                "role": "visual_review",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": pages * 2,
            },
        ],
    }
    candidate_document = pymupdf.open()
    for _page in range(38):
        candidate_document.new_page()
    candidate_pdf_bytes = candidate_document.tobytes()
    candidate_document.close()
    artifact_bytes = {
        "candidate_tex": _fixture_syntax_tex_bytes(pages),
        "candidate_pdf": candidate_pdf_bytes,
        "compile_log": b"XeLaTeX pass 1: exit 0\nXeLaTeX pass 2: exit 0\n",
    }
    artifacts = {}
    for role, (filename, _compilation_field) in MODULE.ANALYSIS_ARTIFACT_SPECS.items():
        artifact_path = run_dir / filename
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(artifact_bytes[role])
        artifacts[role] = {
            "filename": filename,
            "bytes": artifact_path.stat().st_size,
            "sha256": MODULE._sha256_file(artifact_path),
        }
    compilation = {
        "status": "COMPILED",
        "successful_passes": 2,
        "pass_exit_codes": [0, 0],
        "compile_log_sha256": artifacts["compile_log"]["sha256"],
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "candidate_pdf_sha256": artifacts["candidate_pdf"]["sha256"],
    }
    timing = {
        "measurement": (
            "external monotonic wall clock started before browser upload/start click "
            "and stopped after VERIFIED"
        ),
        "started_at": "2026-08-24T00:00:00Z",
        "ended_at": "2026-08-24T02:00:00Z",
        "wall_time_seconds": 600,
        "timed_out": False,
        "completed_terminal_run": True,
    }
    reviews = [
        {
            "pass_number": 1,
            "review_id": "final-review-a",
            "context_id": "context-1",
            "context_sha256": MODULE.review_context_sha256(
                pass_number=1,
                context_id="context-1",
                candidate_tex_sha256=artifacts["candidate_tex"]["sha256"],
                checked_page_ids=page_ids,
            ),
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "expected_page_ids": list(page_ids),
            "checked_page_ids": list(page_ids),
            "checked_page_ids_sha256": MODULE.page_id_sequence_sha256(page_ids),
            "model_id": "gpt-5.4-mini",
            "backend": "codex_cli",
            "calls": pages,
        },
        {
            "pass_number": 2,
            "review_id": "final-review-b",
            "context_id": "context-2",
            "context_sha256": MODULE.review_context_sha256(
                pass_number=2,
                context_id="context-2",
                candidate_tex_sha256=artifacts["candidate_tex"]["sha256"],
                checked_page_ids=page_ids,
            ),
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "expected_page_ids": list(page_ids),
            "checked_page_ids": list(page_ids),
            "checked_page_ids_sha256": MODULE.page_id_sequence_sha256(page_ids),
            "model_id": "gpt-5.4-mini",
            "backend": "codex_cli",
            "calls": pages,
        },
    ]
    verification_report = {
        "schema_version": MODULE.ANALYSIS_MACHINE_VERIFICATION_SCHEMA,
        "result": "PASS",
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "pages_checked": pages,
        "silent_omissions": 0,
        "text_loss": 0,
        "unauthorized_math_changes": 0,
        "unclosed_formal_environments": 0,
        "open_critical_issues": 0,
        "open_high_issues": 0,
        "regressions": 0,
    }
    verification_path = run_dir / "analysis-machine-verification.json"
    _write_json(verification_path, verification_report)
    machine = {
        "passed": True,
        **{
            key: value
            for key, value in verification_report.items()
            if key not in {"schema_version", "result"}
        },
        "verification_json_sha256": MODULE._sha256_file(verification_path),
    }
    execution = {
        "real_execution": real_execution,
        "test_double": not real_execution,
        "simulated": not real_execution,
        "api_client": "LocalHttpApi",
        "ui_driver": "PlaywrightUiDriver",
        "workflow": "OCR_ANALYSIS_REVIEW",
        "producer": (
            "tools/v2_analysis_acceptance.py"
            if real_execution
            else "tests/fake_analysis_runner.py"
        ),
    }
    performance = {
        "schema_version": MODULE.ANALYSIS_PERFORMANCE_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": source,
        "selected_range": selected,
        "models": models,
        "compilation": compilation,
        "timing": timing,
        "thresholds": {"maximum_wall_time_seconds": None},
        "target_status": "NOT_EVALUATED",
        "target_met": None,
    }
    validation = {
        "schema_version": MODULE.ANALYSIS_VALIDATION_SCHEMA,
        "result": "PASS",
        "acceptance_passed": True,
        "runtime_identity": runtime,
        "source": source,
        "execution": execution,
        "terminal_status": terminal_status,
        "independent_final_reviews": reviews,
        "machine_verification": machine,
    }
    performance_path = run_dir / "analysis-performance.json"
    validation_path = run_dir / "analysis-validation-report.json"
    _write_json(performance_path, performance)
    _write_json(validation_path, validation)
    ocr_dir = _valid_run(
        run_dir,
        pages,
        # Keep the prerequisite independently real even when a test deliberately
        # marks only the outer analysis run as a test double.
        real_execution=True,
        executable_sha256=executable_sha256,
        source_sha256=source_sha256,
        build_id=build_id,
        run_dir_name="ocr-prerequisite",
    )
    nested_ocr_attestation = json.loads(
        (ocr_dir / "acceptance-attestation.json").read_text(encoding="utf-8")
    )
    nested_ocr_baseline = nested_ocr_attestation.get("ocr_baseline") or {}
    ocr_prerequisite = {
        "profile": "ocr-37",
        "attestation_filename": "ocr-prerequisite/acceptance-attestation.json",
        "attestation_sha256": MODULE._sha256_file(
            ocr_dir / "acceptance-attestation.json"
        ),
        "result": "PASS",
        "acceptance_passed": True,
        "successful_pages": pages,
        "source_sha256": source_sha256,
        "run_id": nested_ocr_baseline.get("run_id") or TEST_RUN_ID,
        "baseline_manifest_sha256": (
            nested_ocr_baseline.get("manifest_sha256") or "0" * 64
        ),
        "runtime_identity": runtime,
        "selected_range": selected,
    }
    snapshot_evidence_hashes = {
        name: MODULE._sha256_bytes(name.encode("utf-8"))
        for name in MODULE.ANALYSIS_EVIDENCE_HASH_FIELDS
    }
    nested_package = ocr_dir / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY
    nested_manifest = json.loads(
        (nested_package / MODULE.OCR_BASELINE_MANIFEST_MEMBER).read_text(
            encoding="utf-8"
        )
    )

    def nested_artifact_bytes(role: str) -> bytes:
        descriptor = next(
            artifact
            for artifact in nested_manifest["artifacts"]
            if artifact["role"] == role
        )
        return (nested_package / descriptor["path"]).read_bytes()

    nested_page_records_bytes = nested_artifact_bytes("PAGE_RECORDS")
    _ocr_run_id, page_records_source, nested_page_records = parse_page_records(
        nested_page_records_bytes
    )
    assert page_records_source == source_sha256
    assert len(nested_page_records) == pages
    snapshot_evidence_hashes["ocr_page_records_hash"] = MODULE._sha256_bytes(
        nested_page_records_bytes
    )
    verified_nested = MODULE.verify_run_attestation(
        ocr_dir,
        expected_pages=pages,
        version=VERSION,
        commit=COMMIT,
        expected_source_sha256=source_sha256,
    )
    verified_nested_baseline = verified_nested["ocr_baseline"]
    snapshot_evidence_hashes.update(
        verified_nested_baseline["recomputed_evidence_hashes"]
    )
    snapshot_evidence_hashes["build_identity_hash"] = (
        MODULE._canonical_json_sha256({
            "schema": "latexstruct-analysis-build-identity-v1",
            "ocr_producer": verified_nested_baseline["ocr_producer"],
            "analysis_runtime": {
                "app_version": VERSION,
                "build_id": runtime["build_id"],
                "commit": runtime["commit"],
                "prompt_version": "analysis-prompts-v2",
            },
        })
    )
    from latexstruct.core.analysis_risk import (
        PAGE_RISK_CLASSIFIER_POLICY,
        PageRiskPreflightInput,
        build_page_risk_admission,
    )
    from latexstruct.core.analysis_schema import (
        ANALYSIS_RESPONSE_SCHEMA_VERSIONS,
        PageRisk,
        PageRiskRouteClosure,
        PageRouteCallKey,
        PageRouteRecord,
        PageTriageOutcome,
    )

    source_pdf_bytes = nested_artifact_bytes("SOURCE")
    baseline_tex_bytes = nested_artifact_bytes("BASELINE_TEX")
    baseline_pdf_bytes = nested_artifact_bytes("BASELINE_PDF")
    runtime_page_records_bytes = nested_artifact_bytes("RUNTIME_PAGE_RECORDS")
    runtime_rows = json.loads(runtime_page_records_bytes)["pages"]
    with pymupdf.open(stream=source_pdf_bytes, filetype="pdf") as source_document:
        source_texts = [
            str(source_document.load_page(index).get_text("text") or "")
            for index in range(pages)
        ]
    baseline_regions = MODULE._tex_page_regions(
        baseline_tex_bytes.decode("utf-8"), range(1, pages + 1)
    )
    policy_versions = {
        name: PAGE_RISK_CLASSIFIER_POLICY[name]
        for name in (
            "feature_extractor_version",
            "visual_layout_algorithm_version",
            "machine_visual_algorithm_version",
            "compile_map_algorithm_version",
        )
    }
    preflight_inputs = []
    preflight_rows = []
    for page, (page_id, record, runtime_row) in enumerate(
        zip(page_ids, nested_page_records, runtime_rows, strict=True), 1
    ):
        candidate_ids = (f"candidate-page-{page:06d}",)
        layout_evidence = {
            "schema": "latexstruct-source-layout-preflight-v1",
            **policy_versions,
            "page": page,
            "double_column": False,
            "complex_layout": False,
        }
        compile_map_evidence = {
            "schema": "latexstruct-compile-map-preflight-v1",
            **policy_versions,
            "mapping_sha256": "7" * 64,
            "source_page_number": page,
            "candidate_page_numbers": [page],
            "mapping_complete": True,
            "mapping_in_range": True,
            "mismatch": False,
        }
        machine_visual_evidence = {
            "schema": "latexstruct-machine-visual-preflight-v1",
            **policy_versions,
            "page": page,
            "anomaly_codes": [],
        }
        quality_issues = tuple(runtime_row.get("quality_issues") or ())
        host_flags = tuple(runtime_row.get("host_quality_flags") or ())
        risk_input = PageRiskPreflightInput(
            source_page_id=page_id,
            source_page_number=page,
            source_page_object_hash=record.source_page_object_hash,
            ocr_coverage_checks=record.checks.to_dict(),
            unresolved_region_hashes=tuple(record.unresolved_region_hashes),
            baseline_tex_region=baseline_regions[page],
            candidate_pdf_page_ids=candidate_ids,
            source_pdf_text=source_texts[page - 1],
            ocr_final_status=record.final_status.value,
            ocr_retry_count=int(runtime_row.get("retry_count") or 0),
            ocr_quality_issues=quality_issues,
            host_quality_flags=host_flags,
            machine_visual_anomalies=(),
            double_column=False,
            complex_layout=False,
            compile_map_mismatch=False,
            layout_evidence=layout_evidence,
            compile_map_evidence=compile_map_evidence,
        )
        preflight_inputs.append(risk_input)
        preflight_rows.append({
            "source_page_id": page_id,
            "source_page_number": page,
            "source_page_object_hash": record.source_page_object_hash,
            "ocr_page_id": record.page_id,
            "ocr_coverage_checks": record.checks.to_dict(),
            "unresolved_region_hashes": list(record.unresolved_region_hashes),
            "ocr_final_status": record.final_status.value,
            "ocr_retry_count": int(runtime_row.get("retry_count") or 0),
            "ocr_quality_issues": list(quality_issues),
            "host_quality_flags": list(host_flags),
            "candidate_pdf_page_ids": list(candidate_ids),
            "source_pdf_text_sha256": MODULE._sha256_bytes(
                source_texts[page - 1].encode("utf-8")
            ),
            "baseline_tex_region_sha256": MODULE._sha256_bytes(
                baseline_regions[page].encode("utf-8")
            ),
            "machine_visual_anomalies": [],
            "machine_visual_evidence": machine_visual_evidence,
            "double_column": False,
            "complex_layout": False,
            "layout_evidence": layout_evidence,
            "compile_map_mismatch": False,
            "compile_map_evidence": compile_map_evidence,
        })
    admission = build_page_risk_admission(
        source_pdf_sha256=source_sha256,
        ocr_page_records_sha256=snapshot_evidence_hashes[
            "ocr_page_records_hash"
        ],
        ocr_runtime_page_records_sha256=snapshot_evidence_hashes[
            "ocr_runtime_page_records_hash"
        ],
        baseline_tex_sha256=MODULE._sha256_bytes(baseline_tex_bytes),
        baseline_pdf_sha256=MODULE._sha256_bytes(baseline_pdf_bytes),
        page_inputs=tuple(preflight_inputs),
    )
    page_risk_payload = admission.to_dict()
    page_risk_sha = admission.digest
    snapshot_evidence_hashes["page_risk_admission_hash"] = page_risk_sha
    risk_preflight = {
        "schema": "latexstruct-analysis-risk-preflight-inputs-v2",
        "source_pdf_sha256": source_sha256,
        "baseline_tex_sha256": MODULE._sha256_bytes(baseline_tex_bytes),
        "baseline_pdf_sha256": MODULE._sha256_bytes(baseline_pdf_bytes),
        "ocr_page_records_sha256": snapshot_evidence_hashes[
            "ocr_page_records_hash"
        ],
        "ocr_runtime_page_records_sha256": snapshot_evidence_hashes[
            "ocr_runtime_page_records_hash"
        ],
        "inputs": preflight_rows,
    }
    risk_preflight["preflight_sha256"] = MODULE._canonical_json_sha256(
        risk_preflight
    )
    snapshot_hash = "5" * 64
    sampled_low_risk = set(admission.low_risk_sampling.selected_page_ids)
    route_specs = [
        ("AI-3", "visual-triage", page_id) for page_id in page_ids
    ]
    for admitted_page in admission.pages:
        page_id = admitted_page.summary.source_page_id
        if (
            admitted_page.risk_level in {PageRisk.R1, PageRisk.R2}
            or page_id in sampled_low_risk
        ):
            route_specs.append(("AI-1", "structure-findings", page_id))
        if (
            admitted_page.risk_level is PageRisk.R2
            or page_id in sampled_low_risk
        ):
            route_specs.extend((
                ("AI-2", "content-math-findings", page_id),
                ("AI-3", "visual-findings", page_id),
            ))
    for pass_number in (1, 2):
        route_specs.extend(
            ("AI-5", f"final-review-{pass_number}", page_id)
            for page_id in page_ids
        )
    route_call_keys = tuple(sorted(
        (
            PageRouteCallKey(
                role=role,
                operation=operation,
                source_page_id=page_id,
                candidate_hash=artifacts["candidate_tex"]["sha256"],
                issue_id="DISCOVERY-fixture",
                snapshot_hash=snapshot_hash,
                response_schema_version=(
                    ANALYSIS_RESPONSE_SCHEMA_VERSIONS[operation]
                ),
                succeeded=True,
            )
            for role, operation, page_id in route_specs
        ),
        key=lambda item: (
            item.role,
            item.operation,
            item.source_page_id,
            item.candidate_hash,
            item.issue_id,
        ),
    ))
    route_closure = PageRiskRouteClosure(
        admission_sha256=admission.digest,
        final_candidate_hash=artifacts["candidate_tex"]["sha256"],
        pages=tuple(
            PageRouteRecord(
                source_page_id=page.summary.source_page_id,
                source_page_number=page.summary.source_page_number,
                admitted_risk=page.risk_level,
                triage_outcome=PageTriageOutcome.CLEAR,
                triage_response_sha256=MODULE._sha256_bytes(
                    f"triage:{page.summary.source_page_id}".encode("utf-8")
                ),
                effective_risk=page.risk_level,
                modified=False,
                anomaly_reasons=(),
                sampled_low_risk=(
                    page.summary.source_page_id in sampled_low_risk
                ),
                deep_review_required=(
                    page.risk_level is PageRisk.R2
                    or page.summary.source_page_id in sampled_low_risk
                ),
                final_candidate_hash=artifacts["candidate_tex"]["sha256"],
            )
            for page in admission.pages
        ),
        route_call_keys=route_call_keys,
    )
    transport_count = len(route_call_keys)
    ai1_calls = sum(call.role == "AI-1" for call in route_call_keys)
    analysis_calls = sum(
        call.role in {"AI-2", "AI-3"} for call in route_call_keys
    )
    review_calls = sum(call.role == "AI-5" for call in route_call_keys)
    models = {
        "calls_total": transport_count,
        "roles": [
            {
                "role": "structure",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": ai1_calls,
            },
            {
                "role": "analysis",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": analysis_calls,
            },
            {
                "role": "visual_review",
                "model_id": "gpt-5.4-mini",
                "backend": "codex_cli",
                "calls": review_calls,
            },
        ],
    }
    performance["models"] = models
    _write_json(performance_path, performance)
    budget_limits = {
        "max_input_tokens": 100_000,
        "max_output_tokens": 100_000,
        "max_cost": 0.0,
        "max_requests": 1_000,
        "max_strong_model_calls": 0,
        "max_wall_time_minutes": 120.0,
    }
    budget_usage = {
        "observed": {
            "input_tokens": transport_count * 10,
            "output_tokens": transport_count * 5,
            "cost": 0.0,
        },
        "actual": {
            "input_tokens": transport_count * 10,
            "output_tokens": transport_count * 5,
            "cost": None,
        },
        "accounted": {
            "input_tokens": transport_count * 10,
            "output_tokens": transport_count * 5,
            "cost": 0.0,
        },
        "requests": transport_count,
        "strong_model_calls": 0,
        "unknown": {
            "input_token_requests": 0,
            "output_token_requests": 0,
            "cost_requests": transport_count,
        },
        "committed_reservations": transport_count,
        "cancelled_reservations": 0,
        "wall_time_minutes": 2.0,
    }
    budget_state = {
        "schema_version": "analysis-budget-v1",
        "limits": budget_limits,
        "usage": budget_usage,
        "low_priority_threshold": 0.9,
        "stop_reason": None,
        "stop_details": [],
        "unbounded_unknown_dimensions": [],
        "reservations": [],
    }
    model_bindings = [
        {
            "role": f"AI-{index}",
            "model_id": "gpt-5.4-mini",
            "capabilities": [],
            "reasoning_effort": "high",
        }
        for index in range(1, 7)
    ]
    transport_contracts = [
        {
            "role": model["role"],
            "model_id": model["model_id"],
            "reasoning_effort": model["reasoning_effort"],
            "operations": sorted(
                operation
                for operation, role in MODULE.ANALYSIS_OPERATION_ROLES.items()
                if role == model["role"]
            ),
            "client_type": "latexstruct.core.codex_cli.CodexCLIClient",
            "method": (
                "chat_vision_json_images_bytes"
                if model["role"] in {"AI-3", "AI-5"}
                else "chat_json_schema"
            ),
            "max_retries": 0,
            "max_tokens": 20,
            "backend_authority_sha256": (
                MODULE.ANALYSIS_STABLE_BACKEND_AUTHORITY_SHA256
            ),
            "backend_configuration_sha256": (
                MODULE.ANALYSIS_STABLE_BACKEND_CONFIGURATION_SHA256
            ),
        }
        for model in model_bindings
    ]
    native_input = load_ocr_analysis_input_package(
        nested_package,
        expected_source_sha256=source_sha256,
        expected_manifest_sha256=str(
            verified_nested_baseline["manifest_sha256"]
        ),
        expected_run_id=str(verified_nested_baseline["run_id"]),
        expected_selected_pages=tuple(range(1, pages + 1)),
    )
    fixture_routes = parse_lane_routes_artifact(
        native_input.artifacts_by_role["LANE_ROUTES"].data,
        expected_run_id=native_input.run_id,
        expected_selected_pages=native_input.snapshot.selected_pages,
    )
    fixture_page_bindings = parse_ocr_page_evidence_bindings(
        native_input.artifacts_by_role["OCR_PAGE_EVIDENCE_BINDINGS"].data,
        expected_run_id=native_input.run_id,
        expected_source_sha256=native_input.source_sha256,
        expected_selected_pages=native_input.snapshot.selected_pages,
    )
    fixture_snapshot_pages = {
        row["page_id"]: row
        for row in native_input.snapshot.pipeline_contract["page_strategies"]
    }
    fixture_cross_rows = []
    fixture_event_rows = []
    for route, binding in zip(
        fixture_routes, fixture_page_bindings, strict=True
    ):
        snapshot_page = fixture_snapshot_pages[route.page_id]
        block_page = native_input.block_inventory.pages_by_id[route.page_id]
        fixture_cross_rows.append({
            "page_id": route.page_id,
            "source_page": route.source_page,
            "initial_candidate_tex_sha256": snapshot_page[
                "candidate_tex_sha256"
            ],
            "visual_verification_response_sha256": (
                binding.visual_verification_response_sha256
            ),
            "terminal_cleaned_tex_sha256": (
                binding.terminal_cleaned_tex_sha256
            ),
            "route_sha256": route.route_sha256,
            "source_page_object_hash": block_page.source_page_object_hash,
            "source_text_layer_sha256": block_page.source_text_layer_sha256,
        })
        fixture_event_rows.append({
            "page_id": route.page_id,
            "event_sha256s": [event.event_sha256 for event in route.history],
        })
    fixture_route_page_bindings_sha256 = _sha(
        canonical_json_bytes(fixture_cross_rows)
    )
    fixture_route_event_chain_sha256 = _sha(
        canonical_json_bytes(fixture_event_rows)
    )
    native_source_blocks = [dict(item) for item in native_input.native_source_blocks]
    inventory_authorizations = build_host_inventory_authorizations(
        native_source_blocks,
        ocr_manifest_sha256=native_input.manifest_sha256,
        generated_toc_required=True,
    )
    inventory_authorization_payload = [
        item.as_dict() for item in inventory_authorizations
    ]
    inventory_source_page_map = {
        int(page): tuple(pdf_pages)
        for page, pdf_pages in native_input.source_page_map.items()
    }
    baseline_inventory = build_analysis_inventory_bundle(
        baseline_tex_bytes.decode("utf-8"),
        baseline_tex_bytes.decode("utf-8"),
        inventory_source_page_map,
        native_source_blocks=native_source_blocks,
        authorizations=inventory_authorizations,
        require_native_heading_inventory=True,
    )
    final_inventory = build_analysis_inventory_bundle(
        baseline_tex_bytes.decode("utf-8"),
        artifact_bytes["candidate_tex"].decode("utf-8"),
        inventory_source_page_map,
        native_source_blocks=native_source_blocks,
        authorizations=inventory_authorizations,
        require_native_heading_inventory=True,
    )
    inventory_gate = evaluate_analysis_inventory_gate(final_inventory)
    assert inventory_gate.passed is True
    baseline_inventory_bytes = canonical_json_bytes(baseline_inventory.as_dict())
    final_inventory_bytes = canonical_json_bytes(final_inventory.as_dict())
    inventory_gate_bytes = canonical_json_bytes(inventory_gate.as_dict())
    analysis_configuration = {
        "workflow_version": "analysis-loop-v2",
        "prompt_version": "analysis-prompts-v2",
        "application_version": VERSION,
        "latex_engine": "xelatex",
        "concurrency_limit": 3,
        "models": model_bindings,
        "transport_contracts": transport_contracts,
        "page_range": list(range(1, pages + 1)),
        "candidate_page_map": [
            [page, list(pdf_pages)]
            for page, pdf_pages in inventory_source_page_map.items()
        ],
        "candidate_storage_name": "candidate.tex",
        "raw_ocr_frozen": True,
        "page_risks": [
            {
                "source_page_number": page.summary.source_page_number,
                "risk_level": page.risk_level.value,
                "risk_reasons": list(page.risk_reasons),
            }
            for page in admission.pages
        ],
        "page_risk_admission": admission.canonical_payload(),
        "page_risk_admission_hash": admission.digest,
        "page_risk_source_admission_hash": admission.digest,
        "baseline_inventory_digest": baseline_inventory.digest,
        "baseline_inventory_json_sha256": _sha(baseline_inventory_bytes),
        "native_source_blocks": native_source_blocks,
        "native_source_blocks_supplied": True,
        "inventory_authorizations": inventory_authorization_payload,
        "inventory_authorization_source": "HOST_REQUIRED_POLICY",
        "inventory_policy_schema": "latexstruct-host-inventory-policy-v1",
        "inventory_policy_ocr_manifest_sha256": native_input.manifest_sha256,
        "native_heading_inventory_required": True,
        "compile_extra_files": [],
        "max_macro_rounds": 3,
        **budget_limits,
    }
    analysis_configuration_sha256 = MODULE._canonical_json_sha256(
        analysis_configuration
    )
    snapshot_evidence_hashes["analysis_config_hash"] = (
        analysis_configuration_sha256
    )
    ledger_roles = [call.role for call in route_call_keys]
    transport_budget_ledger = [
        {
            "ordinal": ordinal,
            "role": role,
            "budget_claim": {
                "input_tokens": 100,
                "output_tokens": 20,
                "cost": 0.0,
                "requests": 1,
                "strong_model_calls": 0,
            },
            "budget_actual_usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cost": None,
            },
            "attempts": [{
                "attempt_number": 1,
                "succeeded": True,
                "usage_complete": True,
                "failure_stage": "",
                "input_tokens": 10,
                "output_tokens": 5,
                "cached_tokens": 2,
                "billing_mode": "chatgpt_subscription",
                "cost": None,
                "cost_provenance": "chatgpt_subscription",
            }],
        }
        for ordinal, role in enumerate(ledger_roles, 1)
    ]
    runtime_model_configuration = {
        "analysis_backend": "codex_cli",
        "codex_model": "gpt-5.4-mini",
        "codex_reasoning_effort": "high",
        "codex_triage_model": "gpt-5.4-mini",
        "codex_triage_reasoning_effort": "high",
    }
    release_model_policy = {
        "schema_version": MODULE.ANALYSIS_RELEASE_MODEL_POLICY_SCHEMA,
        "declared_model_id": "gpt-5.4-mini",
        "declared_reasoning_effort": "high",
        "runtime_configuration": runtime_model_configuration,
        "runtime_configuration_sha256": MODULE._canonical_json_sha256(
            runtime_model_configuration
        ),
        "model_bindings_sha256": MODULE._canonical_json_sha256(model_bindings),
        "transport_contracts_sha256": MODULE._canonical_json_sha256(
            transport_contracts
        ),
        "runtime_matches_declared": True,
        "all_role_bindings_match_declared": True,
        "all_transport_contracts_match_declared": True,
        "allowed_by_release": True,
    }
    snapshot_binding = {
        "snapshot_hash": snapshot_hash,
        "prompt_version": "analysis-prompts-v2",
        "response_schema_hash": snapshot_evidence_hashes["response_schema_hash"],
        "evidence_hashes": snapshot_evidence_hashes,
        "model_bindings": model_bindings,
        "model_bindings_sha256": MODULE._canonical_json_sha256(model_bindings),
        "transport_contracts_sha256": MODULE._canonical_json_sha256(
            transport_contracts
        ),
        "analysis_configuration": analysis_configuration,
        "analysis_configuration_sha256": analysis_configuration_sha256,
        "release_model_policy": release_model_policy,
        "transport_invocation_count": transport_count,
        "transport_closure": {
            "schema_version": MODULE.ANALYSIS_TRANSPORT_CLOSURE_SCHEMA,
            "transport_evidence_sha256": "6" * 64,
            "orchestration_invocation_count": transport_count,
            "transport_invocation_count": transport_count,
            "transport_attempt_count": transport_count,
            "usage_observed_call_count": transport_count,
            "usage_observed_attempt_count": transport_count,
            "usage_missing_call_count": 0,
            "usage_missing_attempt_count": 0,
            "input_tokens": transport_count * 10,
            "output_tokens": transport_count * 5,
            "cached_tokens": transport_count * 2,
            "total_tokens": transport_count * 15,
            "usage_complete": True,
            "attempt_evidence_complete": True,
            "budget_closure": {
                "schema_version": MODULE.ANALYSIS_BUDGET_CLOSURE_SCHEMA,
                "budget_state_sha256": MODULE._canonical_json_sha256(
                    budget_state
                ),
                "budget_state": budget_state,
                "budget_usage_sha256": MODULE._canonical_json_sha256(
                    budget_usage
                ),
                "budget_usage": budget_usage,
                "limits_sha256": MODULE._canonical_json_sha256(budget_limits),
                "limits": budget_limits,
                "transport_contracts_sha256": MODULE._canonical_json_sha256(
                    transport_contracts
                ),
                "transport_contracts": transport_contracts,
                "transport_budget_ledger_sha256": MODULE._canonical_json_sha256(
                    transport_budget_ledger
                ),
                "transport_budget_ledger": transport_budget_ledger,
                "observed": budget_usage["observed"],
                "actual": budget_usage["actual"],
                "accounted": budget_usage["accounted"],
                "requests": transport_count,
                "strong_model_calls": 0,
                "unknown": budget_usage["unknown"],
                "transport_claim_count": transport_count,
                "committed_reservations": transport_count,
                "cancelled_reservations": 0,
                "active_reservations": 0,
                "wall_time_minutes": budget_usage["wall_time_minutes"],
                "unbounded_unknown_dimensions": [],
                "all_claims_verified": True,
                "all_actual_usage_verified": True,
                "exact_aggregate_verified": True,
            },
        },
        "all_transport_bindings_verified": True,
    }
    page_ids_sha = MODULE.page_id_sequence_sha256(page_ids)
    page_risk_admission = {
        "schema_version": MODULE.ANALYSIS_PAGE_RISK_CLOSURE_SCHEMA,
        "admission_sha256": page_risk_sha,
        "admission": page_risk_payload,
        "preflight_sha256": risk_preflight["preflight_sha256"],
        "preflight": risk_preflight,
        "route_closure_sha256": route_closure.digest,
        "route_closure": route_closure.to_dict(),
        "page_count": pages,
        "page_ids_sha256": page_ids_sha,
        "risk_counts": route_closure.risk_counts,
        "low_risk_sampling": admission.low_risk_sampling.canonical_payload(),
        "all_preflight_bindings_verified": True,
        "all_route_bindings_verified": True,
    }
    closed_loop_evidence = {
        "schema_version": MODULE.RENDER_COMPARE_CLOSED_LOOP_SCHEMA,
        "branch": "NO_FIX_NEEDED",
        "detected_issue_count": 0,
        "fixed_issue_count": 0,
        "rejected_false_positive_count": 0,
        "fixes": [],
        "final_review_context_sha256s": [
            review["context_sha256"] for review in reviews
        ],
        "final_candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "final_candidate_pdf_sha256": artifacts["candidate_pdf"]["sha256"],
    }
    closed_loop_evidence["evidence_sha256"] = MODULE._canonical_json_sha256(
        closed_loop_evidence
    )
    visual_verification = {
        "passed": True,
        "expected_pages": pages,
        "pages_checked": pages,
        "independent_review_passes": 2,
        "model_calls": pages * 2,
        "page_id_set_sha256": MODULE.page_id_sequence_sha256(page_ids),
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "candidate_pdf_sha256": artifacts["candidate_pdf"]["sha256"],
        "render_compare_closed_loop": True,
        "closed_loop_evidence": closed_loop_evidence,
    }
    candidate_mapping = MODULE.build_candidate_page_mapping(
        source_page_count=37,
        candidate_page_count=38,
        candidate_tex_sha256=artifacts["candidate_tex"]["sha256"],
        candidate_pdf_sha256=artifacts["candidate_pdf"]["sha256"],
        upstream_mapping_sha256="4" * 64,
        canonical_rows=[
            {"source_page": page, "candidate_pages": [page + 1]}
            for page in range(1, 38)
        ],
        candidate_only_pages=[1],
    )
    page_layout = {
        "source_page_count": 37,
        "candidate_page_count": 38,
        "minimum_candidate_pages": 32,
        "maximum_candidate_pages": 42,
        "page_growth": 1,
        "candidate_only_pages": [1],
        "candidate_mapping_sha256": candidate_mapping["mapping_sha256"],
        "candidate_mapping": candidate_mapping,
        "no_abnormal_page_inflation": True,
        "active_tableofcontents_count": 1,
        "template": "faithfulbook",
    }
    final_decision = {
        "status": "VERIFIED",
        "verified": True,
        "failures": [],
        "best_candidate_id": "candidate-final-fixture",
        "baseline_inventory_digest": baseline_inventory.digest,
        "baseline_inventory_json_sha256": _sha(baseline_inventory_bytes),
        "final_inventory_digest": final_inventory.digest,
        "final_inventory_json_sha256": _sha(final_inventory_bytes),
        "inventory_gate_digest": inventory_gate.digest,
        "inventory_gate_json_sha256": _sha(inventory_gate_bytes),
        "inventory_gate_status": inventory_gate.status.value,
    }
    audit_role_members = {
        "BASELINE_TEX": ("audit/baseline.tex", baseline_tex_bytes),
        "CURRENT_TEX": (
            "audit/current.tex",
            artifact_bytes["candidate_tex"],
        ),
        "ANALYSIS_CONFIGURATION": (
            "audit/analysis_configuration.json",
            canonical_json_bytes(analysis_configuration),
        ),
        "ANALYSIS_INVENTORY_BASELINE": (
            "audit/analysis_inventory_baseline.json",
            baseline_inventory_bytes,
        ),
        "ANALYSIS_INVENTORY_FINAL": (
            "audit/analysis_inventory_final.json",
            final_inventory_bytes,
        ),
        "ANALYSIS_INVENTORY_GATE": (
            "audit/analysis_inventory_gate.json",
            inventory_gate_bytes,
        ),
        "FINAL_DECISION": (
            "audit/final_decision.json",
            canonical_json_bytes(final_decision),
        ),
    }
    audit_members = {
        member: payload for member, payload in audit_role_members.values()
    }
    submission_manifest = {
        "schema_version": "latexstruct-ai-audit-submission-fixture-v1",
        "artifacts": [
            {
                "artifact_role": role,
                "path": member,
                "byte_count": len(payload),
                "bytes_sha256": _sha(payload),
                "aliases": [],
            }
            for role, (member, payload) in audit_role_members.items()
        ],
    }
    audit_members["submission_manifest.json"] = canonical_json_bytes(
        submission_manifest
    )
    audit_members["audit/packaging-integrity.json"] = canonical_json_bytes({
        "valid": True,
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
    })
    audit_members["audit/SHA256SUMS"] = "".join(
        f"{_sha(payload)}  {member}\n"
        for member, payload in sorted(audit_members.items())
    ).encode("utf-8")
    audit_path = run_dir / "analysis-audit-submission.zip"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(audit_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member, payload in sorted(audit_members.items()):
            archive.writestr(member, payload)
    audit_submission = {
        "filename": audit_path.name,
        "bytes": audit_path.stat().st_size,
        "sha256": MODULE._sha256_file(audit_path),
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
        "verification_status": "VERIFIED",
        "published_to_github": False,
    }
    analysis_inventory = {
        "schema_version": MODULE.ANALYSIS_INVENTORY_RELEASE_CLOSURE_SCHEMA,
        "result": "PASS",
        "analysis_configuration_sha256": analysis_configuration_sha256,
        "ocr_baseline_manifest_sha256": native_input.manifest_sha256,
        "baseline_tex_sha256": _sha(baseline_tex_bytes),
        "final_candidate_tex_sha256": _sha(artifact_bytes["candidate_tex"]),
        "page_map_digest": baseline_inventory.page_map_digest,
        "native_source_blocks_digest": baseline_inventory.as_dict()[
            "native_source_blocks_digest"
        ],
        "inventory_authorizations_sha256": _sha(
            canonical_json_bytes(inventory_authorization_payload)
        ),
        "baseline_inventory_digest": baseline_inventory.digest,
        "baseline_inventory_json_sha256": _sha(baseline_inventory_bytes),
        "final_inventory_digest": final_inventory.digest,
        "final_inventory_json_sha256": _sha(final_inventory_bytes),
        "inventory_gate_digest": inventory_gate.digest,
        "inventory_gate_json_sha256": _sha(inventory_gate_bytes),
        "inventory_gate_status": "PASS",
        "scanner_executed": True,
        "residual_total": 0,
        "blocked_categories": [],
        "ocr_manifest_roles": {
            "lane_routes": {
                "role": "LANE_ROUTES",
                "sha256": native_input.lane_routes_sha256,
                "status": "PASS",
                "page_count": len(fixture_routes),
                "event_count": sum(
                    len(route.history) for route in fixture_routes
                ),
                "page_bindings_sha256": (
                    fixture_route_page_bindings_sha256
                ),
                "event_chain_sha256": fixture_route_event_chain_sha256,
            },
            "page_evidence_bindings": {
                "role": "OCR_PAGE_EVIDENCE_BINDINGS",
                "sha256": native_input.artifact_sha256s[
                    "OCR_PAGE_EVIDENCE_BINDINGS"
                ],
                "status": "PASS",
                "page_count": len(fixture_page_bindings),
                "cross_binding_sha256": (
                    fixture_route_page_bindings_sha256
                ),
            },
            "evidence_correction_report": {
                "role": "EVIDENCE_CORRECTION_REPORT",
                "sha256": native_input.evidence_correction_report_sha256,
                "status": native_input.evidence_correction_status,
            },
            "block_inventory": {
                "role": "OCR_BLOCK_INVENTORY",
                "sha256": native_input.block_inventory_sha256,
                "status": "PASS",
                "page_count": len(native_input.block_inventory.pages),
                "block_count": len(native_input.native_source_blocks),
            },
        },
    }
    attestation = {
        "schema_version": MODULE.ANALYSIS_ATTESTATION_SCHEMA,
        "profile_kind": "analysis",
        "profile": f"analysis-{pages}",
        "result": "PASS",
        "acceptance_passed": True,
        "terminal_status": terminal_status,
        "quality_tier": "high",
        "template": "faithfulbook",
        "generated_at": "2026-08-24T02:00:00Z",
        "execution": execution,
        "runtime_identity": runtime,
        "service_binding": {
            "verified": True,
            "pid": 1234,
            "process_image_filename": "LaTeXStruct.exe",
            "process_image_sha256": executable_sha256,
            "listener_port": 8080,
            "listener_pid": 1234,
            "listener_pid_verified": True,
            "listener_image_filename": "LaTeXStruct.exe",
            "listener_image_sha256": executable_sha256,
        },
        "snapshot_binding": snapshot_binding,
        "page_risk_admission": page_risk_admission,
        "source": source,
        "selected_range": selected,
        "models": models,
        "compilation": compilation,
        "artifacts": artifacts,
        "timing": timing,
        "ocr_prerequisite": ocr_prerequisite,
        "independent_final_reviews": reviews,
        "visual_verification": visual_verification,
        "page_layout": page_layout,
        "analysis_inventory": analysis_inventory,
        "machine_verification": machine,
        "audit_submission": audit_submission,
        "reports": {
            "performance": {
                "filename": "analysis-performance.json",
                "sha256": MODULE._sha256_file(performance_path),
            },
            "validation": {
                "filename": "analysis-validation-report.json",
                "sha256": MODULE._sha256_file(validation_path),
            },
            "verification": {
                "filename": "analysis-machine-verification.json",
                "sha256": MODULE._sha256_file(verification_path),
            },
        },
    }
    _write_json(run_dir / "analysis-attestation.json", attestation)
    return run_dir


def _candidate_release_fixture(
    tmp_path: Path,
    *,
    private_publication_sentinels: bool = False,
) -> dict[str, Path]:
    executable = tmp_path / "candidate-inputs" / "LaTeXStruct.exe"
    license_file = tmp_path / "candidate-inputs" / "LICENSE"
    notices_file = tmp_path / "candidate-inputs" / "THIRD_PARTY_NOTICES.txt"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"MZ-analysis-37-tested")
    license_file.write_text("license", encoding="utf-8")
    notices_file.write_text("notices", encoding="utf-8")
    executable_sha = MODULE._sha256_file(executable)

    candidate_dir = tmp_path / "candidate-artifact"
    candidate_dir.mkdir()
    portable = candidate_dir / f"LaTeXStruct-portable-{VERSION}.zip"
    setup = candidate_dir / f"LaTeXStruct-setup-{VERSION}.exe"
    MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices_file,
        output=portable,
    )
    setup.write_bytes(b"MZ-tested-setup-wrapper")
    assets_manifest = candidate_dir / "release-assets.json"
    checksums = candidate_dir / "SHA256SUMS.txt"
    MODULE.write_asset_manifest(
        assets=[portable, setup],
        version=VERSION,
        commit=COMMIT,
        build_id="200",
        output=assets_manifest,
        checksums_output=checksums,
    )

    attestation = tmp_path / "release" / "release-attestation.json"
    analysis_run = _valid_analysis_run(
        tmp_path / "analysis37", 37, executable_sha256=executable_sha
    )
    if private_publication_sentinels:
        _inject_private_publication_sentinels(analysis_run)
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": analysis_run},
        output=attestation,
    )
    return {
        "attestation": attestation,
        "candidate_dir": candidate_dir,
        "portable": portable,
        "setup": setup,
        "assets_manifest": assets_manifest,
        "checksums": checksums,
    }


def test_portable_archive_has_exact_root_license_and_notice_bytes(tmp_path: Path):
    executable = tmp_path / "LaTeXStruct.exe"
    license_file = tmp_path / "LICENSE"
    notices = tmp_path / "THIRD_PARTY_NOTICES.txt"
    executable.write_bytes(b"MZ-test")
    license_file.write_text("project license", encoding="utf-8")
    notices.write_text("third party notices", encoding="utf-8")
    output = tmp_path / "portable.zip"

    digests = MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices,
        output=output,
    )

    with zipfile.ZipFile(output) as archive:
        assert archive.namelist() == [
            "LaTeXStruct.exe",
            "LICENSE",
            "THIRD_PARTY_NOTICES.txt",
        ]
        assert archive.read("LICENSE") == b"project license"
        assert archive.read("THIRD_PARTY_NOTICES.txt") == b"third party notices"
    assert digests["LaTeXStruct.exe"] == _sha(b"MZ-test")


def test_asset_manifest_and_sha256sums_are_generated_from_final_bytes(tmp_path: Path):
    portable = tmp_path / "LaTeXStruct-portable-2.0.0.zip"
    setup = tmp_path / "LaTeXStruct-setup-2.0.0.exe"
    portable.write_bytes(b"portable")
    setup.write_bytes(b"setup")

    manifest = MODULE.write_asset_manifest(
        assets=[portable, setup],
        version=VERSION,
        commit=COMMIT,
        build_id="12345",
        output=tmp_path / "release-assets.json",
        checksums_output=tmp_path / "SHA256SUMS.txt",
    )

    by_name = {item["filename"]: item for item in manifest["assets"]}
    assert by_name[portable.name]["sha256"] == _sha(b"portable")
    assert by_name[setup.name]["sha256"] == _sha(b"setup")
    sums = (tmp_path / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert f"{_sha(b'portable')}  {portable.name}" in sums
    assert f"{_sha(b'setup')}  {setup.name}" in sums


def test_tag_release_reuses_and_verifies_exact_attested_candidate_bytes(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path)

    verified = MODULE.verify_candidate_release_assets(
        manifest=fixture["attestation"],
        version=VERSION,
        commit=COMMIT,
        assets_manifest=fixture["assets_manifest"],
        checksums=fixture["checksums"],
        assets_dir=fixture["candidate_dir"],
    )

    assert verified["build_id"] == "200"
    assert verified["tested_executable_sha256"] == _sha(
        b"MZ-analysis-37-tested"
    )
    assert verified["portable_executable_sha256"] == verified[
        "tested_executable_sha256"
    ]
    assert {item["filename"] for item in verified["assets"]} == {
        f"LaTeXStruct-portable-{VERSION}.zip",
        f"LaTeXStruct-setup-{VERSION}.exe",
    }
    assert (
        MODULE.main(
            [
                "verify-candidate-assets",
                "--manifest",
                str(fixture["attestation"]),
                "--version",
                VERSION,
                "--commit",
                COMMIT,
                "--assets-manifest",
                str(fixture["assets_manifest"]),
                "--checksums",
                str(fixture["checksums"]),
                "--assets-dir",
                str(fixture["candidate_dir"]),
            ]
        )
        == 0
    )


def test_candidate_asset_verification_rejects_tampering_and_wrong_run_identity(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path / "tampered")
    fixture["setup"].write_bytes(b"MZ-replaced-after-acceptance")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="byte count mismatch"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "extra-file")
    (fixture["candidate_dir"] / "unreviewed.exe").write_bytes(b"MZ-extra")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="exactly portable"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "wrong-run")
    payload = json.loads(fixture["assets_manifest"].read_text(encoding="utf-8"))
    payload["build_id"] = "201"
    _write_json(fixture["assets_manifest"], payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="build id differs"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )


def test_candidate_asset_verification_recomputes_checksums_and_portable_exe(
    tmp_path: Path,
):
    fixture = _candidate_release_fixture(tmp_path / "checksums")
    fixture["checksums"].write_text("0" * 64 + "  forged.exe\n", encoding="utf-8")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="SHA256SUMS"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )

    fixture = _candidate_release_fixture(tmp_path / "wrong-exe")
    bad_executable = tmp_path / "wrong-exe" / "bad.exe"
    bad_executable.write_bytes(b"MZ-not-four-profile-tested")
    MODULE.build_portable_archive(
        executable=bad_executable,
        license_file=tmp_path / "wrong-exe" / "candidate-inputs" / "LICENSE",
        notices_file=(
            tmp_path
            / "wrong-exe"
            / "candidate-inputs"
            / "THIRD_PARTY_NOTICES.txt"
        ),
        output=fixture["portable"],
    )
    MODULE.write_asset_manifest(
        assets=[fixture["portable"], fixture["setup"]],
        version=VERSION,
        commit=COMMIT,
        build_id="200",
        output=fixture["assets_manifest"],
        checksums_output=fixture["checksums"],
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="strict analysis-37 run"):
        MODULE.verify_candidate_release_assets(
            manifest=fixture["attestation"],
            version=VERSION,
            commit=COMMIT,
            assets_manifest=fixture["assets_manifest"],
            checksums=fixture["checksums"],
            assets_dir=fixture["candidate_dir"],
        )


def test_release_attestation_requires_numeric_github_run_id(tmp_path: Path):
    with pytest.raises(MODULE.ReleaseIntegrityError, match="numeric GitHub Actions"):
        MODULE.verify_run_attestation(
            _valid_run(tmp_path, 17, build_id="build-200"),
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )


def test_ocr_37_release_gate_accepts_only_the_recomputable_package(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 37)
    verified = MODULE.verify_run_attestation(
        run_dir,
        expected_pages=37,
        version=VERSION,
        commit=COMMIT,
        expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
    )
    assert {
        key: verified["ocr_baseline"][key]
        for key in (
            "package_directory",
            "manifest_filename",
            "manifest_sha256",
            "run_id",
        )
    } == {
        "package_directory": MODULE.OCR_BASELINE_PACKAGE_DIRECTORY,
        "manifest_filename": (
            f"{MODULE.OCR_BASELINE_PACKAGE_DIRECTORY}/"
            f"{MODULE.OCR_BASELINE_MANIFEST_MEMBER}"
        ),
        "manifest_sha256": verified["ocr_baseline"]["manifest_sha256"],
        "run_id": TEST_RUN_ID,
    }

    legacy_attestation = json.loads(
        (run_dir / "acceptance-attestation.json").read_text(encoding="utf-8")
    )
    legacy_attestation.pop("ocr_baseline")
    _write_json(run_dir / "acceptance-attestation.json", legacy_attestation)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="recomputable baseline"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


@pytest.mark.parametrize(
    "member",
    (
        "evidence/page-records.json",
        "baseline/page-map.json",
        "compile/pass-02.log",
    ),
)
def test_ocr_37_release_gate_rejects_tampered_package_files(
    tmp_path: Path,
    member: str,
):
    run_dir = _valid_run(tmp_path, 37)
    artifact = (
        run_dir / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY
    ).joinpath(*member.split("/"))
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="failed recomputation"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


def test_ocr_37_release_gate_rejects_extra_package_files(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 37)
    extra = run_dir / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY / "unbound.txt"
    extra.write_text("not in manifest", encoding="utf-8")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="extra file"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


def test_ocr_37_release_gate_requires_measured_compile_inputs(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 37)

    def remove_measurements(payload: dict) -> None:
        for compile_pass in payload["compile"]["passes"]:
            compile_pass["command"] = []
            compile_pass["command_history"] = []
            compile_pass["compile_workdir"] = None
            compile_pass["input_inventory"] = []
            compile_pass["compile_input_sha256"] = None

    _rewrite_ocr_manifest(run_dir, remove_measurements)
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="unmeasured evidence cannot bind input artifacts",
    ):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


def test_ocr_37_release_gate_requires_bytes_for_every_compile_input(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 37)
    package_root = run_dir / MODULE.OCR_BASELINE_PACKAGE_DIRECTORY
    manifest = json.loads(
        (package_root / MODULE.OCR_BASELINE_MANIFEST_MEMBER).read_text(
            encoding="utf-8"
        )
    )
    baseline_descriptor = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["role"] == "BASELINE_TEX"
    )
    syntax_bytes = (package_root / baseline_descriptor["path"]).read_bytes()
    compile_inputs = build_compile_input_manifest(
        syntax_bytes.decode("utf-8"),
        {"figures/unbound.png": b"not-preserved-in-the-package"},
    )

    def add_unbound_input(payload: dict) -> None:
        for compile_pass in payload["compile"]["passes"]:
            compile_pass["input_inventory"] = compile_inputs["files"]
            compile_pass["compile_input_sha256"] = compile_inputs["manifest_sha256"]

    _rewrite_ocr_manifest(run_dir, add_unbound_input)
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="exact input roles do not cover inventory",
    ):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


def test_ocr_37_release_gate_binds_manifest_producer_to_candidate(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 37)
    _rewrite_ocr_manifest(
        run_dir,
        lambda payload: payload["producer"].__setitem__("build_id", "201"),
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="exact tested candidate"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
            expected_source_sha256=MODULE.RAMSEY_37_SOURCE_SHA256,
        )


def test_release_executable_and_portable_must_equal_analysis_37_tested_bytes(
    tmp_path: Path,
):
    executable = tmp_path / "LaTeXStruct.exe"
    executable.write_bytes(b"MZ-exact-tested-release")
    executable_sha = MODULE._sha256_file(executable)
    license_file = tmp_path / "LICENSE"
    notices = tmp_path / "THIRD_PARTY_NOTICES.txt"
    license_file.write_text("license", encoding="utf-8")
    notices.write_text("notices", encoding="utf-8")
    portable = tmp_path / "LaTeXStruct-portable-2.0.0.zip"
    MODULE.build_portable_archive(
        executable=executable,
        license_file=license_file,
        notices_file=notices,
        output=portable,
    )
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "analysis-37": _valid_analysis_run(
                tmp_path, 37, executable_sha256=executable_sha
            )
        },
        output=manifest,
    )
    assert json.loads(manifest.read_text(encoding="utf-8"))[
        "tested_executable_sha256"
    ] == executable_sha

    result = MODULE.verify_release_executable(
        manifest=manifest,
        version=VERSION,
        commit=COMMIT,
        executable=executable,
        portable=portable,
    )
    assert set(result.values()) == {executable_sha}

    executable.write_bytes(b"MZ-rebuilt-but-never-accepted")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="release executable SHA"):
        MODULE.verify_release_executable(
            manifest=manifest,
            version=VERSION,
            commit=COMMIT,
            executable=executable,
            portable=portable,
        )

    executable.write_bytes(b"MZ-exact-tested-release")
    untested = tmp_path / "untested.exe"
    untested.write_bytes(b"MZ-untested-portable")
    bad_portable = tmp_path / "bad-portable.zip"
    MODULE.build_portable_archive(
        executable=untested,
        license_file=license_file,
        notices_file=notices,
        output=bad_portable,
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="portable LaTeXStruct"):
        MODULE.verify_release_executable(
            manifest=manifest,
            version=VERSION,
            commit=COMMIT,
            executable=executable,
            portable=bad_portable,
        )


def test_release_notes_reject_hard_coded_current_ci_asset_digest(tmp_path: Path):
    changelog = tmp_path / "CHANGELOG.md"
    honest_limits = (
        "- `analysis-37` 只测试 37 页范围；OCR 的 600 页 / 30 分钟目标和 "
        "AI 的 600 页 / 120 分钟目标均为 `NOT_EVALUATED`。\n"
        "- 不声称 95% 准确率，不构成出版质量证明；私有证据不公开上传。\n"
    )
    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n{honest_limits}\n"
        "LaTeXStruct-portable asset SHA-256: "
        f"{'f' * 64}\n\n## v1.0.0（旧）\nold\n",
        encoding="utf-8",
    )


    with pytest.raises(MODULE.ReleaseIntegrityError, match="hard-codes"):
        MODULE.verify_release_notes(changelog, VERSION)

    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n{honest_limits}\n"
        "摘要由 CI 的 SHA256SUMS.txt 动态生成。\n",
        encoding="utf-8",
    )
    MODULE.verify_release_notes(changelog, VERSION)


@pytest.mark.parametrize(
    "forbidden",
    [
        "600 页 / 120 分钟已通过验证并达到目标。",
        "VERIFIED：600 页 / 120 分钟。",
        "The 600-page / 120-minute performance target is VERIFIED and passed.",
        "The six-hundred pages / two-hours SLO has been achieved.",
        "AI 六百页／两小时性能已经达标。",
        "The 600 - pages / 120 - minutes target was met.",
        "本版本达到 95% 准确率。",
        "本版本已具备出版质量。",
    ],
)
def test_release_notes_reject_unearned_quality_or_600_page_claims(
    tmp_path: Path, forbidden: str
):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n"
        "- `analysis-37` 只测试 37 页范围；OCR 的 600 页 / 30 分钟目标和 "
        "AI 的 600 页 / 120 分钟目标均为 `NOT_EVALUATED`。\n"
        "- 不声称 95% 准确率，不构成出版质量证明；私有证据不公开上传。\n"
        f"- {forbidden}\n",
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseIntegrityError, match="forbidden"):
        MODULE.verify_release_notes(changelog, VERSION)


def test_repository_v2_release_notes_state_truthful_limits():
    root = Path(__file__).resolve().parents[1]
    MODULE.verify_release_notes(
        root / "CHANGELOG.md",
        VERSION,
        readme=root / "README.md",
    )


def _write_artifact_zip(output: Path, files: dict[str, Path]) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name].read_bytes())


def _trusted_acceptance_fixture(
    tmp_path: Path,
    *,
    same_run: bool = False,
    private_publication_sentinels: bool = False,
) -> dict[str, Path]:
    fixture = _candidate_release_fixture(
        tmp_path,
        private_publication_sentinels=private_publication_sentinels,
    )
    analysis_run = tmp_path / "analysis37" / "analysis-run-37"
    payload_dir = tmp_path / "trusted-payload"
    acceptance_run_id = "200" if same_run else "300"
    acceptance_workflow_path = (
        MODULE.GITHUB_CANDIDATE_WORKFLOW
        if same_run
        else MODULE.GITHUB_ACCEPTANCE_WORKFLOW
    )
    MODULE.assemble_github_acceptance_payload(
        version=VERSION,
        commit=COMMIT,
        repository="Ararataki-number-one/LaTeXStruct",
        acceptance_run_id=acceptance_run_id,
        acceptance_run_attempt=1,
        acceptance_workflow_path=acceptance_workflow_path,
        runner_label=RUNNER_LABEL,
        candidate_run_id="200",
        analysis_run_dir=analysis_run,
        release_manifest=fixture["attestation"],
        assets_manifest=fixture["assets_manifest"],
        checksums=fixture["checksums"],
        assets_dir=fixture["candidate_dir"],
        output_dir=payload_dir,
    )
    payload_archive = tmp_path / "payload.zip"
    _write_artifact_zip(
        payload_archive,
        {
            "github-acceptance-reference.json": (
                payload_dir / "github-acceptance-reference.json"
            ),
            "github-acceptance-root.json": (
                payload_dir / "github-acceptance-root.json"
            ),
            "release-attestation.json": payload_dir / "release-attestation.json",
        },
    )
    closure_dir = tmp_path / "trusted-closure"
    closure_dir.mkdir()
    closure_path = closure_dir / "github-acceptance-closure.json"
    MODULE.write_github_acceptance_closure(
        payload_dir=payload_dir,
        repository="Ararataki-number-one/LaTeXStruct",
        version=VERSION,
        commit=COMMIT,
        acceptance_run_id=acceptance_run_id,
        acceptance_run_attempt=1,
        acceptance_workflow_path=acceptance_workflow_path,
        runner_label=RUNNER_LABEL,
        candidate_run_id="200",
        payload_artifact_id="501",
        payload_artifact_digest=f"sha256:{MODULE._sha256_file(payload_archive)}",
        output=closure_path,
    )
    closure_archive = tmp_path / "closure.zip"
    _write_artifact_zip(
        closure_archive,
        {"github-acceptance-closure.json": closure_path},
    )
    run_metadata = tmp_path / "run-metadata.json"
    _write_json(
        run_metadata,
        {
            "id": int(acceptance_run_id),
            "head_sha": COMMIT,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "path": acceptance_workflow_path,
            "run_attempt": 1,
            "repository": {"full_name": "Ararataki-number-one/LaTeXStruct"},
        },
    )
    artifacts_metadata = tmp_path / "artifacts-metadata.json"
    artifact_records = [
                {
                    "id": 501,
                    "name": f"LaTeXStruct-analysis-37-evidence-v{VERSION}",
                    "expired": False,
                    "digest": f"sha256:{MODULE._sha256_file(payload_archive)}",
                    "workflow_run": {
                        "id": int(acceptance_run_id),
                        "head_sha": COMMIT,
                    },
                },
                {
                    "id": 502,
                    "name": f"LaTeXStruct-analysis-37-closure-v{VERSION}",
                    "expired": False,
                    "digest": f"sha256:{MODULE._sha256_file(closure_archive)}",
                    "workflow_run": {
                        "id": int(acceptance_run_id),
                        "head_sha": COMMIT,
                    },
                },
    ]
    if same_run:
        artifact_records.append(
            {
                "id": 500,
                "name": f"LaTeXStruct-v{VERSION}",
                "expired": False,
                "digest": f"sha256:{'c' * 64}",
                "workflow_run": {"id": 200, "head_sha": COMMIT},
            }
        )
    _write_json(
        artifacts_metadata,
        {"total_count": len(artifact_records), "artifacts": artifact_records},
    )
    committed_reference = (
        tmp_path / "release" / "github-acceptance-reference.json"
    )
    committed_reference.write_bytes(
        (payload_dir / "github-acceptance-reference.json").read_bytes()
    )
    return {
        **fixture,
        "analysis_run": analysis_run,
        "payload_dir": payload_dir,
        "payload_archive": payload_archive,
        "closure_archive": closure_archive,
        "reference": committed_reference,
        "run_metadata": run_metadata,
        "artifacts_metadata": artifacts_metadata,
    }


def test_github_acceptance_artifact_closure_is_a_recomputable_trust_root(
    tmp_path: Path,
):
    fixture = _trusted_acceptance_fixture(tmp_path)
    verified = MODULE.verify_github_acceptance_trust(
        reference_manifest=fixture["reference"],
        release_manifest=fixture["attestation"],
        run_metadata=fixture["run_metadata"],
        artifacts_metadata=fixture["artifacts_metadata"],
        payload_archive=fixture["payload_archive"],
        closure_archive=fixture["closure_archive"],
        repository="Ararataki-number-one/LaTeXStruct",
        version=VERSION,
        commit=COMMIT,
    )

    assert verified["acceptance_run_id"] == "300"
    assert verified["candidate_run_id"] == "200"
    assert verified["payload_artifact_id"] == "501"
    assert verified["closure_artifact_id"] == "502"
    assert not (fixture["payload_dir"] / "analysis-audit-submission.zip").exists()
    assert not (fixture["payload_dir"] / "candidate.pdf").exists()
    assert (
        MODULE.main(
            [
                "verify-github-acceptance",
                "--reference-manifest",
                str(fixture["reference"]),
                "--release-manifest",
                str(fixture["attestation"]),
                "--run-metadata",
                str(fixture["run_metadata"]),
                "--artifacts-metadata",
                str(fixture["artifacts_metadata"]),
                "--payload-archive",
                str(fixture["payload_archive"]),
                "--closure-archive",
                str(fixture["closure_archive"]),
                "--repository",
                "Ararataki-number-one/LaTeXStruct",
                "--version",
                VERSION,
                "--commit",
                COMMIT,
            ]
        )
        == 0
    )


def test_all_three_public_github_json_files_exclude_private_sentinels(
    tmp_path: Path,
) -> None:
    fixture = _trusted_acceptance_fixture(
        tmp_path,
        private_publication_sentinels=True,
    )
    private_text = (
        fixture["analysis_run"] / "analysis-attestation.json"
    ).read_text(encoding="utf-8")
    assert PRIVATE_SOURCE_FILENAME_SENTINEL in private_text
    assert PRIVATE_PAGE_RISK_SENTINEL.replace("\\", "\\\\") in private_text

    for filename in (
        "github-acceptance-reference.json",
        "github-acceptance-root.json",
        "release-attestation.json",
    ):
        public_text = (fixture["payload_dir"] / filename).read_text(
            encoding="utf-8"
        )
        assert PRIVATE_SOURCE_FILENAME_SENTINEL not in public_text
        assert "private_diagnostic_path" not in public_text
        assert PRIVATE_PAGE_RISK_SENTINEL.replace("\\", "\\\\") not in public_text


def test_github_acceptance_trust_supports_same_run_reusable_acceptance(
    tmp_path: Path,
):
    fixture = _trusted_acceptance_fixture(tmp_path, same_run=True)
    verified = MODULE.verify_github_acceptance_trust(
        reference_manifest=fixture["reference"],
        release_manifest=fixture["attestation"],
        run_metadata=fixture["run_metadata"],
        artifacts_metadata=fixture["artifacts_metadata"],
        payload_archive=fixture["payload_archive"],
        closure_archive=fixture["closure_archive"],
        repository="Ararataki-number-one/LaTeXStruct",
        version=VERSION,
        commit=COMMIT,
    )

    assert verified["acceptance_run_id"] == "200"
    assert verified["candidate_run_id"] == "200"
    reference = json.loads(fixture["reference"].read_text(encoding="utf-8"))
    assert reference["acceptance_run"]["workflow_path"] == (
        MODULE.GITHUB_CANDIDATE_WORKFLOW
    )
    assert reference["acceptance_run"]["runner_label"] == RUNNER_LABEL


def test_github_acceptance_trust_rejects_local_projection_and_artifact_tampering(
    tmp_path: Path,
):
    fixture = _trusted_acceptance_fixture(tmp_path)
    forged_reference = json.loads(fixture["reference"].read_text(encoding="utf-8"))
    forged_reference["acceptance_run"]["run_id"] = "301"
    _write_json(fixture["reference"], forged_reference)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="GitHub acceptance run"):
        MODULE.verify_github_acceptance_trust(
            reference_manifest=fixture["reference"],
            release_manifest=fixture["attestation"],
            run_metadata=fixture["run_metadata"],
            artifacts_metadata=fixture["artifacts_metadata"],
            payload_archive=fixture["payload_archive"],
            closure_archive=fixture["closure_archive"],
            repository="Ararataki-number-one/LaTeXStruct",
            version=VERSION,
            commit=COMMIT,
        )

    fixture = _trusted_acceptance_fixture(tmp_path / "forged-runner-label")
    forged_reference = json.loads(fixture["reference"].read_text(encoding="utf-8"))
    forged_reference["acceptance_run"]["runner_label"] = "self-hosted"
    _write_json(fixture["reference"], forged_reference)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="runner label"):
        MODULE.verify_github_acceptance_trust(
            reference_manifest=fixture["reference"],
            release_manifest=fixture["attestation"],
            run_metadata=fixture["run_metadata"],
            artifacts_metadata=fixture["artifacts_metadata"],
            payload_archive=fixture["payload_archive"],
            closure_archive=fixture["closure_archive"],
            repository="Ararataki-number-one/LaTeXStruct",
            version=VERSION,
            commit=COMMIT,
        )

    fixture = _trusted_acceptance_fixture(tmp_path / "tampered-artifact")
    fixture["payload_archive"].write_bytes(
        fixture["payload_archive"].read_bytes() + b"tampered"
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="archive digest"):
        MODULE.verify_github_acceptance_trust(
            reference_manifest=fixture["reference"],
            release_manifest=fixture["attestation"],
            run_metadata=fixture["run_metadata"],
            artifacts_metadata=fixture["artifacts_metadata"],
            payload_archive=fixture["payload_archive"],
            closure_archive=fixture["closure_archive"],
            repository="Ararataki-number-one/LaTeXStruct",
            version=VERSION,
            commit=COMMIT,
        )


def test_release_docs_require_explicit_600_page_not_evaluated_disclaimer(
    tmp_path: Path,
) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    readme = tmp_path / "README.md"
    honest = (
        "analysis-37 covers 37 页. OCR 600-page / 30-minute and AI "
        "600-page / 120-minute targets are NOT_EVALUATED. "
        "不声称 95% 准确率，不构成出版质量证明，证据不公开上传。"
    )
    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n{honest}\n",
        encoding="utf-8",
    )
    readme.write_text(
        f"## 当前状态（v{VERSION}）\n\n{honest}\n\n## Next\n",
        encoding="utf-8",
    )
    MODULE.verify_release_notes(
        changelog,
        VERSION,
        readme=readme,
    )

    readme.write_text(
        f"## 当前状态（v{VERSION}）\n\n"
        "analysis-37 covers 37 页. OCR 600-page / 30-minute and AI "
        "600-page / 120-minute targets are pending.\n",
        encoding="utf-8",
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="NOT_EVALUATED"):
        MODULE.verify_release_notes(changelog, VERSION, readme=readme)

    readme.write_text(
        f"## 当前状态（v{VERSION}）\n\n{honest}\n\n"
        "The six hundred pages / two hours performance SLO has passed.\n",
        encoding="utf-8",
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="forbidden"):
        MODULE.verify_release_notes(changelog, VERSION, readme=readme)


def test_future_release_docs_cannot_bypass_600_page_disclaimer(
    tmp_path: Path,
) -> None:
    future_version = "2.0.1"
    changelog = tmp_path / "CHANGELOG.md"
    readme = tmp_path / "README.md"
    changelog.write_text(
        f"## v{future_version}（待发布）\n\n"
        "OCR 600-page / 30-minute target is NOT_EVALUATED. "
        "The 600-page / 120-minute target passed.\n",
        encoding="utf-8",
    )
    readme.write_text(
        f"## 当前状态（v{future_version}）\n\n"
        "analysis-37. OCR 600-page / 30-minute and AI 600-page / "
        "120-minute targets are NOT_EVALUATED.\n",
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseIntegrityError, match="forbidden"):
        MODULE.verify_release_notes(
            changelog,
            future_version,
            readme=readme,
        )


def test_release_attestation_requires_strict_analysis_37_and_detects_tampering(
    tmp_path: Path,
):
    analysis37 = _valid_analysis_run(tmp_path, 37)
    manifest = tmp_path / "release" / "release-attestation.json"

    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": analysis37},
        output=manifest,
    )
    MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["acceptance"]["visual_verification"]["pages_checked"] = 36
    _write_json(manifest, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="visual verification"):
        MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)


def test_analysis_inventory_rejects_missing_private_role(tmp_path: Path) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)

    def remove_gate(members: dict[str, bytes], manifest: dict) -> None:
        members.pop("audit/analysis_inventory_gate.json")
        manifest["artifacts"] = [
            record
            for record in manifest["artifacts"]
            if record["artifact_role"] != "ANALYSIS_INVENTORY_GATE"
        ]

    _rewrite_private_analysis_audit(
        run_dir, remove_gate, rebind_internal_hashes=True
    )
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="exactly one ANALYSIS_INVENTORY_GATE",
    ):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_inventory_rejects_unrebound_content_tampering(
    tmp_path: Path,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)

    def tamper(members: dict[str, bytes], _manifest: dict) -> None:
        payload = json.loads(members["audit/analysis_inventory_final.json"])
        payload["current_tex_sha256"] = "f" * 64
        members["audit/analysis_inventory_final.json"] = canonical_json_bytes(
            payload
        )

    _rewrite_private_analysis_audit(
        run_dir, tamper, rebind_internal_hashes=False
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="member digest mismatch"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_inventory_rejects_hash_recomputed_content_tampering(
    tmp_path: Path,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)

    def tamper_and_rebind(members: dict[str, bytes], _manifest: dict) -> None:
        payload = json.loads(members["audit/analysis_inventory_final.json"])
        payload["current_tex_sha256"] = "f" * 64
        members["audit/analysis_inventory_final.json"] = canonical_json_bytes(
            payload
        )

    _rewrite_private_analysis_audit(
        run_dir, tamper_and_rebind, rebind_internal_hashes=True
    )
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="differs from independent recomputation",
    ):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_inventory_rejects_rebound_final_status_forgery(
    tmp_path: Path,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)

    def forge_status(members: dict[str, bytes], _manifest: dict) -> None:
        payload = json.loads(members["audit/final_decision.json"])
        payload["inventory_gate_status"] = "FAILED"
        members["audit/final_decision.json"] = canonical_json_bytes(payload)

    _rewrite_private_analysis_audit(
        run_dir, forge_status, rebind_internal_hashes=True
    )
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="final decision is not inventory/hash bound",
    ):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_inventory_rejects_forged_public_pass_status(
    tmp_path: Path,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["analysis_inventory"]["inventory_gate_status"] = "FAILED"
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="strict PASS"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_inventory_rejects_rebound_configuration_tampering(
    tmp_path: Path,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)

    def forge_configuration(members: dict[str, bytes], _manifest: dict) -> None:
        payload = json.loads(members["audit/analysis_configuration.json"])
        payload["inventory_authorizations"] = []
        members["audit/analysis_configuration.json"] = canonical_json_bytes(
            payload
        )

    _rewrite_private_analysis_audit(
        run_dir, forge_configuration, rebind_internal_hashes=True
    )
    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="configuration differs from snapshot authority",
    ):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_status", "VERIFIED"),
        ("target_met", True),
        ("performance_target_pages", 37),
        ("performance_target_maximum_wall_time_seconds", 1800),
        ("performance_report_sha256", "f" * 64),
    ],
)
def test_release_projection_keeps_analysis_600_performance_not_evaluated(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    analysis37 = _valid_analysis_run(tmp_path / "private", 37)
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": analysis37},
        output=manifest,
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    claim = payload["performance_claim"]
    assert claim == {
        "schema_version": MODULE.ANALYSIS_PERFORMANCE_CLAIM_SCHEMA,
        "acceptance_profile": "analysis-37",
        "acceptance_sample_pages": 37,
        "performance_target_pages": 600,
        "performance_target_maximum_wall_time_seconds": 7200,
        "target_status": "NOT_EVALUATED",
        "target_met": None,
        "performance_report_filename": "analysis-performance.json",
        "performance_report_sha256": payload["acceptance"]["reports"][
            "performance"
        ]["sha256"],
    }
    claim[field] = value
    _write_json(manifest, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="NOT_EVALUATED"):
        MODULE.verify_release_attestation(
            manifest,
            version=VERSION,
            commit=COMMIT,
        )


def test_release_projection_rejects_missing_performance_claim(tmp_path: Path) -> None:
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": _valid_analysis_run(tmp_path / "private", 37)},
        output=manifest,
    )
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload.pop("performance_claim")
    _write_json(manifest, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="performance_claim"):
        MODULE.verify_release_attestation(
            manifest,
            version=VERSION,
            commit=COMMIT,
        )


def test_release_projection_keeps_private_evidence_out_of_public_tree(tmp_path: Path):
    analysis37 = _valid_analysis_run(tmp_path / "private", 37)
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": analysis37},
        output=manifest,
    )
    verified = MODULE.verify_release_attestation(
        manifest, version=VERSION, commit=COMMIT
    )
    assert verified["source"] == {
        "sha256": MODULE.RAMSEY_37_SOURCE_SHA256,
        "total_pages": 37,
    }
    assert verified["acceptance"]["source"] == verified["source"]
    assert verified["evidence_publication"]["projection_only"] is True
    public_snapshot = verified["acceptance"]["snapshot_binding"]
    assert "analysis_configuration" not in public_snapshot
    assert public_snapshot["analysis_configuration_private"] is True
    assert public_snapshot["native_source_blocks_published"] is False
    private = json.loads(
        (analysis37 / "analysis-attestation.json").read_text(encoding="utf-8")
    )
    public_risk = verified["acceptance"]["page_risk_admission"]
    assert set(public_risk) == {
        "schema_version",
        "private_closure_sha256",
        "source_pdf_sha256",
        "baseline_tex_sha256",
        "baseline_pdf_sha256",
        "ocr_page_records_sha256",
        "ocr_runtime_page_records_sha256",
        "admission_sha256",
        "preflight_sha256",
        "route_closure_sha256",
        "final_candidate_tex_sha256",
        "page_count",
        "page_ids_sha256",
        "risk_counts",
        "low_risk_sampling_sha256",
        "low_risk_sample_count",
        "all_preflight_bindings_verified",
        "all_route_bindings_verified",
    }
    assert public_risk["schema_version"] == (
        MODULE.ANALYSIS_PAGE_RISK_PUBLIC_PROJECTION_SCHEMA
    )
    assert public_risk["private_closure_sha256"] == (
        MODULE._canonical_json_sha256(private["page_risk_admission"])
    )
    assert public_risk["admission_sha256"] == (
        public_snapshot["evidence_hashes"]["page_risk_admission_hash"]
    )
    assert not {"admission", "preflight", "route_closure", "low_risk_sampling"} & set(
        public_risk
    )
    public_text = manifest.read_text(encoding="utf-8")
    assert PRIVATE_SOURCE_FILENAME_SENTINEL not in public_text
    assert '"preflight": {' not in public_text
    assert '"native_source_blocks": [' not in public_text
    assert "release fixture source page 1" not in public_text
    assert {path.name for path in manifest.parent.iterdir()} == {
        "release-attestation.json"
    }


def test_public_page_risk_projection_is_exact_hash_only_and_content_free() -> None:
    source_sha = MODULE.RAMSEY_37_SOURCE_SHA256
    page_records_sha = "1" * 64
    runtime_records_sha = "2" * 64
    admission_sha = "3" * 64
    final_candidate_sha = "4" * 64
    private = {
        "admission": {
            "source_pdf_sha256": source_sha,
            "baseline_tex_sha256": "5" * 64,
            "baseline_pdf_sha256": "6" * 64,
            "ocr_page_records_sha256": page_records_sha,
            "ocr_runtime_page_records_sha256": runtime_records_sha,
        },
        "route_closure": {
            "final_candidate_hash": final_candidate_sha,
            "private_reason": PRIVATE_PAGE_RISK_SENTINEL,
        },
        "low_risk_sampling": {
            "target_count": 1,
            "private_filename": PRIVATE_SOURCE_FILENAME_SENTINEL,
        },
        "admission_sha256": admission_sha,
        "preflight_sha256": "7" * 64,
        "route_closure_sha256": "8" * 64,
        "page_count": 37,
        "page_ids_sha256": "9" * 64,
        "risk_counts": {
            "admitted": {"R0": 37, "R1": 0, "R2": 0, "R3": 0},
            "effective": {"R0": 37, "R1": 0, "R2": 0, "R3": 0},
        },
        "all_preflight_bindings_verified": True,
        "all_route_bindings_verified": True,
    }
    public = MODULE._public_analysis_page_risk_projection(private)
    verified = MODULE._verify_public_analysis_page_risk_projection(
        public,
        expected_pages=37,
        source_sha256=source_sha,
        evidence_hashes={
            "ocr_page_records_hash": page_records_sha,
            "ocr_runtime_page_records_hash": runtime_records_sha,
            "page_risk_admission_hash": admission_sha,
        },
        final_candidate_sha256=final_candidate_sha,
    )
    public_text = json.dumps(verified, ensure_ascii=False)
    assert PRIVATE_PAGE_RISK_SENTINEL not in public_text
    assert PRIVATE_SOURCE_FILENAME_SENTINEL not in public_text
    assert verified["private_closure_sha256"] == (
        MODULE._canonical_json_sha256(private)
    )

    forged = dict(public)
    forged["preflight"] = {"private_reason": PRIVATE_PAGE_RISK_SENTINEL}
    with pytest.raises(MODULE.ReleaseIntegrityError, match="unsupported fields"):
        MODULE._verify_public_analysis_page_risk_projection(
            forged,
            expected_pages=37,
            source_sha256=source_sha,
            evidence_hashes={
                "ocr_page_records_hash": page_records_sha,
                "ocr_runtime_page_records_hash": runtime_records_sha,
                "page_risk_admission_hash": admission_sha,
            },
            final_candidate_sha256=final_candidate_sha,
        )


def test_analysis_37_rejects_recommended_tier_and_49_page_inflation(tmp_path: Path):
    recommended = _valid_analysis_run(tmp_path / "recommended", 37)
    path = recommended / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["quality_tier"] = "recommended"
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="quality tier high"):
        MODULE.verify_analysis_attestation(
            recommended, expected_pages=37, version=VERSION, commit=COMMIT
        )

    inflated = _valid_analysis_run(tmp_path / "inflated", 37)
    path = inflated / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["page_layout"]["candidate_page_count"] = 49
    payload["page_layout"]["page_growth"] = 12
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="abnormal page inflation"):
        MODULE.verify_analysis_attestation(
            inflated, expected_pages=37, version=VERSION, commit=COMMIT
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("target_status", "VERIFIED"), ("target_met", True)],
)
def test_analysis_37_private_performance_report_cannot_promote_600_page_target(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    run_dir = _valid_analysis_run(tmp_path, 37)
    performance_path = run_dir / "analysis-performance.json"
    performance = json.loads(performance_path.read_text(encoding="utf-8"))
    performance[field] = value
    _write_json(performance_path, performance)
    attestation_path = run_dir / "analysis-attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["reports"]["performance"]["sha256"] = MODULE._sha256_file(
        performance_path
    )
    _write_json(attestation_path, attestation)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="NOT_EVALUATED"):
        MODULE.verify_analysis_attestation(
            run_dir,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
        )


def test_analysis_37_rejects_unbound_service_executable(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["service_binding"]["process_image_sha256"] = "f" * 64
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="service process"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_test_double_run_is_rejected_as_release_attestation(tmp_path: Path):
    run_dir = _valid_run(tmp_path, 17, real_execution=False)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="test-double"):
        MODULE.verify_run_attestation(
            run_dir,
            expected_pages=17,
            version=VERSION,
            commit=COMMIT,
        )


def test_analysis_rejects_nested_ocr_with_different_executable(tmp_path: Path):
    analysis37 = _valid_analysis_run(tmp_path, 37)
    ocr_dir = analysis37 / "ocr-prerequisite"
    path = ocr_dir / "acceptance-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runtime_identity"]["executable_sha256"] = "f" * 64
    for report_name in ("performance.json", "validation-report.json"):
        report_path = ocr_dir / report_name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["runtime_identity"]["executable_sha256"] = "f" * 64
        _write_json(report_path, report)
        report_key = "performance" if report_name == "performance.json" else "validation"
        payload["reports"][report_key]["sha256"] = MODULE._sha256_file(report_path)
    _write_json(path, payload)
    analysis_path = analysis37 / "analysis-attestation.json"
    analysis_payload = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis_payload["ocr_prerequisite"]["attestation_sha256"] = MODULE._sha256_file(
        path
    )
    _write_json(analysis_path, analysis_payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="different commit/build/executable"):
        MODULE.verify_analysis_attestation(
            analysis37,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
        )


def test_analysis_rejects_nested_ocr_with_different_baseline_manifest(tmp_path: Path):
    analysis37 = _valid_analysis_run(tmp_path, 37)
    analysis_path = analysis37 / "analysis-attestation.json"
    payload = json.loads(analysis_path.read_text(encoding="utf-8"))
    payload["ocr_prerequisite"]["baseline_manifest_sha256"] = "f" * 64
    _write_json(analysis_path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="exact recomputable baseline"):
        MODULE.verify_analysis_attestation(
            analysis37,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
        )


def test_missing_analysis_profiles_fail_closed_with_actionable_error(tmp_path: Path):
    with pytest.raises(MODULE.ReleaseIntegrityError, match="analysis-37"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={},
            output=tmp_path / "release" / "release-attestation.json",
        )
    assert not (tmp_path / "release" / "release-attestation.json").exists()

    old_manifest = tmp_path / "old-release-attestation.json"
    _write_json(
        old_manifest,
        {
            "schema_version": "latexstruct-release-acceptance/2",
            "version": VERSION,
            "commit": COMMIT,
            "runs": {"ocr-17": {}, "ocr-600": {}},
        },
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="missing fields"):
        MODULE.verify_release_attestation(
            old_manifest, version=VERSION, commit=COMMIT
        )


def test_analysis_test_double_and_unverified_terminal_cannot_mint_pass(tmp_path: Path):
    fake = _valid_analysis_run(tmp_path / "fake", 37, real_execution=False)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="test-double"):
        MODULE.verify_analysis_attestation(
            fake,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
        )

    unverified = _valid_analysis_run(
        tmp_path / "unverified", 37, terminal_status="UNVERIFIED"
    )
    with pytest.raises(MODULE.ReleaseIntegrityError, match="VERIFIED"):
        MODULE.verify_analysis_attestation(
            unverified,
            expected_pages=37,
            version=VERSION,
            commit=COMMIT,
        )


def test_analysis_requires_real_calls_distinct_contexts_and_machine_pass(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["models"]["calls_total"] = 0
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="call total"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "contexts", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["independent_final_reviews"][1]["context_id"] = "context-1"
    payload["independent_final_reviews"][1]["context_sha256"] = payload[
        "independent_final_reviews"
    ][0]["context_sha256"]
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="distinct context ids"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "machine", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["machine_verification"]["passed"] = False
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="machine verification"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_rejects_transport_and_page_risk_closure_tampering(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path / "transport", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["snapshot_binding"]["transport_closure"][
        "usage_missing_attempt_count"
    ] = 1
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="closed ledger"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "missing-budget-closure", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["snapshot_binding"]["transport_closure"].pop("budget_closure")
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="missing fields: budget_closure"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "forged-budget-aggregate", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    budget = payload["snapshot_binding"]["transport_closure"]["budget_closure"]
    for section in ("observed", "actual", "accounted"):
        budget[section]["input_tokens"] += 1
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="persisted budget state"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "missing-transport-contracts", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    budget = payload["snapshot_binding"]["transport_closure"]["budget_closure"]
    budget.pop("transport_contracts")
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="transport_contracts"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "contract-claim-formula", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    snapshot = payload["snapshot_binding"]
    budget = snapshot["transport_closure"]["budget_closure"]
    budget["transport_contracts"][0]["max_tokens"] = 21
    contracts_sha = MODULE._canonical_json_sha256(budget["transport_contracts"])
    budget["transport_contracts_sha256"] = contracts_sha
    snapshot["transport_contracts_sha256"] = contracts_sha
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="differs from its contract"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "forged-sanitized-attempt", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    budget = payload["snapshot_binding"]["transport_closure"]["budget_closure"]
    ledger = budget["transport_budget_ledger"]
    ledger[0]["attempts"][0]["input_tokens"] += 1
    budget["transport_budget_ledger_sha256"] = MODULE._canonical_json_sha256(ledger)
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="differs from attempts"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "token-algebra", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["snapshot_binding"]["transport_closure"]["total_tokens"] += 1
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="closed ledger"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "missing-risk-page", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    risk = payload["page_risk_admission"]
    risk["admission"]["pages"].pop()
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="page-risk admission is invalid"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )

    run_dir = _valid_analysis_run(tmp_path / "risk-row-vs-ocr", 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    risk = payload["page_risk_admission"]
    risk["admission"]["pages"][0]["summary"][
        "source_page_object_hash"
    ] = "f" * 64
    _write_json(path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="page-risk admission is invalid"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_gate_rejects_unsupported_budget_ledger_fields(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    budget = payload["snapshot_binding"]["transport_closure"]["budget_closure"]
    ledger = budget["transport_budget_ledger"]
    ledger[0]["budget_claim"]["reserved_prompt"] = 1
    budget["transport_budget_ledger_sha256"] = MODULE._canonical_json_sha256(ledger)
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="unsupported fields"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_gate_rejects_runtime_page_record_hash_drift(
    tmp_path: Path,
):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["snapshot_binding"]["evidence_hashes"][
        "ocr_runtime_page_records_hash"
    ] = "f" * 64
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="identity/hash closure"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_gate_rejects_non_subscription_attempt(tmp_path: Path):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    budget = payload["snapshot_binding"]["transport_closure"]["budget_closure"]
    ledger = budget["transport_budget_ledger"]
    ledger[0]["attempts"][0]["billing_mode"] = "api"
    budget["transport_budget_ledger_sha256"] = MODULE._canonical_json_sha256(ledger)
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="subscription billed"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_gate_rejects_mixed_disallowed_model_policy(
    tmp_path: Path,
):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    snapshot = payload["snapshot_binding"]
    snapshot["model_bindings"][0]["model_id"] = "gpt-5.4"
    snapshot["model_bindings_sha256"] = MODULE._canonical_json_sha256(
        snapshot["model_bindings"]
    )
    budget = snapshot["transport_closure"]["budget_closure"]
    budget["transport_contracts"][0]["model_id"] = "gpt-5.4"
    contracts_sha256 = MODULE._canonical_json_sha256(budget["transport_contracts"])
    budget["transport_contracts_sha256"] = contracts_sha256
    snapshot["transport_contracts_sha256"] = contracts_sha256
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="release model policy"):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_gate_rejects_runtime_model_declaration_drift(
    tmp_path: Path,
):
    run_dir = _valid_analysis_run(tmp_path, 37)
    path = run_dir / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    policy = payload["snapshot_binding"]["release_model_policy"]
    runtime = policy["runtime_configuration"]
    runtime["codex_model"] = "gpt-5.4"
    policy["runtime_configuration_sha256"] = MODULE._canonical_json_sha256(runtime)
    _write_json(path, payload)

    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="runtime model configuration differs",
    ):
        MODULE.verify_analysis_attestation(
            run_dir, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_analysis_release_model_policy_rejects_uniform_non_high_effort(
    tmp_path: Path,
):
    run_dir = _valid_analysis_run(tmp_path, 37)
    payload = json.loads(
        (run_dir / "analysis-attestation.json").read_text(encoding="utf-8")
    )
    snapshot = payload["snapshot_binding"]
    bindings = snapshot["model_bindings"]
    contracts = snapshot["analysis_configuration"]["transport_contracts"]
    for item in (*bindings, *contracts):
        item["reasoning_effort"] = "medium"
    policy = snapshot["release_model_policy"]
    policy["declared_reasoning_effort"] = "medium"
    runtime = policy["runtime_configuration"]
    runtime["codex_reasoning_effort"] = "medium"
    runtime["codex_triage_reasoning_effort"] = "medium"
    policy["runtime_configuration_sha256"] = MODULE._canonical_json_sha256(
        runtime
    )
    policy["model_bindings_sha256"] = MODULE._canonical_json_sha256(bindings)
    policy["transport_contracts_sha256"] = MODULE._canonical_json_sha256(
        contracts
    )

    with pytest.raises(
        MODULE.ReleaseIntegrityError,
        match="release model declaration is not allowed",
    ):
        MODULE._verify_analysis_release_model_policy(
            policy,
            model_bindings=bindings,
            transport_contracts=contracts,
        )


def test_analysis_requires_recomputable_compilation_artifacts(tmp_path: Path):
    hash_only = _valid_analysis_run(tmp_path / "hash-only", 37)
    attestation_path = hash_only / "analysis-attestation.json"
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload.pop("artifacts")
    _write_json(attestation_path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="missing fields: artifacts"):
        MODULE.verify_analysis_attestation(
            hash_only, expected_pages=37, version=VERSION, commit=COMMIT
        )

    missing = _valid_analysis_run(tmp_path / "missing", 37)
    (missing / "candidate.pdf").unlink()
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact is missing: candidate.pdf"):
        MODULE.verify_analysis_attestation(
            missing, expected_pages=37, version=VERSION, commit=COMMIT
        )

    tampered = _valid_analysis_run(tmp_path / "tampered", 37)
    candidate_path = tampered / "candidate.tex"
    candidate_bytes = candidate_path.read_bytes()
    candidate_path.write_bytes(b"X" + candidate_bytes[1:])
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact digest mismatch: candidate.tex"):
        MODULE.verify_analysis_attestation(
            tampered, expected_pages=37, version=VERSION, commit=COMMIT
        )

    wrong_size = _valid_analysis_run(tmp_path / "wrong-size", 37)
    attestation_path = wrong_size / "analysis-attestation.json"
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload["artifacts"]["compile_log"]["bytes"] += 1
    _write_json(attestation_path, payload)
    with pytest.raises(MODULE.ReleaseIntegrityError, match="byte count mismatch: compile.log"):
        MODULE.verify_analysis_attestation(
            wrong_size, expected_pages=37, version=VERSION, commit=COMMIT
        )


def test_release_assembly_reverifies_private_artifacts_before_projection(tmp_path: Path):
    analysis37 = _valid_analysis_run(tmp_path / "runs", 37)
    manifest = tmp_path / "release" / "release-attestation.json"
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={"analysis-37": analysis37},
        output=manifest,
    )
    MODULE.verify_release_attestation(manifest, version=VERSION, commit=COMMIT)
    assert not (manifest.parent / "analysis-37").exists()

    analysis37 = _valid_analysis_run(tmp_path / "tampered-private", 37)
    (analysis37 / "candidate.pdf").write_bytes(b"%PDF-1.7\ntampered\n")
    with pytest.raises(MODULE.ReleaseIntegrityError, match="artifact .*candidate.pdf"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={"analysis-37": analysis37},
            output=tmp_path / "blocked" / "release-attestation.json",
        )


def test_analysis_source_pdf_must_match_fixed_ramsey_sha(tmp_path: Path):
    analysis37 = _valid_analysis_run(tmp_path, 37)
    path = analysis37 / "analysis-attestation.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["source"]["sha256"] = "f" * 64
    for report_name in (
        "analysis-performance.json",
        "analysis-validation-report.json",
    ):
        report_path = analysis37 / report_name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source"]["sha256"] = "f" * 64
        _write_json(report_path, report)
        report_key = "performance" if "performance" in report_name else "validation"
        payload["reports"][report_key]["sha256"] = MODULE._sha256_file(report_path)
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseIntegrityError, match="analysis-37 source PDF SHA"):
        MODULE.assemble_release_attestation(
            version=VERSION,
            commit=COMMIT,
            run_dirs={"analysis-37": analysis37},
            output=tmp_path / "release" / "release-attestation.json",
        )


def test_analysis_schema_is_strict_and_cli_can_write_it(tmp_path: Path):
    schema = MODULE.analysis_attestation_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["execution"]["additionalProperties"] is False
    assert schema["properties"]["terminal_status"] == {"const": "VERIFIED"}
    assert schema["properties"]["profile"] == {"const": "analysis-37"}
    assert schema["properties"]["quality_tier"] == {"const": "high"}
    assert schema["properties"]["template"] == {"const": "faithfulbook"}
    assert schema["properties"]["source"]["properties"]["sha256"] == {
        "const": MODULE.RAMSEY_37_SOURCE_SHA256
    }
    assert schema["properties"]["independent_final_reviews"]["minItems"] == 2
    assert schema["properties"]["independent_final_reviews"]["maxItems"] == 2
    assert schema["properties"]["models"]["properties"]["calls_total"]["minimum"] == 1
    assert "artifacts" in schema["required"]
    assert "ocr_prerequisite" in schema["required"]
    assert "visual_verification" in schema["required"]
    assert "audit_submission" in schema["required"]
    assert "service_binding" in schema["required"]
    assert "page_risk_admission" in schema["required"]
    assert "page_layout" in schema["required"]
    transport = schema["properties"]["snapshot_binding"]["properties"][
        "transport_closure"
    ]
    assert transport["additionalProperties"] is False
    assert transport["properties"]["usage_missing_call_count"] == {"const": 0}
    assert transport["properties"]["usage_missing_attempt_count"] == {"const": 0}
    assert "budget_closure" in transport["required"]
    budget = transport["properties"]["budget_closure"]
    assert budget["additionalProperties"] is False
    assert budget["properties"]["active_reservations"] == {"const": 0}
    assert budget["properties"]["cancelled_reservations"] == {"const": 0}
    assert budget["properties"]["transport_claim_count"] == {
        "type": "integer",
        "minimum": 1,
    }
    assert budget["properties"]["exact_aggregate_verified"] == {"const": True}
    page_risk = schema["properties"]["page_risk_admission"]
    assert page_risk["additionalProperties"] is False
    assert {
        "admission",
        "preflight",
        "preflight_sha256",
        "route_closure",
        "route_closure_sha256",
        "risk_counts",
        "low_risk_sampling",
        "all_preflight_bindings_verified",
        "all_route_bindings_verified",
    }.issubset(page_risk["required"])
    snapshot = schema["properties"]["snapshot_binding"]
    assert {
        "analysis_configuration",
        "analysis_configuration_sha256",
    }.issubset(snapshot["required"])
    assert {
        "run_id",
        "baseline_manifest_sha256",
    }.issubset(schema["properties"]["ocr_prerequisite"]["required"])
    assert schema["properties"]["page_layout"]["properties"][
        "candidate_page_count"
    ]["maximum"] == 42
    artifacts = schema["properties"]["artifacts"]
    assert artifacts["additionalProperties"] is False
    assert artifacts["required"] == list(MODULE.ANALYSIS_ARTIFACT_SPECS)
    assert (
        artifacts["properties"]["candidate_tex"]["properties"]["filename"]
        == {"const": "candidate.tex"}
    )

    output = tmp_path / "analysis-attestation.schema.json"
    assert MODULE.main(["analysis-schema", "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == schema


def test_release_docs_declare_playwright_acceptance_environment():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert "acceptance = [" in pyproject
    assert '"playwright>=' in pyproject
    assert 'pip install -e ".[server,acceptance]"' in readme
    assert "python -m playwright install chromium" in readme
    assert "浏览器二进制" in readme and "不进入仓库" in readme


def test_build_workflow_guards_tag_release_and_publishes_dynamic_hashes():
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
    ).read_text(encoding="utf-8")
    release_action = workflow.index(
        "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"
    )
    tag_job = workflow.index("release_attested_candidate:")
    candidate_job = workflow.index("build_candidate:")
    acceptance_job = workflow.index("trusted_analysis_37:")
    final_installer_smoke = workflow.index("最终安装器字节绑定（未签名候选静默安装")
    final_ref_gate = workflow.index("发布瞬间再次校验 tag 与 origin/main 当前 HEAD")
    trusted_evidence_gate = workflow.index("下载并验证 GitHub 受信 acceptance artifact 闭包")
    assert workflow.index("git merge-base --is-ancestor") < release_action
    assert "$tagSha -ne $mainSha" in workflow
    assert "稳定 tag 必须精确指向 origin/main 当前 HEAD" in workflow
    assert "--readme README.md" in workflow
    assert workflow.index("verify-attestation") < release_action
    assert final_installer_smoke < workflow.index("record-assets")
    assert "最终安装器内 EXE 与候选 EXE 字节不一致" in workflow
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath 'dist/LaTeXStruct.exe'" in workflow
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath $installedExe" in workflow
    assert workflow.index("record-assets") < workflow.index(
        "actions/upload-artifact@v4"
    ) < tag_job
    assert tag_job < workflow.index(
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    ) < workflow.index("verify-candidate-assets") < release_action
    assert "if: github.event_name == 'workflow_dispatch'" in workflow[
        candidate_job:tag_job
    ]
    assert "run_analysis_37:" in workflow[:candidate_job]
    assert "runner_label:" in workflow[:candidate_job]
    assert "uses: ./.github/workflows/analysis-37-acceptance.yml" in workflow[
        acceptance_job:tag_job
    ]
    assert "candidate_run_id: ${{ github.run_id }}" in workflow[
        acceptance_job:tag_job
    ]
    assert "needs.build_candidate.outputs.app_version" in workflow[
        acceptance_job:tag_job
    ]
    assert "WINDOWS_CERT_BASE64" not in workflow[candidate_job:tag_job]
    assert "WINDOWS_CERT_PASSWORD" not in workflow[candidate_job:tag_job]
    assert (
        "if: startsWith(github.ref, 'refs/tags/v') && "
        "!contains(github.ref_name, '-')"
    ) in workflow[tag_job:release_action]
    assert "run-id: ${{ env.CANDIDATE_RUN_ID }}" in workflow[tag_job:]
    assert "[string]$candidateRun.event -ne 'workflow_dispatch'" in workflow
    assert "[string]$candidateRun.status -ne 'completed'" in workflow
    assert "[string]$candidateRun.conclusion -ne 'success'" in workflow
    assert "[string]$candidateRun.path -ne '.github/workflows/build.yml'" in workflow
    assert "[int]$candidateRun.run_attempt -ne 1" in workflow
    assert "candidateRun.head_sha" in workflow
    assert "PyInstaller" not in workflow[tag_job:]
    assert "iscc" not in workflow[tag_job:]
    assert "record-assets" not in workflow[tag_job:]
    assert "verify-release-executable" not in workflow
    assert "真实验收后仍修改了运行时文件" in workflow
    assert "analysis-37" in workflow
    assert "github-acceptance-reference.json" in workflow
    assert "只能提交 release-attestation.json 与 github-acceptance-reference.json" in workflow
    assert "禁止上传源 PDF、候选 PDF、逐页图或完整审计包" in workflow
    assert "git ls-tree -r --name-only" in workflow
    assert "SOME RECENT RESULTS IN RAMSEY THEORY.pdf" in workflow
    assert "analysis-audit-submission.zip" in workflow
    assert "refs/release-gate/origin-main" in workflow
    assert "refs/release-gate/stable-tag" in workflow
    assert "$mainSha -ne $remoteTagSha" in workflow
    assert "$mainSha -ne $checkoutSha" in workflow
    assert "$mainSha -ne $eventSha" in workflow
    assert trusted_evidence_gate < workflow.index("verify-candidate-assets")
    assert workflow.index("verify-candidate-assets") < final_ref_gate < release_action
    assert "verify-github-acceptance" in workflow[trusted_evidence_gate:release_action]
    assert "acceptanceRun.run_attempt -ne 1" in workflow
    assert "acceptanceWorkflowPath" in workflow
    assert "acceptanceRunnerLabel" in workflow
    assert "$expectedArtifactCount = if ($sameRun) { 3 } else { 2 }" in workflow
    assert "actions/artifacts/$env:PAYLOAD_ARTIFACT_ID/zip" in workflow
    assert "actions/artifacts/$env:CLOSURE_ARTIFACT_ID/zip" in workflow
    assert "稳定发布保持关闭" not in workflow
    assert "release/acceptance/v$env:APP_VERSION/" in workflow
    assert "dist/SHA256SUMS.txt" in workflow
    assert "dist/release-assets.json" in workflow
    assert "build-portable" in workflow
    assert "LaTeXStruct-portable-${{ env.APP_VERSION }}.zip" in workflow[tag_job:]
    assert "LaTeXStruct-setup-${{ env.APP_VERSION }}.exe" in workflow[tag_job:]


def test_contents_write_jobs_pin_all_remote_actions_to_reviewed_commits():
    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"
    ).read_text(encoding="utf-8")
    expected_release_actions = {
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
    }

    job_starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", workflow))
    contents_write_jobs: dict[str, set[str]] = {}
    for index, match in enumerate(job_starts):
        end = (
            job_starts[index + 1].start()
            if index + 1 < len(job_starts)
            else len(workflow)
        )
        job_block = workflow[match.start() : end]
        if not re.search(r"(?m)^      contents:\s*write\s*$", job_block):
            continue
        action_refs = set(
            re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", job_block)
        )
        assert action_refs, f"contents: write job {match.group(1)} has no action refs"
        assert all(
            action.startswith("./")
            or re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action)
            for action in action_refs
        ), f"contents: write job {match.group(1)} contains a mutable action ref"
        contents_write_jobs[match.group(1)] = action_refs

    release_actions = contents_write_jobs["release_attested_candidate"]
    assert {action for action in release_actions if not action.startswith("./")} == (
        expected_release_actions
    )


def test_trusted_analysis_37_workflow_keeps_private_bytes_local_and_closes_artifacts():
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "analysis-37-acceptance.yml"
    ).read_text(encoding="utf-8")

    assert "workflow_call:" in workflow
    assert "- self-hosted" in workflow
    assert "- Windows" in workflow
    assert "- X64" in workflow
    assert "- latexstruct-acceptance-private" in workflow
    assert "- ${{ inputs.runner_label }}" in workflow
    assert "^latexstruct-acceptance-[0-9a-f]{32}$" in workflow
    assert "environment: v2-stable-acceptance" in workflow
    assert "RAMSEY_37_SOURCE_PATH: ${{ vars.RAMSEY_37_SOURCE_PATH }}" in workflow
    assert PRODUCTION_RAMSEY_37_SOURCE_SHA256 in workflow
    assert "candidate.path -ne '.github/workflows/build.yml'" in workflow
    assert "candidate.run_attempt -ne 1" in workflow
    assert "candidate.head_sha" in workflow
    assert "ACCEPTANCE_WORKFLOW_PATH=$acceptanceWorkflowPath" in workflow
    assert "ACCEPTANCE_RUNNER_LABEL=$runnerLabel" in workflow
    assert "--acceptance-workflow-path $env:ACCEPTANCE_WORKFLOW_PATH" in workflow
    assert "--runner-label $env:ACCEPTANCE_RUNNER_LABEL" in workflow
    assert "LATEXSTRUCT_ANALYSIS_BACKEND: codex_cli" in workflow
    assert "RELEASE_ANALYSIS_MODEL_ID: gpt-5.4-mini" in workflow
    assert "RELEASE_ANALYSIS_REASONING_EFFORT: high" in workflow
    assert "LATEXSTRUCT_CODEX_MODEL: gpt-5.4-mini" in workflow
    assert "LATEXSTRUCT_CODEX_REASONING_EFFORT: high" in workflow
    assert "LATEXSTRUCT_CODEX_TRIAGE_MODEL: gpt-5.4-mini" in workflow
    assert "LATEXSTRUCT_CODEX_TRIAGE_REASONING_EFFORT: high" in workflow
    assert '"HOME=$profileHome"' in workflow
    assert '"CODEX_HOME=$codexHome"' in workflow
    assert "/api/codex/status" in workflow
    assert "/api/config" in workflow
    assert "$codexStatus.ready -ne $true" in workflow
    assert "runtimeConfig.analysis_backend" in workflow
    assert "runtimeConfig.codex_triage_model" in workflow
    assert "runtimeConfig.codex_triage_reasoning_effort" in workflow
    assert "--expected-model-id $env:RELEASE_ANALYSIS_MODEL_ID" in workflow
    assert (
        "--expected-reasoning-effort $env:RELEASE_ANALYSIS_REASONING_EFFORT"
        in workflow
    )
    assert "tools/v2_analysis_acceptance.py" in workflow
    assert "assemble-attestations" in workflow
    assert "assemble-github-acceptance" in workflow
    assert "write-github-acceptance-closure" in workflow
    assert "steps.payload_upload.outputs.artifact-id" in workflow
    assert "steps.payload_upload.outputs.artifact-digest" in workflow
    assert workflow.count(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ) == 2
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "actions/setup-python@" not in workflow
    assert "RUNNER_TOOL_CACHE" in workflow
    assert 'Write-Output "::add-mask::$sensitiveRoot"' in workflow
    assert 'Write-Output "::add-mask::$profileHome"' in workflow
    assert 'Write-Output "::add-mask::$source"' in workflow
    assert "$python = $pythonCandidates[0]" in workflow
    assert "Get-ChildItem -LiteralPath $pythonRoot -Directory" in workflow
    assert "Get-Command python" not in workflow
    assert "$pythonPath = [IO.Path]::GetFullPath($python.FullName)" in workflow
    assert "Add-Content -LiteralPath $env:GITHUB_PATH -Value $pythonDir" in workflow
    assert "sys.version_info[:2] == (3, 13)" in workflow
    assert "platform.machine() == 'AMD64'" in workflow
    assert "验收 Python SHA-256" in workflow
    assert 'Write-Host "验收 Python: $pythonPath"' not in workflow
    assert '工具缓存中: $pythonPath' not in workflow
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in workflow
    upload_section = workflow[workflow.index("上传只含哈希投影的受信 payload") :]
    assert "analysis-audit-submission.zip" not in upload_section
    assert "candidate.pdf" not in upload_section
    assert "RAMSEY_37_SOURCE_PATH }}" not in upload_section
    assert "Remove-Item -LiteralPath $target -Recurse -Force" in workflow
    assert "RUNNER_TEMP 之外" in workflow
    assert 'RUNNER_TEMP 之外的路径: $target' not in workflow
    assert "$privateAppData = Join-Path $privateRoot" in workflow
    assert "$privateLocalAppData = Join-Path $privateRoot" in workflow
    assert "$privateTemp = Join-Path $privateRoot" in workflow
    assert '"APPDATA=$privateAppData"' in workflow
    assert '"LOCALAPPDATA=$privateLocalAppData"' in workflow
    assert '"TEMP=$privateTemp"' in workflow
    assert '"TMP=$privateTemp"' in workflow
    assert "$env:PRIVATE_APPDATA_ROOT" in workflow
    assert "$env:PRIVATE_LOCALAPPDATA_ROOT" in workflow
    assert "$env:PRIVATE_TEMP_ROOT" in workflow
    assert "本次验收私有目录清理后仍存在" in workflow
    assert '私有目录清理后仍存在: $privatePath' not in workflow
    assert "LATEXSTRUCT_OCR_KEY" not in workflow
    assert "LATEXSTRUCT_DECIDE_KEY" not in workflow
    assert "LATEXSTRUCT_REVIEW_KEY" not in workflow
