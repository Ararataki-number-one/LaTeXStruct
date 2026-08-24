from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest
import pymupdf

from latexstruct.core.compilecheck import (
    COMPILE_WORKDIR_ID_PREFIX,
    build_compile_input_manifest,
)
from latexstruct.core.ocr_manifest import (
    OCR_PRODUCER_SCHEMA,
    OCR_RUNTIME_PAGE_RECORDS_SCHEMA,
    ArtifactInput,
    CompilePassInput,
    build_ocr_baseline_manifest,
    canonical_json_bytes,
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
)
from latexstruct.core.ocr_page_map import build_pdf_page_map, extract_page_anchors
from latexstruct.core.ocr_runtime import (
    OcrPageRecord,
    OcrPageStatus,
    make_page_id,
    make_run_snapshot,
)


SCRIPT = Path(__file__).resolve().parents[1] / "packaging" / "release_integrity.py"
SPEC = importlib.util.spec_from_file_location("release_integrity", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VERSION = "2.0.0"
COMMIT = "d" * 40


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
        page_tex = f"Release fixture page {index} with $x_{index}$."
        record = OcrPageRecord(
            page_id=page_id,
            source_page=index,
            task_index=index,
            status=OcrPageStatus.SUCCESS,
            raw_response_sha256=_sha(f"response {index}".encode()),
            raw_tex=page_tex,
            cleaned_tex=page_tex,
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
        b"Recomputable release fixture\n\\end{document}\n"
    )
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
        "filename": "release-source.pdf",
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
        "filename": "release-source.pdf",
        "sha256": source_sha256,
        "total_pages": pages,
    }
    selected = {"start_page": 1, "end_page": pages, "expected_pages": pages}
    models = {
        "calls_total": 1 + (pages * 2),
        "roles": [
            {
                "role": "analysis",
                "model_id": "deepseek-real",
                "backend": "deepseek",
                "calls": 1,
            },
            {
                "role": "visual_review",
                "model_id": "deepseek-review-real",
                "backend": "deepseek",
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
        "candidate_tex": (
            b"\\documentclass{article}\n"
            b"\\begin{document}\nVerified candidate\n\\end{document}\n"
        ),
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
            "review_id": "final-review-a",
            "context_id": "context-a",
            "context_sha256": "1" * 64,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "model_id": "deepseek-review-real",
            "backend": "deepseek",
            "calls": pages,
        },
        {
            "review_id": "final-review-b",
            "context_id": "context-b",
            "context_sha256": "2" * 64,
            "independent": True,
            "result": "PASS",
            "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
            "pages_checked": pages,
            "model_id": "deepseek-review-real",
            "backend": "deepseek",
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
        "thresholds": {"maximum_wall_time_seconds": 10800},
        "target_met": True,
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
        real_execution=real_execution,
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
    visual_verification = {
        "passed": True,
        "expected_pages": pages,
        "pages_checked": pages,
        "independent_review_passes": 2,
        "model_calls": pages * 2,
        "page_id_set_sha256": "3" * 64,
        "candidate_tex_sha256": artifacts["candidate_tex"]["sha256"],
        "candidate_pdf_sha256": artifacts["candidate_pdf"]["sha256"],
        "render_compare_closed_loop": True,
    }
    page_layout = {
        "source_page_count": 37,
        "candidate_page_count": 38,
        "maximum_candidate_pages": 42,
        "page_growth": 1,
        "candidate_only_pages": [1],
        "candidate_mapping_sha256": "4" * 64,
        "no_abnormal_page_inflation": True,
        "active_tableofcontents_count": 1,
        "template": "faithfulbook",
    }
    audit_path = run_dir / "analysis-audit-submission.zip"
    audit_path.write_bytes(b"PK\x03\x04verified-private-audit-fixture")
    audit_submission = {
        "filename": audit_path.name,
        "bytes": audit_path.stat().st_size,
        "sha256": MODULE._sha256_file(audit_path),
        "packaging_status": "SUCCESS",
        "audit_package_status": "VALID",
        "verification_status": "VERIFIED",
        "published_to_github": False,
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


def _candidate_release_fixture(tmp_path: Path) -> dict[str, Path]:
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
    MODULE.assemble_release_attestation(
        version=VERSION,
        commit=COMMIT,
        run_dirs={
            "analysis-37": _valid_analysis_run(
                tmp_path / "analysis37", 37, executable_sha256=executable_sha
            )
        },
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
    assert verified["ocr_baseline"] == {
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
    syntax_bytes = (
        b"\\documentclass{article}\n\\begin{document}\n"
        b"Recomputable release fixture\n\\end{document}\n"
    )
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
    changelog.write_text(
        f"## v{VERSION}（待发布）\n\nLaTeXStruct-portable asset SHA-256: "
        f"{'f' * 64}\n\n## v1.0.0（旧）\nold\n",
        encoding="utf-8",
    )

    with pytest.raises(MODULE.ReleaseIntegrityError, match="hard-codes"):
        MODULE.verify_release_notes(changelog, VERSION)

    changelog.write_text(
        f"## v{VERSION}（待发布）\n\n摘要由 CI 的 SHA256SUMS.txt 动态生成。\n",
        encoding="utf-8",
    )
    MODULE.verify_release_notes(changelog, VERSION)


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
    assert verified["source"]["sha256"] == MODULE.RAMSEY_37_SOURCE_SHA256
    assert verified["evidence_publication"]["projection_only"] is True
    assert {path.name for path in manifest.parent.iterdir()} == {
        "release-attestation.json"
    }


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
    payload["independent_final_reviews"][1]["context_id"] = "context-a"
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
    assert "page_layout" in schema["required"]
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
    release_action = workflow.index("softprops/action-gh-release@v2")
    tag_job = workflow.index("release_attested_candidate:")
    candidate_job = workflow.index("build_candidate:")
    installer_signing = workflow.index("代码签名安装器（配置了证书 secrets 时）")
    final_installer_smoke = workflow.index("最终安装器字节绑定（签名后静默安装")
    assert workflow.index("git merge-base --is-ancestor") < release_action
    assert workflow.index("verify-attestation") < release_action
    assert installer_signing < final_installer_smoke < workflow.index("record-assets")
    assert "最终安装器内 EXE 与候选 EXE 字节不一致" in workflow
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath 'dist/LaTeXStruct.exe'" in workflow
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath $installedExe" in workflow
    assert workflow.index("record-assets") < workflow.index(
        "actions/upload-artifact@v4"
    ) < tag_job
    assert tag_job < workflow.index("actions/download-artifact@v4") < workflow.index(
        "verify-candidate-assets"
    ) < release_action
    assert "if: github.event_name == 'workflow_dispatch'" in workflow[
        candidate_job:tag_job
    ]
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
    assert "只能提交 release-attestation.json 哈希投影" in workflow
    assert "禁止上传源 PDF、候选 PDF、逐页图或完整审计包" in workflow
    assert "git ls-tree -r --name-only" in workflow
    assert "SOME RECENT RESULTS IN RAMSEY THEORY.pdf" in workflow
    assert "analysis-audit-submission.zip" in workflow
    assert "release/acceptance/v$env:APP_VERSION/" in workflow
    assert "dist/SHA256SUMS.txt" in workflow
    assert "dist/release-assets.json" in workflow
    assert "build-portable" in workflow
    assert "LaTeXStruct-portable-${{ env.APP_VERSION }}.zip" in workflow[tag_job:]
    assert "LaTeXStruct-setup-${{ env.APP_VERSION }}.exe" in workflow[tag_job:]
