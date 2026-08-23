# -*- coding: utf-8 -*-
"""Real-artifact acceptance harness for the 17-page Sharp Bounds audit bundle.

This harness deliberately consumes the original user-provided PDF/TEX files
and the historical compiler outputs already present in the workspace.  It does
not compile, OCR, synthesize a replacement PDF, or copy the large source PDF
into the repository.  The emitted ZIP is therefore useful for checking the
audit packager itself, while the JSON result keeps unavailable historical
evidence (notably the current compile log) explicit.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pymupdf


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from latexstruct.core.audit_evidence import (  # noqa: E402
    build_metrics,
    build_outline_evidence,
    build_report_json,
    compile_input_manifest_sha256,
    issues_csv_bytes,
    project_dependency_path,
    structured_blockers,
    template_manifest,
)
from latexstruct.core.audit_schema import (  # noqa: E402
    ArtifactRole,
    AuditDepth,
    AuditSubmissionRequest,
    AuditWorkflow,
    RunSnapshot,
    StageExecutionStatus,
    TerminalStatus,
)
from latexstruct.core.audit_submission import (  # noqa: E402
    build_audit_submission,
    make_audit_artifact,
)
from latexstruct.core.compilecheck import (  # noqa: E402
    build_compile_input_manifest,
    prepare_compile_inputs,
)
from latexstruct.elegantbook import (  # noqa: E402
    ELEGANTBOOK_VERSION,
    LICENSE_FILENAME,
    elegantbook_class_bytes,
    elegantbook_license_bytes,
)


TRUTH_PATH = ROOT / "benchmark" / "sharp_bounds_audit_truth_v1.json"


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default))).expanduser().resolve()


@dataclass(frozen=True)
class RealSharpBoundsPaths:
    source_pdf: Path
    raw_tex: Path
    analyzed_tex: Path
    current_tex: Path
    raw_partial_pdf: Path
    raw_compile_log: Path
    current_pdf: Path
    current_compile_log: Path
    current_qa: Path
    structure_report: Path
    report_md: Path

    @classmethod
    def discover(cls) -> "RealSharpBoundsPaths":
        home = Path.home()
        return cls(
            source_pdf=_env_path(
                "LATEXSTRUCT_SHARP_SOURCE_PDF",
                home / "Desktop" / "Sharp Bound to Multicolor Ramsey number.pdf",
            ),
            raw_tex=_env_path(
                "LATEXSTRUCT_SHARP_RAW_TEX",
                home
                / ".codex"
                / "attachments"
                / "10fc114e-d0f8-4c89-817b-2ce6bd348719"
                / "pasted-text.txt",
            ),
            analyzed_tex=_env_path(
                "LATEXSTRUCT_SHARP_ANALYZED_TEX",
                home
                / ".codex"
                / "attachments"
                / "c5900780-43e6-408c-9d10-8397540b8430"
                / "pasted-text.txt",
            ),
            current_tex=_env_path(
                "LATEXSTRUCT_SHARP_CURRENT_TEX",
                ROOT / "output" / "tex" / "Sharp-Bounds-LaTeXStruct-v1.2.5.tex",
            ),
            raw_partial_pdf=_env_path(
                "LATEXSTRUCT_SHARP_RAW_PARTIAL_PDF",
                ROOT / "tmp" / "sharp_bounds_compile" / "pasted-text.pdf",
            ),
            raw_compile_log=_env_path(
                "LATEXSTRUCT_SHARP_RAW_COMPILE_LOG",
                ROOT / "tmp" / "sharp_bounds_compile" / "pasted-text.log",
            ),
            current_pdf=_env_path(
                "LATEXSTRUCT_SHARP_CURRENT_PDF",
                ROOT / "output" / "pdf" / "Sharp-Bounds-LaTeXStruct-v1.2.5.pdf",
            ),
            current_compile_log=_env_path(
                "LATEXSTRUCT_SHARP_CURRENT_COMPILE_LOG",
                ROOT / "output" / "pdf" / "Sharp-Bounds-LaTeXStruct-v1.2.5.log",
            ),
            current_qa=_env_path(
                "LATEXSTRUCT_SHARP_CURRENT_QA",
                ROOT / "output" / "Sharp-Bounds-LaTeXStruct-v1.2.5-QA.json",
            ),
            structure_report=_env_path(
                "LATEXSTRUCT_SHARP_STRUCTURE_REPORT",
                ROOT / "output" / "Sharp-Bounds-LaTeXStruct-v1.2.5-structure.json",
            ),
            report_md=_env_path(
                "LATEXSTRUCT_SHARP_REPORT_MD",
                home
                / ".codex"
                / "attachments"
                / "54fe72ae-158d-4ab6-b7ed-3ad14450ae89"
                / "pasted-text.txt",
            ),
        )

    def required(self) -> tuple[Path, ...]:
        return (
            self.source_pdf,
            self.raw_tex,
            self.analyzed_tex,
            self.current_tex,
            self.raw_partial_pdf,
            self.raw_compile_log,
            self.current_pdf,
            self.current_qa,
            self.structure_report,
        )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _pdf_pages(data: bytes) -> int:
    with pymupdf.open(stream=data, filetype="pdf") as document:
        return int(document.page_count)


def _current_report_binding(
    path: Path,
    *,
    current_tex_sha256: str,
    current_pdf_sha256: str,
) -> tuple[bool, str]:
    """Fail closed unless a Markdown report identifies this exact v1.2.5 result."""
    if not path.is_file():
        return False, "current Markdown report was not persisted"
    text = path.read_text(encoding="utf-8-sig")
    if "app_version: 1.2.5" not in text:
        return False, "available Markdown report is not bound to app_version 1.2.5"
    if "verification_status: VERIFIED" not in text:
        return False, "available Markdown report is not bound to VERIFIED v1.2.5 QA"
    if f"current_tex_sha256: {current_tex_sha256}" not in text:
        return False, "available Markdown report is not bound to the current TeX bytes"
    if f"current_pdf_sha256: {current_pdf_sha256}" not in text:
        return False, "available Markdown report is not bound to the current PDF bytes"
    return True, "bound to exact current TeX/PDF bytes and VERIFIED v1.2.5 QA"


def _source_outline(data: bytes) -> list[dict[str, object]]:
    with pymupdf.open(stream=data, filetype="pdf") as document:
        return [
            {"level": int(level) - 1, "title": str(title), "page": int(page)}
            for level, title, page in document.get_toc(simple=True)
        ]


def _compile_manifest(
    *,
    tex: str,
    extra_files: dict[str, bytes],
    main_artifact,
    preview_sha256: str,
    scope: str,
    recorded_compile_input_sha256: str,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    prepared = prepare_compile_inputs(tex, extra_files)
    base = build_compile_input_manifest(tex, extra_files)
    recorded_compile_input_sha256 = str(recorded_compile_input_sha256 or "")
    if recorded_compile_input_sha256 != base["manifest_sha256"]:
        raise AssertionError(
            f"real {scope} recorded compile-input hash does not match "
            "the recomputed physical closure"
        )
    assets: list[tuple[str, bytes]] = []
    packaged_files: list[dict[str, object]] = []
    for relative, payload in sorted(prepared.items()):
        if relative == "main.tex":
            packaged_path = main_artifact.path
            artifact_role = main_artifact.artifact_role
            artifact_id = main_artifact.artifact_id
        else:
            packaged_path = project_dependency_path(relative)
            if scope == "raw":
                packaged_path = f"project/raw/{Path(packaged_path).relative_to('project').as_posix()}"
            artifact_role = ArtifactRole.PROJECT_FILE
            artifact_id = None
            assets.append((packaged_path, payload))
        packaged_files.append(
            {
                "path": relative,
                "packaged_path": packaged_path,
                "artifact_role": artifact_role,
                "artifact_id": artifact_id,
                "bytes": len(payload),
                "bytes_sha256": _sha(payload),
                "required_for_compile": True,
                "source": f"real Sharp Bounds {scope} compile closure",
            }
        )
    return (
        {
            **base,
            "compile_scope": scope,
            "main_artifact_id": main_artifact.artifact_id,
            "main_artifact_path": main_artifact.path,
            "preview_artifact_sha256": preview_sha256,
            "recorded_compile_input_sha256": recorded_compile_input_sha256,
            "packaged_files": packaged_files,
            "complete": True,
            "completeness_reasons": [],
        },
        assets,
    )


def build_real_snapshot(paths: RealSharpBoundsPaths) -> tuple[RunSnapshot, dict[str, object]]:
    missing = [str(path) for path in paths.required() if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing real Sharp Bounds artifacts:\n" + "\n".join(missing))

    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    source_truth = truth["source_pdf"]
    source_pdf_facts = {
        "page_count": int(source_truth["page_count"]),
        "selected_page_range": dict(source_truth["selected_page_range"]),
    }
    source_pdf = paths.source_pdf.read_bytes()
    raw_tex_bytes = paths.raw_tex.read_bytes()
    analyzed_tex_bytes = paths.analyzed_tex.read_bytes()
    current_tex_bytes = paths.current_tex.read_bytes()
    raw_pdf = paths.raw_partial_pdf.read_bytes()
    current_pdf = paths.current_pdf.read_bytes()
    raw_log = paths.raw_compile_log.read_bytes()
    qa = json.loads(paths.current_qa.read_text(encoding="utf-8"))
    structure = json.loads(paths.structure_report.read_text(encoding="utf-8"))
    report_md_bound, report_md_binding_reason = _current_report_binding(
        paths.report_md,
        current_tex_sha256=_sha(current_tex_bytes),
        current_pdf_sha256=_sha(current_pdf),
    )
    current_text = current_tex_bytes.decode("utf-8-sig")
    raw_text = raw_tex_bytes.decode("utf-8-sig")

    observed = {
        "source_pdf_sha256": _sha(source_pdf),
        "source_pdf_byte_count": len(source_pdf),
        "source_pdf_pages": _pdf_pages(source_pdf),
        "raw_tex_sha256": _sha(raw_tex_bytes),
        "analyzed_tex_sha256": _sha(analyzed_tex_bytes),
        "current_tex_sha256": _sha(current_tex_bytes),
        "raw_partial_pdf_sha256": _sha(raw_pdf),
        "raw_partial_pdf_pages": _pdf_pages(raw_pdf),
        "current_pdf_sha256": _sha(current_pdf),
        "current_pdf_pages": _pdf_pages(current_pdf),
        "current_compile_log_present": paths.current_compile_log.is_file(),
        "report_md_present": paths.report_md.is_file(),
        "report_md_bound_to_current": report_md_bound,
        "report_md_binding_reason": report_md_binding_reason,
    }
    assert observed["source_pdf_sha256"] == source_truth["bytes_sha256"]
    assert observed["source_pdf_byte_count"] == source_truth["byte_count"]
    assert observed["source_pdf_pages"] == source_truth["page_count"] == 17
    assert source_pdf_facts["selected_page_range"] == {
        "start": 1,
        "end": 17,
        "pages": list(range(1, 18)),
    }
    assert observed["raw_partial_pdf_pages"] == truth["raw_ocr_preview"]["page_count"] == 2
    assert observed["current_pdf_pages"] == truth["current_preview"]["page_count"] == 17
    assert observed["raw_tex_sha256"] == qa["raw_tex_sha256"]
    assert observed["current_tex_sha256"] == qa["output_tex_sha256"]
    assert observed["current_pdf_sha256"] == qa["output_pdf_sha256"]
    assert truth["required_raw_tex_token"] in raw_text
    assert truth["required_current_tex_token"] in current_text
    assert truth["forbidden_tex_token"] not in raw_text
    assert truth["forbidden_tex_token"] not in current_text

    source_artifact = make_audit_artifact(
        ArtifactRole.SOURCE_PDF,
        source_pdf,
        media_type="application/pdf",
    )
    raw_artifact = make_audit_artifact(
        ArtifactRole.RAW_OCR_TEX,
        raw_tex_bytes,
        media_type="application/x-tex",
        parent_artifact_ids=(source_artifact.artifact_id,),
    )
    analyzed_artifact = make_audit_artifact(
        ArtifactRole.AI_ANALYZED_TEX,
        analyzed_tex_bytes,
        media_type="application/x-tex",
        parent_artifact_ids=(raw_artifact.artifact_id,),
    )
    current_artifact = make_audit_artifact(
        ArtifactRole.CURRENT_TEX,
        current_tex_bytes,
        media_type="application/x-tex",
        parent_artifact_ids=(analyzed_artifact.artifact_id,),
    )
    raw_preview = make_audit_artifact(
        ArtifactRole.RAW_OCR_PREVIEW,
        raw_pdf,
        media_type="application/pdf",
        preview_status="PARTIAL_COMPILED",
        parent_artifact_ids=(raw_artifact.artifact_id,),
        metadata={
            "engine": "xelatex",
            "passes_attempted": 1,
            "exit_code": 1,
            "page_count": 2,
            "pdf_sha256": _sha(raw_pdf),
            "fatal_line": 95,
            "fatal_error": "Missing $ inserted.",
            "log_path": "audit/compile_raw.log",
        },
    )
    current_preview = make_audit_artifact(
        ArtifactRole.CURRENT_PREVIEW,
        current_pdf,
        media_type="application/pdf",
        preview_status="COMPILED",
        parent_artifact_ids=(current_artifact.artifact_id,),
        metadata={
            "engine": str(qa.get("compile_engine") or "unknown"),
            "page_count": truth["current_preview"]["page_count"],
            "pdf_sha256": _sha(current_pdf),
            "binding_evidence": "audit/verification.json",
        },
    )

    class_bytes = elegantbook_class_bytes()
    license_bytes = elegantbook_license_bytes()
    current_manifest, current_assets = _compile_manifest(
        tex=current_text,
        extra_files={"elegantbook.cls": class_bytes},
        main_artifact=current_artifact,
        preview_sha256=_sha(current_pdf),
        scope="current",
        recorded_compile_input_sha256=str(
            qa.get("compile_input_sha256")
            or truth["current_preview"]["compile_input_sha256"]
        ),
    )
    raw_manifest, raw_assets = _compile_manifest(
        tex=raw_text,
        extra_files={},
        main_artifact=raw_artifact,
        preview_sha256=_sha(raw_pdf),
        scope="raw",
        recorded_compile_input_sha256=str(
            truth["raw_ocr_preview"]["compile_input_sha256"]
        ),
    )
    assert not raw_assets

    artifacts = [
        source_artifact,
        raw_artifact,
        analyzed_artifact,
        current_artifact,
        raw_preview,
        current_preview,
        make_audit_artifact(
            ArtifactRole.COMPILE_RAW_LOG,
            raw_log,
            media_type="text/plain; charset=utf-8",
            parent_artifact_ids=(raw_artifact.artifact_id,),
        ),
    ]
    if paths.current_compile_log.is_file():
        artifacts.append(
            make_audit_artifact(
                ArtifactRole.COMPILE_CURRENT_LOG,
                paths.current_compile_log.read_bytes(),
                media_type="text/plain; charset=utf-8",
                parent_artifact_ids=(current_artifact.artifact_id,),
            )
        )

    class_asset = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        class_bytes,
        path=current_assets[0][0],
        media_type="application/x-tex",
        parent_artifact_ids=(current_artifact.artifact_id,),
        metadata={"required_for_compile": True, "compile_relative_path": "elegantbook.cls"},
    )
    license_path = f"project/LICENSES/{LICENSE_FILENAME}"
    license_asset = make_audit_artifact(
        ArtifactRole.PROJECT_FILE,
        license_bytes,
        path=license_path,
        media_type="text/plain; charset=utf-8",
        parent_artifact_ids=(class_asset.artifact_id,),
        metadata={"required_for_compile": False, "license_for": "elegantbook.cls"},
    )
    artifacts.extend((class_asset, license_asset))
    class_row = next(
        row for row in current_manifest["packaged_files"] if row["path"] == "elegantbook.cls"
    )
    class_row["artifact_id"] = class_asset.artifact_id
    class_row["parent_artifact_ids"] = [current_artifact.artifact_id]
    class_row["license_path"] = license_path
    current_main_row = next(
        row for row in current_manifest["packaged_files"] if row["path"] == "main.tex"
    )
    current_main_row["parent_artifact_ids"] = [analyzed_artifact.artifact_id]
    raw_main_row = next(
        row for row in raw_manifest["packaged_files"] if row["path"] == "main.tex"
    )
    raw_main_row["parent_artifact_ids"] = [source_artifact.artifact_id]
    artifacts.extend(
        (
            make_audit_artifact(
                ArtifactRole.COMPILE_INPUT_MANIFEST,
                _json_bytes(current_manifest),
                media_type="application/json",
                parent_artifact_ids=(current_artifact.artifact_id, class_asset.artifact_id),
            ),
            make_audit_artifact(
                ArtifactRole.RAW_COMPILE_INPUT_MANIFEST,
                _json_bytes(raw_manifest),
                media_type="application/json",
                parent_artifact_ids=(raw_artifact.artifact_id,),
            ),
            make_audit_artifact(
                ArtifactRole.TEMPLATE_MANIFEST,
                _json_bytes(
                    template_manifest(
                        template_id="elegantbook",
                        template_version=ELEGANTBOOK_VERSION,
                        assets=[class_row],
                    )
                ),
                media_type="application/json",
                parent_artifact_ids=(class_asset.artifact_id, license_asset.artifact_id),
            ),
        )
    )

    rejected = [
        {"title": row["title"], "page": row["page"], "reason": row["reason"]}
        for row in truth["outline"]
        if row["status"] == "REJECTED"
    ]
    verification = {
        **qa,
        "raw_preview_state": "PARTIAL_COMPILED",
        "preview_state": "COMPILED",
        "compile_before": {
            "preview_status": "PARTIAL_COMPILED",
            "page_count": 2,
            "pdf_sha256": _sha(raw_pdf),
        },
        "compile_after": {
            "preview_status": "COMPILED",
            "page_count": truth["current_preview"]["page_count"],
            "pdf_sha256": _sha(current_pdf),
        },
        "ocr_structure": {
            "expected": truth["outline_accepted"],
            "matched": truth["outline_accepted"],
            "rejected_outline": rejected,
        },
        "structure_decisions": {
            "formal_total": qa["formal_total"],
            "formal_wrapped": qa["formal_wrapped"],
            "formal_residual_ids": qa["formal_residual_ids"],
        },
        "invariants": {
            "body_text": {"checked": True, "equal": bool(qa["content_invariant"])},
            "math": {"checked": True, "equal": bool(qa["content_invariant"])},
        },
    }
    outline = build_outline_evidence(_source_outline(source_pdf), current_text, verification)
    assert outline is not None
    assert outline["accepted_count"] == truth["outline_accepted"] == 9
    assert outline["rejected_count"] == truth["outline_rejected"] == 1
    assert outline["unresolved_count"] == truth["outline_unresolved"] == 0

    blockers = structured_blockers([])
    metrics = build_metrics(
        source_pdf=source_pdf_facts,
        outline_evidence=outline,
        verification=verification,
        current_tex=current_text,
    )
    report_json = build_report_json(
        source_run_status="SUCCESS",
        verification_status="VERIFIED" if qa.get("safe_to_export") is True else "UNVERIFIED",
        stages={
            "ocr": "COMPLETED",
            "analysis": "COMPLETED",
            "review": "SKIPPED",
            "template": "COMPLETED",
        },
        blockers=blockers,
        metrics=metrics,
    )
    decisions = {
        "schema_version": "latexstruct-sharp-bounds-decisions-evidence-v1",
        "source": paths.structure_report.name,
        "exact_structure": structure.get("exact_structure"),
        "document_structure": structure.get("document_structure"),
    }
    diff = "".join(
        difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            current_text.splitlines(keepends=True),
            fromfile="stages/00_raw_ocr.tex",
            tofile="stages/30_current.tex",
        )
    ).encode("utf-8")
    artifacts.extend(
        (
            make_audit_artifact(
                ArtifactRole.OUTLINE,
                _json_bytes(outline),
                media_type="application/json",
                parent_artifact_ids=(source_artifact.artifact_id, current_artifact.artifact_id),
            ),
            make_audit_artifact(
                ArtifactRole.VERIFICATION,
                _json_bytes(verification),
                media_type="application/json",
                parent_artifact_ids=(raw_preview.artifact_id, current_preview.artifact_id),
            ),
            make_audit_artifact(
                ArtifactRole.DECISIONS,
                _json_bytes(decisions),
                media_type="application/json",
                parent_artifact_ids=(analyzed_artifact.artifact_id,),
            ),
            make_audit_artifact(
                ArtifactRole.RAW_TO_CURRENT_DIFF,
                diff,
                media_type="text/x-diff; charset=utf-8",
                parent_artifact_ids=(raw_artifact.artifact_id, current_artifact.artifact_id),
            ),
            make_audit_artifact(
                ArtifactRole.REPORT_JSON,
                _json_bytes(report_json),
                media_type="application/json",
                parent_artifact_ids=(current_artifact.artifact_id,),
            ),
            make_audit_artifact(
                ArtifactRole.ISSUES_CSV,
                issues_csv_bytes(blockers),
                media_type="text/csv; charset=utf-8",
                parent_artifact_ids=(current_artifact.artifact_id,),
            ),
            make_audit_artifact(
                ArtifactRole.METRICS,
                _json_bytes(metrics),
                media_type="application/json",
                parent_artifact_ids=(current_artifact.artifact_id,),
            ),
        )
    )
    if report_md_bound:
        artifacts.append(
            make_audit_artifact(
                ArtifactRole.REPORT,
                paths.report_md.read_bytes(),
                media_type="text/markdown; charset=utf-8",
                parent_artifact_ids=(current_artifact.artifact_id,),
            )
        )
    snapshot = RunSnapshot(
        project_id="sharp-bounds-real-17-page",
        run_id="sharp-bounds-v125-real-artifacts",
        workflow=AuditWorkflow.OCR_ANALYSIS_REVIEW,
        terminal_status=TerminalStatus.SUCCESS,
        captured_at="2026-08-21T12:49:10Z",
        artifacts=tuple(artifacts),
        machine_verification=verification,
        model="unknown",
        app_version="1.2.5",
        template="elegantbook",
        page_range="1-17",
        stages={
            "ocr": {"status": StageExecutionStatus.COMPLETED.value, "checked": True},
            "analysis": {"status": StageExecutionStatus.COMPLETED.value, "checked": True},
            "review": {
                "status": StageExecutionStatus.SKIPPED.value,
                "checked": False,
                "reason": "historical run did not persist an independent AI review output",
            },
            "template": {"status": StageExecutionStatus.COMPLETED.value, "checked": True},
        },
        source_pdf=source_pdf_facts,
        provenance={
            "runtime": {
                "app_version": "1.2.5",
                "git_commit": None,
                "dirty": None,
                "status": "UNKNOWN",
                "reason": "historical run did not persist build identity",
                "started_at": None,
                "finished_at": "2026-08-21T12:49:10Z",
            },
            "models": {
                "ocr": {"status": "UNKNOWN", "model": None},
                "decision": {"status": "UNKNOWN", "model": None},
                "review": {"status": "SKIPPED", "model": None},
            },
            "prompts": {},
            "template": {"id": "elegantbook", "version": ELEGANTBOOK_VERSION},
        },
        metadata={
            "project_name": "Sharp Bounds",
            "fixture_truth": str(TRUTH_PATH),
            "historical_evidence_limitations": (
                (
                    []
                    if paths.current_compile_log.is_file()
                    else ["current compile log was not persisted"]
                )
                + ([] if report_md_bound else [report_md_binding_reason])
            ),
        },
    )
    return snapshot, observed


def _verify_sums(files: dict[str, bytes]) -> dict[str, object]:
    if "audit/SHA256SUMS" not in files:
        return {
            "listed_count": 0,
            "expected_count": len(files),
            "coverage": 0.0,
            "missing": sorted(files),
            "unexpected": [],
            "mismatches": [],
            "reason": "normal audit package was suppressed; SHA256SUMS is absent",
        }
    listed: dict[str, str] = {}
    for line in files["audit/SHA256SUMS"].decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    mismatches = [
        name for name, digest in listed.items() if _sha(files[name]) != digest
    ]
    expected = set(files) - {"audit/SHA256SUMS"}
    return {
        "listed_count": len(listed),
        "expected_count": len(expected),
        "coverage": len(set(listed) & expected) / len(expected),
        "missing": sorted(expected - set(listed)),
        "unexpected": sorted(set(listed) - expected),
        "mismatches": mismatches,
    }


def run_acceptance(paths: RealSharpBoundsPaths, output_zip: Path | None = None) -> dict[str, object]:
    snapshot, observed = build_real_snapshot(paths)
    result = build_audit_submission(
        snapshot,
        AuditSubmissionRequest(depth=AuditDepth.STANDARD),
        submission_id="sharp-bounds-real-standard-v127",
        generated_at="2026-08-23T00:00:00Z",
    )
    if output_zip is not None:
        output_zip.parent.mkdir(parents=True, exist_ok=True)
        output_zip.write_bytes(result.zip_bytes)
    with zipfile.ZipFile(Path(output_zip), "r") if output_zip else zipfile.ZipFile(
        __import__("io").BytesIO(result.zip_bytes), "r"
    ) as archive:
        zip_names = archive.namelist()
    tex_paths = [
        name for name in result.files if Path(name).suffix.casefold() in {".tex", ".cls", ".sty"}
    ]
    truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
    tex_payload = b"\n".join(result.files[name] for name in tex_paths)
    expected_diff = "".join(
        difflib.unified_diff(
            paths.raw_tex.read_bytes().decode("utf-8-sig").splitlines(keepends=True),
            paths.current_tex.read_bytes().decode("utf-8-sig").splitlines(keepends=True),
            fromfile="stages/00_raw_ocr.tex",
            tofile="stages/30_current.tex",
        )
    ).encode("utf-8")
    packaged_diff = result.files.get("audit/raw_to_current.diff", b"")
    textual_payload = b"\n".join(
        payload
        for name, payload in result.files.items()
        if Path(name).suffix.casefold()
        in {".tex", ".cls", ".sty", ".txt", ".md", ".json", ".csv", ".diff", ".log"}
    )
    byte_identity = {
        "source_pdf": result.files.get("inputs/source.pdf") == paths.source_pdf.read_bytes(),
        "raw_tex": result.files.get("stages/00_raw_ocr.tex") == paths.raw_tex.read_bytes(),
        "analyzed_tex": (
            result.files.get("stages/10_ai_analyzed.tex") == paths.analyzed_tex.read_bytes()
        ),
        "current_tex": (
            result.files.get("stages/30_current.tex") == paths.current_tex.read_bytes()
        ),
        "raw_partial_pdf": (
            result.files.get("previews/raw_ocr_PARTIAL_COMPILED.pdf")
            == paths.raw_partial_pdf.read_bytes()
        ),
        "current_pdf": (
            result.files.get("previews/current.pdf") == paths.current_pdf.read_bytes()
        ),
        "raw_to_current_diff": packaged_diff == expected_diff,
        "template_class": (
            result.files.get("project/class-style-assets/elegantbook.cls")
            == elegantbook_class_bytes()
        ),
        "template_license": (
            result.files.get(f"project/LICENSES/{LICENSE_FILENAME}")
            == elegantbook_license_bytes()
        ),
    }
    manifest = result.manifest.to_dict()
    forbidden_token = truth["forbidden_tex_token"].encode()
    absolute_path_leaks = [
        needle.decode("utf-8")
        for needle in (
            str(Path.home()).encode("utf-8"),
            str(Path.home()).replace("\\", "/").encode("utf-8"),
        )
        if needle in textual_payload
    ]
    packaging_integrity = json.loads(
        result.files["audit/packaging-integrity.json"].decode("utf-8-sig")
    )
    outline_evidence = json.loads(result.files["evidence/outline.json"].decode("utf-8-sig"))
    metrics_evidence = json.loads(result.files["audit/metrics.json"].decode("utf-8-sig"))
    compile_input_evidence = {
        "current": json.loads(
            result.files["audit/compile-input-manifest.json"].decode("utf-8-sig")
        ),
        "raw": json.loads(
            result.files["audit/compile-input-raw-manifest.json"].decode("utf-8-sig")
        ),
    }
    compile_input_bindings = {
        name: {
            "manifest_sha256": payload["manifest_sha256"],
            "recorded_compile_input_sha256": payload[
                "recorded_compile_input_sha256"
            ],
            "recomputed_manifest_sha256": compile_input_manifest_sha256(payload),
            "valid": (
                payload["manifest_sha256"]
                == payload["recorded_compile_input_sha256"]
                == compile_input_manifest_sha256(payload)
            ),
        }
        for name, payload in compile_input_evidence.items()
    }
    prompt_short = result.files["01_PROMPT_SHORT.txt"].decode("utf-8").strip()
    prompt_full = result.files["02_PROMPT_FULL.md"].decode("utf-8")
    prompt_table_paths: list[str] = []
    for line in prompt_full.splitlines():
        if not line.startswith("| ") or line.startswith(("| artifact_role", "|---")):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) >= 2 and columns[1] in result.files:
            prompt_table_paths.append(columns[1])
        elif len(columns) >= 2 and "/" in columns[1]:
            prompt_table_paths.append(columns[1])
    prompt_missing_paths = sorted(set(prompt_table_paths) - set(result.files))
    current_preview_record = next(
        item
        for item in manifest["artifacts"]
        if item["artifact_role"] == ArtifactRole.CURRENT_PREVIEW
    )
    source_pdf_record = next(
        item
        for item in manifest["artifacts"]
        if item["artifact_role"] == ArtifactRole.SOURCE_PDF
    )
    return {
        "schema": "latexstruct-sharp-bounds-audit-acceptance-v1",
        "real_artifacts": observed,
        "submission_id": result.submission_id,
        "snapshot_id": result.snapshot_id,
        "zip_sha256": result.zip_sha256,
        "zip_bytes": len(result.zip_bytes),
        "zip_member_count": len(zip_names),
        "zip_members": sorted(zip_names),
        "source_run_status": manifest["source_run_status"],
        "verification_status": manifest["verification_status"],
        "packaging_status": manifest["packaging_status"],
        "audit_package_status": manifest["audit_package_status"],
        "source_pdf": manifest["source_pdf"],
        "source_pdf_artifact": {
            key: source_pdf_record[key]
            for key in ("path", "bytes_sha256", "byte_count")
        },
        "stages": manifest["stages"],
        "missing_expected_roles": manifest["missing_expected_roles"],
        "missing_expected_role_details": manifest["missing_expected_role_details"],
        "byte_identity": byte_identity,
        "all_primary_artifacts_byte_identical": all(byte_identity.values()),
        "raw_math_token_preserved": truth["required_raw_tex_token"].encode() in tex_payload,
        "current_math_token_preserved": truth["required_current_tex_token"].encode() in tex_payload,
        "diff_math_token_preserved": (
            truth["required_raw_tex_token"].encode() in packaged_diff
            and truth["required_current_tex_token"].encode() in packaged_diff
        ),
        "forbidden_tex_token_absent": forbidden_token not in tex_payload,
        "forbidden_token_absent_all_text_evidence": forbidden_token not in textual_payload,
        "absolute_path_leaks": absolute_path_leaks,
        "tex_content_gate_valid": packaging_integrity.get("tex_content_gate_valid") is True,
        "packaging_integrity_valid": packaging_integrity.get("valid") is True,
        "compile_input_bindings": compile_input_bindings,
        "current_preview_binding_evidence": current_preview_record["metadata"].get(
            "binding_evidence"
        ),
        "current_preview_engine": current_preview_record["metadata"].get("engine"),
        "prompt_short": prompt_short,
        "prompt_full_sha256": _sha(result.files["02_PROMPT_FULL.md"]),
        "prompt_references_existing_files_only": not prompt_missing_paths,
        "prompt_missing_paths": prompt_missing_paths,
        "outline": {
            key: outline_evidence[key]
            for key in ("accepted_count", "rejected_count", "unresolved_count")
        },
        "metrics": {
            key: metrics_evidence[key]
            for key in (
                "source_pages",
                "selected_pages",
                "outline_total",
                "outline_accepted",
                "outline_rejected",
                "outline_unresolved",
                "compile_raw_status",
                "compile_current_status",
            )
        },
        "raw_preview_member": "previews/raw_ocr_PARTIAL_COMPILED.pdf" in result.files,
        "current_preview_member": "previews/current.pdf" in result.files,
        "template_class_member": "project/class-style-assets/elegantbook.cls" in result.files,
        "template_license_member": f"project/LICENSES/{LICENSE_FILENAME}" in result.files,
        "sha256sums": _verify_sums(dict(result.files)),
        "output_zip": str(output_zip) if output_zip else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-zip", type=Path)
    parser.add_argument("--output-json", type=Path)
    args = parser.parse_args()
    report = run_acceptance(RealSharpBoundsPaths.discover(), args.output_zip)
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
