# -*- coding: utf-8 -*-
"""Immutable persistence and strict loading for OCR baseline bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from latexstruct.core.ocr_baseline import (
    OcrBaselineResult,
    OcrCompileInputFileEvidence,
    OcrCompileInvocationEvidence,
)
from latexstruct.core.ocr_artifacts import load_verified_ocr_baseline_bundle
from latexstruct.core.ocr_manifest import (
    DEFAULT_MANIFEST_PATH,
    OcrBaselineManifestBundle,
    build_ocr_baseline_manifest,
)
from latexstruct.core.ocr_runtime import (
    OcrPreviewStatus,
    OcrRunSnapshot,
    OcrRunStore,
    OcrStoreError,
    make_page_id,
    make_run_snapshot,
)
from latexstruct.server.app import (
    _persist_recomputable_ocr_baseline,
    _verified_v2_baseline_for_analysis,
)
from tests.test_ocr_manifest import (
    CREATED_AT,
    RUN_ID,
    _compile_execution_metadata,
    _fixture,
)


def _prepared_store(tmp_path: Path, *, compile_status: str = "COMPILED"):
    inputs = _fixture(compile_status=compile_status)
    bundle = build_ocr_baseline_manifest(**inputs)
    snapshot = OcrRunSnapshot.from_dict(json.loads(inputs["snapshot"].data))
    store = OcrRunStore(tmp_path / "runs")
    store.initialize(snapshot, inputs["source"].data)
    return store, snapshot, bundle


def test_bundle_commit_is_manifest_last_and_byte_identical_reentry_is_noop(
    tmp_path, monkeypatch,
):
    store, snapshot, bundle = _prepared_store(tmp_path)
    writes: list[str] = []
    original_write = store._atomic_write
    package_root = store.run_dir(snapshot.run_id) / "artifacts" / "ocr-baseline"

    def tracked_write(path: Path, data: bytes) -> None:
        writes.append(path.relative_to(package_root).as_posix())
        original_write(path, data)

    monkeypatch.setattr(store, "_atomic_write", tracked_write)
    manifest_path = store.save_ocr_baseline_bundle(snapshot.run_id, bundle)

    assert manifest_path == package_root / Path(DEFAULT_MANIFEST_PATH)
    assert writes[-1] == DEFAULT_MANIFEST_PATH
    first_writes = tuple(writes)
    assert {
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file()
    } == set(bundle.files())

    assert store.save_ocr_baseline_bundle(snapshot.run_id, bundle) == manifest_path
    assert tuple(writes) == first_writes

    loaded = load_verified_ocr_baseline_bundle(store, snapshot.run_id)
    assert loaded.manifest.sha256 == bundle.manifest.sha256
    assert loaded.baseline_tex.data == bundle.artifact_bytes()[
        loaded.baseline_tex.logical_path
    ]
    assert loaded.baseline_pdf is not None
    assert loaded.baseline_pdf.data.startswith(b"%PDF-")
    assert dict(loaded.artifact_bytes()) == dict(bundle.artifact_bytes())
    with pytest.raises(TypeError):
        loaded.artifacts_by_role["EXTRA"] = loaded.baseline_tex


@pytest.mark.parametrize(
    "invalid_path",
    [
        "../escape.tex",
        "/absolute/escape.tex",
        "C:/escape.tex",
        "nested\\escape.tex",
        "nested/../escape.tex",
    ],
)
def test_store_rejects_unsafe_bundle_paths_before_writing(tmp_path, invalid_path):
    store, snapshot, bundle = _prepared_store(tmp_path)
    invalid = OcrBaselineManifestBundle(
        manifest=bundle.manifest,
        artifacts=(*bundle.artifacts, (invalid_path, b"not allowed")),
    )

    with pytest.raises(OcrStoreError, match="path"):
        store.save_ocr_baseline_bundle(snapshot.run_id, invalid)

    package_root = store.run_dir(snapshot.run_id) / "artifacts" / "ocr-baseline"
    assert not package_root.exists()
    assert not (tmp_path / "escape.tex").exists()


def test_store_rejects_casefold_collisions_and_extra_existing_files(tmp_path):
    store, snapshot, bundle = _prepared_store(tmp_path)
    duplicate = OcrBaselineManifestBundle(
        manifest=bundle.manifest,
        artifacts=(*bundle.artifacts, bundle.artifacts[0]),
    )
    with pytest.raises(OcrStoreError, match="duplicate paths"):
        store.save_ocr_baseline_bundle(snapshot.run_id, duplicate)

    colliding = OcrBaselineManifestBundle(
        manifest=bundle.manifest,
        artifacts=(*bundle.artifacts, ("BASELINE/BASELINE.TEX", b"collision")),
    )
    with pytest.raises(OcrStoreError, match="case-insensitive"):
        store.save_ocr_baseline_bundle(snapshot.run_id, colliding)

    store.save_ocr_baseline_bundle(snapshot.run_id, bundle)
    package_root = store.run_dir(snapshot.run_id) / "artifacts" / "ocr-baseline"
    extra = package_root / "extra.txt"
    extra.write_bytes(b"unbound")

    with pytest.raises(OcrStoreError, match="extra file"):
        store.save_ocr_baseline_bundle(snapshot.run_id, bundle)
    with pytest.raises(OcrStoreError, match="extra file"):
        load_verified_ocr_baseline_bundle(store, snapshot.run_id)


@pytest.mark.parametrize("mutation", ["tamper", "missing"])
def test_loader_rejects_tampered_or_missing_described_artifacts(tmp_path, mutation):
    store, snapshot, bundle = _prepared_store(tmp_path)
    store.save_ocr_baseline_bundle(snapshot.run_id, bundle)
    manifest = bundle.manifest.to_dict()
    descriptor = next(
        item for item in manifest["artifacts"] if item["role"] == "BASELINE_TEX"
    )
    target = (
        store.run_dir(snapshot.run_id)
        / "artifacts"
        / "ocr-baseline"
        / Path(descriptor["path"])
    )
    if mutation == "tamper":
        target.write_bytes(target.read_bytes() + b"% tampered\n")
        expected = "failed verification"
    else:
        target.unlink()
        expected = "missing required files"

    with pytest.raises(OcrStoreError, match=expected):
        load_verified_ocr_baseline_bundle(store, snapshot.run_id)


def test_loader_exposes_no_baseline_pdf_for_source_preview(tmp_path):
    store, snapshot, bundle = _prepared_store(
        tmp_path,
        compile_status="SOURCE_PREVIEW",
    )
    store.save_ocr_baseline_bundle(snapshot.run_id, bundle)

    loaded = load_verified_ocr_baseline_bundle(store, snapshot.run_id)

    assert loaded.baseline_tex.data
    assert loaded.baseline_pdf is None


def test_production_finalizer_persists_exact_bundle_and_analysis_reads_only_it(
    tmp_path,
):
    inputs = _fixture()
    source_bytes = inputs["source"].data
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
        pipeline_contract={
            "page_strategies": [
                {"page_id": make_page_id(1)},
                {"page_id": make_page_id(2)},
            ],
            "verification_model": "gpt-test",
            "prompt_version": "ocr-v3",
            "git_commit": "c" * 40,
            "build_id": "32690000000",
            "dirty": False,
        },
        run_id=RUN_ID,
        started_at="2026-08-24T05:00:00.000Z",
    )
    store = OcrRunStore(tmp_path / "runs")
    store.initialize(snapshot, source_bytes)
    for record_input in json.loads(inputs["runtime_page_records"].data)["pages"]:
        response = {
            "page_id": record_input["page_id"],
            "latex": record_input["cleaned_tex"],
        }
        response_bytes = store._response_bytes(response)
        record_input["raw_response_sha256"] = hashlib.sha256(
            response_bytes
        ).hexdigest()
        record = store.load_record(snapshot.run_id, record_input["page_id"])
        terminal = record.__class__.from_dict(record_input)
        store.persist_record(snapshot.run_id, terminal, raw_response=response)
    store.freeze_raw_ocr(snapshot.run_id, model_usage={"calls": 2})

    baseline_tex_bytes = inputs["baseline_tex"].data
    baseline_pdf_bytes = inputs["baseline_pdf"].data
    compile_invocations = []
    for index in (1, 2):
        metadata = _compile_execution_metadata(
            baseline_tex_bytes,
            marker=index,
            extra_files={"figures/plot.pdf": b"exact figure bytes"},
        )
        compile_invocations.append(OcrCompileInvocationEvidence(
            sequence=index,
            exit_code=0,
            ok=True,
            engine="xelatex.exe",
            log=f"real pass {index} exit 0\n",
            input_tex_sha256=hashlib.sha256(baseline_tex_bytes).hexdigest(),
            output_pdf_sha256=hashlib.sha256(baseline_pdf_bytes).hexdigest(),
            passes_requested=1,
            passes_attempted=1,
            passes_completed=1,
            command=tuple(metadata["command"]),
            command_history=tuple(
                tuple(command) for command in metadata["command_history"]
            ),
            compile_workdir=str(metadata["compile_workdir"]),
            input_inventory=tuple(
                OcrCompileInputFileEvidence(
                    path=str(item["path"]),
                    byte_count=int(item["bytes"]),
                    sha256=str(item["sha256"]),
                )
                for item in metadata["input_inventory"]
            ),
            compile_input_sha256=str(metadata["compile_input_sha256"]),
            input_artifacts=tuple(metadata["input_files"]),
        ))
    baseline = OcrBaselineResult(
        tex=baseline_tex_bytes.decode("utf-8"),
        log="real pass 1 exit 0\nreal pass 2 exit 0\n",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=baseline_pdf_bytes,
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex.exe",
        compile_invocations=tuple(compile_invocations),
        page_map_json=inputs["page_map"].data,
    )

    class FrozenReports:
        def canonical_reports(self, *, now_seconds):
            assert now_seconds > 0
            return {
                "performance_metrics": inputs["performance_metrics"].data,
                "cost_report": inputs["cost_metrics"].data,
            }

    verified = _persist_recomputable_ocr_baseline(
        store,
        snapshot,
        SimpleNamespace(page_records_bytes=inputs["page_records"].data),
        baseline,
        FrozenReports(),
        created_at=CREATED_AT,
    )
    assert all(
        item["command"] and item["input_inventory"]
        for item in verified.manifest.to_dict()["compile"]["passes"]
    )

    analysis_tex, lineage = _verified_v2_baseline_for_analysis({
        "_v2_store": store,
        "_v2_snapshot": snapshot,
    })
    assert analysis_tex.encode("utf-8") == baseline_tex_bytes
    assert lineage["verified"] is True
    assert lineage["baseline_manifest_sha256"] == verified.manifest.sha256

    package_root = store.run_dir(snapshot.run_id) / "artifacts" / "ocr-baseline"
    (package_root / verified.baseline_tex.logical_path).write_bytes(
        baseline_tex_bytes + b"% tampered\n"
    )
    with pytest.raises(OcrStoreError, match="failed verification"):
        _verified_v2_baseline_for_analysis({
            "_v2_store": store,
            "_v2_snapshot": snapshot,
        })
