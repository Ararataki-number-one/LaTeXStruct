# -*- coding: utf-8 -*-
"""Immutable persistence and strict loading for OCR baseline bundles."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from latexstruct.core.ocr_baseline import (
    OcrBaselineResult,
    OcrCompileInputFileEvidence,
    OcrCompileInvocationEvidence,
)
from latexstruct.core.ocr_artifacts import load_verified_ocr_baseline_bundle
from latexstruct.core.ocr_evidence_correction import (
    EvidenceCorrectionOperation,
    EvidenceCorrectionProductionInput,
    EvidenceCorrectionStatus,
    IndependentEvidenceVerification,
    SourceEvidenceAuthorization,
    produce_evidence_corrected_baseline_from_input,
    sha256_text,
)
from latexstruct.core.ocr_manifest import (
    ArtifactInput,
    DEFAULT_MANIFEST_PATH,
    OcrBaselineManifestError,
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
    _analysis_v2_snapshot_evidence,
    _persist_recomputable_ocr_baseline,
    _select_evidence_corrected_ocr_baseline,
    _verified_v2_baseline_for_analysis,
)
from tests.test_ocr_manifest import (
    CREATED_AT,
    RUN_ID,
    _compile_execution_metadata,
    _fixture,
    _with_measured_compile_evidence,
)
from tests.test_ocr_block_inventory import source_classification


def _prepared_store(tmp_path: Path, *, compile_status: str = "COMPILED"):
    inputs = _fixture(compile_status=compile_status)
    bundle = build_ocr_baseline_manifest(**inputs)
    snapshot = OcrRunSnapshot.from_dict(json.loads(inputs["snapshot"].data))
    store = OcrRunStore(tmp_path / "runs")
    store.initialize(snapshot, inputs["source"].data)
    return store, snapshot, bundle


def _production_correction_input(
    raw_tex: str,
    syntax_tex: str,
    *,
    authorized: bool = True,
) -> EvidenceCorrectionProductionInput:
    old_text = "Baseline"
    new_text = "Corrected"
    start = syntax_tex.index(old_text)
    source_page_sha = sha256_text("immutable source page one")
    source_evidence_sha = sha256_text("source evidence page one")
    operation = EvidenceCorrectionOperation(
        operation_id="correct-baseline-word",
        syntax_baseline_sha256=sha256_text(syntax_tex),
        page_id=make_page_id(1),
        source_page_number=1,
        start_offset=start,
        end_offset=start + len(old_text),
        old_text=old_text,
        new_text=new_text,
        reason="source evidence resolves the OCR word",
        source_page_sha256=source_page_sha,
        source_evidence_sha256=source_evidence_sha,
        recognition_model="deterministic-source-evidence",
    )
    if not authorized:
        return EvidenceCorrectionProductionInput(operations=(operation,))
    authorization = SourceEvidenceAuthorization(
        syntax_baseline_sha256=sha256_text(syntax_tex),
        page_id=make_page_id(1),
        source_page_number=1,
        syntax_start_offset=0,
        syntax_end_offset=len(syntax_tex),
        syntax_region_sha256=sha256_text(syntax_tex),
        source_page_sha256=source_page_sha,
        source_evidence_sha256=source_evidence_sha,
        authorized_operation_sha256s=(operation.digest,),
    )
    verification = IndependentEvidenceVerification(
        operation_sha256=operation.digest,
        source_evidence_sha256=source_evidence_sha,
        old_text_sha256=sha256_text(old_text),
        new_text_sha256=sha256_text(new_text),
        verification_evidence_sha256=sha256_text("independent correction verification"),
        verifier="independent-host-verifier",
        verdict="PASS",
        independent=True,
        math_unchanged=True,
        structure_unchanged=True,
    )
    # Keep the raw argument explicit in this test helper: the production
    # producer itself binds it in the report when the input is consumed.
    assert raw_tex.strip()
    return EvidenceCorrectionProductionInput(
        operations=(operation,),
        source_authorizations=(authorization,),
        independent_verifications=(verification,),
    )


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    target_is_directory: bool,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"filesystem symlink creation is unavailable: {exc}")


def _junction_or_skip(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows junction test")
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", os.fspath(link), os.fspath(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or not link.exists():
        pytest.skip("Windows junction creation is unavailable")


def _prepared_analysis_evidence_project(tmp_path: Path, monkeypatch) -> SimpleNamespace:
    inputs = _fixture()
    marker_baseline = (
        b"\\documentclass{article}\n"
        b"\\begin{document}\n"
        b"% Page 1\n"
        b"Page 1 with $x_1$.\n\n"
        b"% Page 2\n"
        b"Page 2 with $x_2$.\n"
        b"\\end{document}\n"
    )
    inputs["syntax_baseline"] = ArtifactInput(
        "SYNTAX_BASELINE_TEX", "baseline/syntax_baseline.tex", marker_baseline
    )
    inputs["baseline_tex"] = ArtifactInput(
        "BASELINE_TEX", "baseline/baseline.tex", marker_baseline
    )
    inputs = _with_measured_compile_evidence(inputs)
    bundle = build_ocr_baseline_manifest(**inputs)
    manifest = bundle.manifest.to_dict()
    producer = manifest["producer"]
    monkeypatch.setattr(
        "latexstruct.server.app._runtime_provenance_identity",
        lambda _prompt: {
            "app_version": producer["app_version"],
            "build_id": producer["build_id"],
            "commit": producer["git_commit"],
            "prompt_version": "analysis-prompts-v2",
        },
    )
    project = tmp_path / "project"
    package = project / "evidence" / "ocr-baseline"
    for logical_path, data in bundle.files().items():
        target = package / Path(logical_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    descriptors = {item["role"]: item for item in manifest["artifacts"]}

    def artifact(role: str) -> bytes:
        descriptor = descriptors[role]
        return bundle.artifact_bytes()[descriptor["path"]]

    raw_tex = artifact("RAW_OCR_TEX").decode("utf-8")
    baseline_tex = artifact("BASELINE_TEX").decode("utf-8")
    (project / "source.tex").write_bytes(artifact("BASELINE_TEX"))
    (project / "meta.json").write_text(json.dumps({
        "ocr_baseline_lineage": {
            "run_id": manifest["run_id"],
            "verified": True,
            "raw_ocr_sha256": descriptors["RAW_OCR_TEX"]["sha256"],
            "baseline_tex_sha256": descriptors["BASELINE_TEX"]["sha256"],
            "baseline_pdf_sha256": descriptors["BASELINE_PDF"]["sha256"],
            "baseline_manifest_sha256": bundle.manifest.sha256,
        }
    }), encoding="utf-8")
    return SimpleNamespace(
        artifact=artifact,
        baseline_tex=baseline_tex,
        bundle=bundle,
        descriptors=descriptors,
        manifest=manifest,
        package=package,
        project=project,
        raw_tex=raw_tex,
    )


def _snapshot_prepared_evidence(prepared: SimpleNamespace) -> dict[str, str]:
    return _analysis_v2_snapshot_evidence(
        project_dir=prepared.project,
        source_pdf_bytes=prepared.artifact("SOURCE"),
        raw_ocr_tex=prepared.raw_tex,
        baseline_tex=prepared.baseline_tex,
        baseline_pdf_bytes=prepared.artifact("BASELINE_PDF"),
        compile_extra_files={},
        page_numbers=(1, 2),
        candidate_page_map={1: (1,), 2: (2,)},
        candidate_mapping_evidence={
            "map": {"1": [1], "2": [2]},
            "mapping_sha256": "9" * 64,
        },
    )


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


def test_analysis_snapshot_evidence_recomputes_package_and_rejects_tamper(
    tmp_path, monkeypatch
):
    prepared = _prepared_analysis_evidence_project(tmp_path, monkeypatch)
    artifact = prepared.artifact
    baseline_tex = prepared.baseline_tex
    bundle = prepared.bundle
    descriptors = prepared.descriptors
    package = prepared.package
    project = prepared.project
    raw_tex = prepared.raw_tex

    risk_admission = {}
    evidence = _analysis_v2_snapshot_evidence(
        project_dir=project,
        source_pdf_bytes=artifact("SOURCE"),
        raw_ocr_tex=raw_tex,
        baseline_tex=baseline_tex,
        baseline_pdf_bytes=artifact("BASELINE_PDF"),
        compile_extra_files={},
        page_numbers=(1, 2),
        candidate_page_map={1: (1,), 2: (2,)},
        candidate_mapping_evidence={
            "map": {"1": [1], "2": [2]},
            "mapping_sha256": "9" * 64,
        },
        page_risk_admission_capture=risk_admission,
    )
    assert evidence["ocr_baseline_manifest_hash"] == bundle.manifest.sha256
    assert evidence["ocr_page_records_hash"] == descriptors["PAGE_RECORDS"]["sha256"]
    assert evidence["ocr_runtime_page_records_hash"] == (
        descriptors["RUNTIME_PAGE_RECORDS"]["sha256"]
    )
    assert evidence["ocr_page_map_hash"] == descriptors["PAGE_MAP"]["sha256"]
    assert evidence["page_risk_admission_hash"] == risk_admission["sha256"]
    assert risk_admission["strategy"] == (
        "deterministic-preflight-and-fixed-low-risk-sampling-v2"
    )
    assert risk_admission["page_count"] == 2
    assert risk_admission["payload"]["schema_version"] == (
        "latexstruct-analysis-page-risk-admission-v2"
    )
    assert risk_admission["payload"]["admission_sha256"] == risk_admission["sha256"]
    assert all(
        page["risk_level"] in {"R0", "R1", "R2", "R3"}
        and page["risk_reasons"]
        and page["summary"]["ocr_coverage_all_pass"] is True
        and not page["summary"]["required_evidence_missing"]
        and len(page["summary_sha256"]) == 64
        for page in risk_admission["payload"]["pages"]
    )

    transformed_tex = baseline_tex + "% deterministic structure candidate\n"
    transformed_evidence = _analysis_v2_snapshot_evidence(
        project_dir=project,
        source_pdf_bytes=artifact("SOURCE"),
        raw_ocr_tex=raw_tex,
        baseline_tex=transformed_tex,
        baseline_pdf_bytes=artifact("BASELINE_PDF"),
        compile_extra_files={},
        page_numbers=(1, 2),
        candidate_page_map={1: (1,), 2: (2,)},
        candidate_mapping_evidence={
            "map": {"1": [1], "2": [2]},
            "mapping_sha256": "9" * 64,
        },
    )
    assert (
        transformed_evidence["baseline_compile_inputs_hash"]
        != evidence["baseline_compile_inputs_hash"]
    )

    (project / "source.tex").write_bytes(artifact("BASELINE_TEX") + b"% tamper\n")
    with pytest.raises(ValueError, match="project source TEX differs"):
        _analysis_v2_snapshot_evidence(
            project_dir=project,
            source_pdf_bytes=artifact("SOURCE"),
            raw_ocr_tex=raw_tex,
            baseline_tex=transformed_tex,
            baseline_pdf_bytes=artifact("BASELINE_PDF"),
            compile_extra_files={},
            page_numbers=(1, 2),
            candidate_page_map={1: (1,), 2: (2,)},
            candidate_mapping_evidence={
                "map": {"1": [1], "2": [2]},
                "mapping_sha256": "9" * 64,
            },
        )
    (project / "source.tex").write_bytes(artifact("BASELINE_TEX"))

    page_records = package / Path(descriptors["PAGE_RECORDS"]["path"])
    page_records.write_bytes(page_records.read_bytes() + b"tamper")
    with pytest.raises(OcrBaselineManifestError, match="mismatch"):
        _analysis_v2_snapshot_evidence(
            project_dir=project,
            source_pdf_bytes=artifact("SOURCE"),
            raw_ocr_tex=raw_tex,
            baseline_tex=baseline_tex,
            baseline_pdf_bytes=artifact("BASELINE_PDF"),
            compile_extra_files={},
            page_numbers=(1, 2),
            candidate_page_map={1: (1,), 2: (2,)},
            candidate_mapping_evidence={
                "map": {"1": [1], "2": [2]},
                "mapping_sha256": "9" * 64,
            },
        )


@pytest.mark.parametrize(
    "invalid_manifest",
    [
        b'{"artifacts":[],"artifacts":[]}',
        b'{"artifacts":NaN}',
    ],
)
def test_analysis_snapshot_evidence_rejects_non_strict_manifest_json(
    tmp_path: Path,
    monkeypatch,
    invalid_manifest: bytes,
) -> None:
    prepared = _prepared_analysis_evidence_project(tmp_path, monkeypatch)
    (prepared.package / Path(DEFAULT_MANIFEST_PATH)).write_bytes(invalid_manifest)

    with pytest.raises(ValueError, match="manifest is not valid JSON"):
        _snapshot_prepared_evidence(prepared)


@pytest.mark.parametrize(
    "invalid_meta",
    [
        b'{"ocr_baseline_lineage":{},"ocr_baseline_lineage":{}}',
        b'{"ocr_baseline_lineage":NaN}',
    ],
)
def test_analysis_snapshot_evidence_rejects_non_strict_project_metadata_json(
    tmp_path: Path,
    monkeypatch,
    invalid_meta: bytes,
) -> None:
    prepared = _prepared_analysis_evidence_project(tmp_path, monkeypatch)
    (prepared.project / "meta.json").write_bytes(invalid_meta)

    with pytest.raises(ValueError, match="project metadata is missing or corrupt"):
        _snapshot_prepared_evidence(prepared)


@pytest.mark.parametrize(
    "location",
    ["project-root", "evidence-parent", "evidence-root", "artifact"],
)
def test_analysis_snapshot_evidence_rejects_symlink_in_evidence_path_chain(
    tmp_path: Path,
    monkeypatch,
    location: str,
) -> None:
    prepared = _prepared_analysis_evidence_project(tmp_path, monkeypatch)
    if location == "project-root":
        link = prepared.project
    elif location == "evidence-parent":
        link = prepared.project / "evidence"
    elif location == "evidence-root":
        link = prepared.package
    else:
        descriptor = prepared.descriptors["PAGE_RECORDS"]
        link = prepared.package / Path(descriptor["path"])
    external = tmp_path / f"external-{location}"
    link.rename(external)
    _symlink_or_skip(link, external, target_is_directory=external.is_dir())
    try:
        with pytest.raises(ValueError, match="link or reparse point"):
            _snapshot_prepared_evidence(prepared)
    finally:
        if link.is_symlink():
            link.unlink()


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
@pytest.mark.parametrize(
    "location",
    ["evidence-parent", "evidence-root", "artifact-parent"],
)
def test_analysis_snapshot_evidence_rejects_windows_junction_in_path_chain(
    tmp_path: Path,
    monkeypatch,
    location: str,
) -> None:
    prepared = _prepared_analysis_evidence_project(tmp_path, monkeypatch)
    if location == "evidence-parent":
        junction = prepared.project / "evidence"
    elif location == "evidence-root":
        junction = prepared.package
    else:
        descriptor = prepared.descriptors["PAGE_RECORDS"]
        junction = (prepared.package / Path(descriptor["path"])).parent
        if junction == prepared.package:
            pytest.skip("fixture has no nested artifact directory")
    external = tmp_path / f"external-{location}"
    junction.rename(external)
    _junction_or_skip(junction, external)
    try:
        with pytest.raises(ValueError, match="link or reparse point"):
            _snapshot_prepared_evidence(prepared)
    finally:
        if junction.exists():
            junction.rmdir()


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


def test_evidence_correction_selector_covers_noop_pass_and_failed_paths(
    monkeypatch,
):
    raw_tex = "% Page 1\nraw OCR\n"
    syntax_tex = "\\documentclass{article}\n\\begin{document}\nBaseline\\end{document}\n"
    syntax_baseline = SimpleNamespace(tex=syntax_tex)
    compile_calls: list[str] = []

    def fake_compile(tex, *, extra_files, selected_pages):
        compile_calls.append(tex)
        assert extra_files == {"figures/x.pdf": b"figure"}
        assert selected_pages == (1,)
        return SimpleNamespace(tex=tex)

    monkeypatch.setattr(
        "latexstruct.core.ocr_baseline.compile_ocr_baseline",
        fake_compile,
    )
    selected, noop = _select_evidence_corrected_ocr_baseline(
        raw_ocr_tex=raw_tex,
        syntax_baseline=syntax_baseline,
        production_input=EvidenceCorrectionProductionInput(),
        extra_files={"figures/x.pdf": b"figure"},
        selected_pages=(1,),
    )
    assert selected is syntax_baseline
    assert noop.report.status is EvidenceCorrectionStatus.NOT_APPLICABLE
    assert noop.evidence_tex is None
    assert compile_calls == []

    pass_input = _production_correction_input(raw_tex, syntax_tex)
    selected, passed = _select_evidence_corrected_ocr_baseline(
        raw_ocr_tex=raw_tex,
        syntax_baseline=syntax_baseline,
        production_input=pass_input,
        extra_files={"figures/x.pdf": b"figure"},
        selected_pages=(1,),
    )
    assert passed.report.status is EvidenceCorrectionStatus.PASS
    assert selected.tex == passed.evidence_tex
    assert compile_calls == [passed.evidence_tex]

    failed_input = _production_correction_input(
        raw_tex,
        syntax_tex,
        authorized=False,
    )
    with pytest.raises(OcrStoreError, match="failed closed"):
        _select_evidence_corrected_ocr_baseline(
            raw_ocr_tex=raw_tex,
            syntax_baseline=syntax_baseline,
            production_input=failed_input,
            extra_files={"figures/x.pdf": b"figure"},
            selected_pages=(1,),
        )
    assert compile_calls == [passed.evidence_tex]


@pytest.mark.parametrize("with_correction", [False, True])
def test_production_finalizer_persists_exact_bundle_and_analysis_reads_only_it(
    tmp_path,
    with_correction,
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

    syntax_baseline_bytes = inputs["baseline_tex"].data
    raw_ocr_tex = (store.run_dir(snapshot.run_id) / "artifacts" / "raw-ocr.tex").read_text(
        encoding="utf-8"
    )
    correction_input = (
        _production_correction_input(
            raw_ocr_tex,
            syntax_baseline_bytes.decode("utf-8"),
        )
        if with_correction
        else EvidenceCorrectionProductionInput()
    )
    correction_result = produce_evidence_corrected_baseline_from_input(
        raw_ocr_tex=raw_ocr_tex,
        syntax_baseline_tex=syntax_baseline_bytes.decode("utf-8"),
        production_input=correction_input,
    )
    baseline_tex_bytes = (
        correction_result.evidence_tex.encode("utf-8")
        if correction_result.evidence_tex is not None
        else syntax_baseline_bytes
    )
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
        source_classification=source_classification(
            source_sha256=snapshot.source_sha256,
            selected_pages=(1, 2),
        ),
        syntax_baseline_tex=syntax_baseline_bytes.decode("utf-8"),
        evidence_correction_input=correction_input,
    )
    verified_payload = verified.manifest.to_dict()
    assert all(
        item["command"] and item["input_inventory"]
        for item in verified_payload["compile"]["passes"]
    )
    expected_role = (
        "EVIDENCE_CORRECTED_BASELINE_TEX"
        if with_correction
        else "SYNTAX_BASELINE_TEX"
    )
    assert verified_payload["compile"]["selected_baseline"] == expected_role
    assert verified_payload["bindings"]["evidence_correction_report"] == (
        "EVIDENCE_CORRECTION_REPORT"
    )
    assert verified_payload["bindings"]["evidence_corrected_baseline"] == (
        "EVIDENCE_CORRECTED_BASELINE_TEX" if with_correction else None
    )
    assert verified_payload["bindings"]["block_inventory"] == (
        "OCR_BLOCK_INVENTORY"
    )
    correction_descriptor = next(
        item
        for item in verified_payload["artifacts"]
        if item["role"] == "EVIDENCE_CORRECTION_REPORT"
    )
    persisted_correction = json.loads(
        verified.artifact_bytes()[correction_descriptor["path"]]
    )
    assert persisted_correction["status"] == (
        "PASS" if with_correction else "NOT_APPLICABLE"
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
