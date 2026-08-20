# -*- coding: utf-8 -*-
"""Unit and synthetic-PDF tests for formula evidence preparation."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from latexstruct.core import ocrformula as formula


def _span(text, font, bbox, *, size=10.0, origin_y=None):
    return {
        "text": text,
        "font": font,
        "size": size,
        "bbox": bbox,
        "origin": (bbox[0], bbox[3] - 3.0 if origin_y is None else origin_y),
    }


def _payload(*lines):
    return {"blocks": [{"type": 0, "lines": [{"spans": line} for line in lines]}]}


def _region(index=1, page=7):
    return formula.FormulaRegion(
        region_id=f"p{page:04d}-f{index:03d}",
        page=page,
        bbox_points=(100.0, 120.0, 180.0, 145.0),
        score=8.5,
        text_hint="x / y",
        fonts=("CMMI10", "CMR7"),
        evidence=("display-geometry", "operator", "script-size"),
    )


def _evidence(tmp_path: Path, *, index=1, page=7):
    crop = tmp_path / f"crop-{index}.png"
    crop.write_bytes(b"deterministic synthetic crop " + str(index).encode("ascii"))
    return formula.FormulaEvidence(
        region=_region(index, page),
        crop_path=crop,
        crop_bbox_points=(88.0, 110.0, 192.0, 155.0),
        image_sha256=formula.sha256_file(crop),
        image_size_pixels=(607, 263),
        dpi=420,
    )


def _identity(**changes):
    base = formula.FormulaCacheIdentity(
        backend="codex_cli",
        model="test-model",
        reasoning_effort="medium",
        prompt_version="formula-prompt-v1",
        prompt_sha256="1" * 64,
        schema_version="formula-schema-v1",
        schema_sha256="2" * 64,
    )
    return dataclasses.replace(base, **changes)


def _valid_result(region_id):
    return {
        "id": region_id,
        "latex": r"\frac{x_i}{y^{2}}",
        "confidence": "high",
        "uncertain": False,
        "notes": "",
    }


def test_detector_merges_fraction_across_zero_height_pdf_rule():
    payload = _payload(
        [_span("xy", "CMMI10", (205.0, 100.0, 221.0, 117.0))],
        [_span("uv", "CMMI10", (205.0, 123.0, 221.0, 140.0))],
    )
    regions = formula.detect_formula_regions_from_payload(
        payload,
        page_no=3,
        page_width=439.0,
        page_height=666.0,
        drawings=[{"rect": (202.0, 120.0, 224.0, 120.0)}],
    )
    assert len(regions) == 1
    assert regions[0].bbox_points == (202.0, 100.0, 224.0, 140.0)
    assert "nearby-horizontal-rule" in regions[0].evidence
    assert "merged-geometry" in regions[0].evidence


def test_detector_joins_long_display_but_rejects_inline_and_sparse_labels():
    long_display = _payload(
        [_span("a+b=c", "CMMI10", (100.0, 100.0, 180.0, 117.0))],
        [_span("d+e=f", "CMMI10", (195.0, 100.0, 255.0, 117.0))],
    )
    regions = formula.detect_formula_regions_from_payload(
        long_display,
        page_no=4,
        page_width=439.0,
        page_height=666.0,
    )
    assert len(regions) == 1
    assert regions[0].bbox_points == (100.0, 100.0, 255.0, 117.0)

    inline = _payload(
        [
            _span("For ", "CMR10", (40.0, 100.0, 70.0, 114.0)),
            _span("x", "CMMI10", (70.0, 100.0, 78.0, 114.0)),
            _span(" is a vertex.", "CMR10", (78.0, 100.0, 160.0, 114.0)),
        ]
    )
    assert formula.detect_formula_regions_from_payload(
        inline, page_no=4, page_width=439.0, page_height=666.0
    ) == []

    labels = _payload(
        [
            _span("G", "CMMI10", (100.0, 150.0, 108.0, 164.0)),
            _span("1", "CMR7", (108.0, 155.0, 113.0, 164.0), size=7.0),
            _span("G", "CMMI10", (220.0, 150.0, 228.0, 164.0)),
            _span("2", "CMR7", (228.0, 155.0, 233.0, 164.0), size=7.0),
        ]
    )
    assert formula.detect_formula_regions_from_payload(
        labels, page_no=4, page_width=439.0, page_height=666.0
    ) == []


def test_detector_fails_closed_without_math_font_evidence():
    ordinary = _payload(
        [_span("E(X) = 3/4", "Times-Roman", (100.0, 100.0, 180.0, 115.0))]
    )
    assert formula.detect_formula_regions_from_payload(
        ordinary, page_no=1, page_width=439.0, page_height=666.0
    ) == []
    assert formula.detect_formula_regions_from_payload(
        {"blocks": []}, page_no=1, page_width=439.0, page_height=666.0
    ) == []


def test_direct_pdf_crop_is_high_resolution_local_and_reusable(tmp_path):
    fitz = formula._load_fitz()
    source = tmp_path / "source.pdf"
    document = fitz.open()
    page = document.new_page(width=400, height=600)
    page.insert_text((100, 220), "E(X) <= n^2 / 2", fontsize=12)
    document.save(source)
    document.close()

    region = formula.FormulaRegion(
        region_id="p0001-f001",
        page=1,
        bbox_points=(90.0, 195.0, 220.0, 225.0),
        score=9.0,
        evidence=("display-geometry", "operator"),
    )
    source_hash = formula.sha256_file(source)
    first = formula.render_pdf_formula_evidence(
        source, source_hash, [region], tmp_path / "evidence", dpi=420
    )[0]
    assert first.crop_path.is_file()
    assert first.image_sha256 == formula.sha256_file(first.crop_path)
    assert first.dpi == 420
    assert first.image_size_pixels[0] > 700
    assert first.image_size_pixels[1] > 200
    assert first.image_size_pixels[0] < round(400 / 72 * 420 * 0.92)
    assert first.image_size_pixels[1] < round(600 / 72 * 420 * 0.92)
    assert 0 < first.crop_bbox_points[0] < first.crop_bbox_points[2] < 400

    second = formula.render_pdf_formula_evidence(
        source, source_hash, [region], tmp_path / "evidence", dpi=420
    )[0]
    assert second.crop_path == first.crop_path
    assert second.image_sha256 == first.image_sha256


def test_prepare_pdf_formula_evidence_detects_and_crops_real_pdf_font_geometry(tmp_path):
    fitz = formula._load_fitz()
    source = tmp_path / "symbol-formula.pdf"
    document = fitz.open()
    page = document.new_page(width=400, height=600)
    page.insert_text((120, 220), "A=B+C", fontname="symb", fontsize=16)
    document.save(source)
    document.close()

    prepared = formula.prepare_pdf_formula_evidence(
        source,
        [1],
        tmp_path / "prepared",
        dpi=360,
    )
    assert prepared.source_sha256 == formula.sha256_file(source)
    assert len(prepared.regions) == len(prepared.evidence) == 1
    assert prepared.regions[0].fonts == ("Symbol",)
    assert "operator" in prepared.regions[0].evidence
    assert prepared.evidence[0].crop_path.is_file()
    assert prepared.by_page() == {1: [prepared.evidence[0]]}


def test_render_refuses_whole_page_or_out_of_page_regions(tmp_path):
    fitz = formula._load_fitz()
    source = tmp_path / "source.pdf"
    document = fitz.open()
    document.new_page(width=400, height=600)
    document.save(source)
    document.close()
    source_hash = formula.sha256_file(source)
    whole = dataclasses.replace(
        _region(page=1),
        region_id="p0001-f001",
        bbox_points=(1.0, 1.0, 399.0, 599.0),
    )
    with pytest.raises(formula.FormulaEvidenceError, match="non-local"):
        formula.render_pdf_formula_evidence(
            source, source_hash, [whole], tmp_path / "evidence"
        )
    outside = dataclasses.replace(
        whole,
        bbox_points=(-1.0, 100.0, 200.0, 140.0),
    )
    with pytest.raises(formula.FormulaEvidenceError, match="leaves page"):
        formula.render_pdf_formula_evidence(
            source, source_hash, [outside], tmp_path / "evidence"
        )
    traversal = dataclasses.replace(
        _region(page=1),
        region_id="../outside",
    )
    with pytest.raises(formula.FormulaEvidenceError, match="region id"):
        formula.render_pdf_formula_evidence(
            source, source_hash, [traversal], tmp_path / "evidence"
        )
    assert not (tmp_path / "outside.png").exists()


def test_balanced_batches_records_and_strict_schema(tmp_path):
    for count in range(2, 25):
        batches = formula.balanced_formula_batches(list(range(count)), 4)
        assert [item for batch in batches for item in batch] == list(range(count))
        assert all(2 <= len(batch) <= 4 for batch in batches)
    assert [len(item) for item in formula.balanced_formula_batches(range(5))] == [3, 2]
    assert formula.balanced_formula_batches([1]) == [[1]]

    evidence = [_evidence(tmp_path, index=i, page=7) for i in range(1, 4)]
    records = formula.formula_batch_records(evidence)
    assert [item["image_index"] for item in records] == [1, 2, 3]
    assert [item["id"] for item in records] == [item.region.region_id for item in evidence]
    assert all(len(item["target_bbox_normalized"]) == 4 for item in records)
    schema = formula.formula_result_schema([item.region.region_id for item in evidence])
    assert schema["properties"]["results"]["minItems"] == 3
    assert schema["properties"]["results"]["maxItems"] == 3


def test_result_validator_rejects_duplicates_wrappers_and_unsafe_tex():
    ids = ["p0001-f001", "p0001-f002"]
    good = {"results": [_valid_result(item) for item in ids]}
    assert [item["id"] for item in formula.validate_formula_batch_result(good, ids)] == ids

    duplicate = {"results": [good["results"][0], good["results"][0]]}
    with pytest.raises(formula.FormulaEvidenceError, match="duplicate|missing"):
        formula.validate_formula_batch_result(duplicate, ids)
    for bad_tex in (
        r"\input{private}",
        r"\write18{command}",
        r"\[x+y\]",
        r"$x+y$",
        "x+y% hide the closing delimiter",
        r"\begin{document}x\end{document}",
        r"\begin{aligned}x+y",
        r"\frac{x}{y",
    ):
        bad = json.loads(json.dumps(good))
        bad["results"][0]["latex"] = bad_tex
        with pytest.raises(formula.FormulaEvidenceError, match="unsafe|wrapped|unbalanced"):
            formula.validate_formula_batch_result(bad, ids)
    inconsistent = json.loads(json.dumps(good))
    inconsistent["results"][0]["uncertain"] = True
    with pytest.raises(formula.FormulaEvidenceError, match="high-confidence"):
        formula.validate_formula_batch_result(inconsistent, ids)


def test_cache_key_covers_source_geometry_pixels_prompt_schema_model_and_effort(tmp_path):
    evidence = _evidence(tmp_path)

    def key(item=evidence, source="a" * 64, identity=None):
        return formula.formula_cache_key(source, item, identity or _identity())

    baseline = key()
    inputs = formula.formula_cache_inputs("a" * 64, evidence, _identity())
    assert {
        "source_sha256",
        "physical_page",
        "formula_bbox_points",
        "crop_bbox_points",
        "image_sha256",
        "prompt_version",
        "prompt_sha256",
        "schema_version",
        "schema_sha256",
        "backend",
        "model",
        "reasoning_effort",
    } <= inputs.keys()
    variants = [
        key(source="b" * 64),
        key(dataclasses.replace(evidence, region=dataclasses.replace(evidence.region, page=8))),
        key(
            dataclasses.replace(
                evidence,
                region=dataclasses.replace(
                    evidence.region, bbox_points=(101.0, 120.0, 180.0, 145.0)
                ),
            )
        ),
        key(dataclasses.replace(evidence, crop_bbox_points=(87.0, 110.0, 192.0, 155.0))),
        key(dataclasses.replace(evidence, image_sha256="c" * 64)),
        key(identity=_identity(prompt_sha256="3" * 64)),
        key(identity=_identity(schema_sha256="4" * 64)),
        key(identity=_identity(model="another-model")),
        key(identity=_identity(reasoning_effort="low")),
        key(identity=_identity(backend="api")),
    ]
    assert all(item != baseline for item in variants)


def test_metadata_cache_round_trip_omits_crop_path_and_fails_closed_on_damage(tmp_path):
    evidence = _evidence(tmp_path)
    source_hash = "a" * 64
    identity = _identity()
    cache = formula.FormulaResultCache(tmp_path / "cache")
    result = _valid_result(evidence.region.region_id)
    path = cache.store_for(source_hash, evidence, identity, result)
    assert path.is_file()
    raw = path.read_text(encoding="utf-8")
    assert str(evidence.crop_path) not in raw
    assert "crop_path" not in raw
    assert cache.lookup(source_hash, evidence, identity)["result"] == result
    assert not list((tmp_path / "cache").rglob("*.tmp"))

    damaged = json.loads(raw)
    damaged["result"]["latex"] = r"\input{bad}"
    path.write_text(json.dumps(damaged), encoding="utf-8")
    assert cache.lookup(source_hash, evidence, identity) is None


def test_cache_rejects_mismatched_inputs_and_invalid_identity(tmp_path):
    evidence = _evidence(tmp_path)
    identity = _identity()
    inputs = formula.formula_cache_inputs("a" * 64, evidence, identity)
    key = formula.sha256_bytes(formula.canonical_json_bytes(inputs))
    cache = formula.FormulaResultCache(tmp_path / "cache")
    wrong = dict(inputs)
    wrong["model"] = "other"
    with pytest.raises(formula.FormulaEvidenceError, match="do not match"):
        cache.store(key, wrong, evidence, _valid_result(evidence.region.region_id))
    with pytest.raises(formula.FormulaEvidenceError, match="prompt_sha256"):
        formula.formula_cache_inputs(
            "a" * 64,
            evidence,
            dataclasses.replace(identity, prompt_sha256="not-a-hash"),
        )
