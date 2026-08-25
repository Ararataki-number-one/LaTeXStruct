"""Host-owned OCR block inventory contracts."""

from __future__ import annotations

import hashlib
import json

import pytest

from latexstruct.core.ocr_block_inventory import (
    OCR_BLOCK_INVENTORY_SCHEMA,
    OcrBlockInventoryError,
    build_ocr_block_inventory,
    parse_ocr_block_inventory,
)
from latexstruct.core.ocr_pipeline import SourceClassification
from latexstruct.core.ocr_schema import (
    DocumentStrategy,
    PageBlock,
    PageBlockType,
    PageClassification,
    PageFeatures,
    PageStrategy,
)


RUN_ID = "b" * 32
SOURCE_SHA = hashlib.sha256(b"immutable source").hexdigest()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _features(block_count: int) -> PageFeatures:
    return PageFeatures(
        page_width=612.0,
        page_height=792.0,
        rotation=0,
        has_text_objects=bool(block_count),
        text_character_count=40 * block_count,
        printable_character_ratio=1.0,
        unicode_replacement_ratio=0.0,
        garbled_character_ratio=0.0,
        font_mapping_health=1.0,
        text_block_count=block_count,
        image_count=0,
        image_coverage_ratio=0.0,
        single_full_page_image=False,
        math_symbol_density=0.0,
        formula_region_count=0,
        double_column_likelihood=0.0,
        text_pixel_alignment_confidence=1.0,
        reading_order_confidence=1.0,
    )


def _block(
    page_index: int,
    reading_order: int,
    text: str,
    block_type: PageBlockType,
) -> PageBlock:
    source_hash = _sha(f"page={page_index};order={reading_order};text={text}")
    return PageBlock(
        block_id=(
            f"ocr-page-{page_index:06d}-block-{reading_order:04d}-"
            f"{source_hash[:12]}"
        ),
        block_type=block_type,
        bbox=(72.0, 80.0 + 20 * reading_order, 500.0, 96.0 + 20 * reading_order),
        reading_order=reading_order,
        plain_text=text,
        style_features={
            "font_names": "CMR10",
            "font_size": 10.0,
            "bold": False,
            "italic": False,
            "line_count": 1,
        },
        math_likelihood=0.0,
        source_object_hash=source_hash,
        candidate_latex=text,
    )


def source_classification(
    *,
    source_sha256: str = SOURCE_SHA,
    selected_pages: tuple[int, int] = (3, 7),
) -> SourceClassification:
    page_blocks = (
        (
            _block(1, 1, "1. ordinary numbered list item", PageBlockType.LIST_ITEM),
            _block(1, 2, "1. Introduction", PageBlockType.HEADING_TEXT),
        ),
        (_block(2, 1, "Body text", PageBlockType.TEXT),),
    )
    pages = tuple(
        PageClassification(
            page_id=f"ocr-page-{index:06d}",
            source_page_number=source_page,
            selected_index=index,
            strategy=PageStrategy.BORN_DIGITAL_CLEAN,
            features=_features(len(blocks)),
            blocks=blocks,
            source_page_object_hash=_sha(f"page object {source_page}"),
            source_text_layer_sha256=_sha(f"text layer {source_page}"),
            candidate_tex="\n\n".join(block.candidate_latex for block in blocks),
        )
        for index, (source_page, blocks) in enumerate(
            zip(selected_pages, page_blocks, strict=True), start=1
        )
    )
    return SourceClassification(
        source_sha256=source_sha256,
        source_type="pdf",
        document_strategy=DocumentStrategy.BORN_DIGITAL_FAST,
        pages=pages,
    )


def _artifact() -> bytes:
    return build_ocr_block_inventory(
        run_id=RUN_ID,
        source_classification=source_classification(),
        selected_pages=(3, 7),
    )


def _parse(data: bytes, **overrides):
    values = {
        "expected_run_id": RUN_ID,
        "expected_source_sha256": SOURCE_SHA,
        "expected_selected_pages": (3, 7),
        "expected_snapshot_pages": source_classification().snapshot_contract_pages(),
    }
    values.update(overrides)
    return parse_ocr_block_inventory(data, **values)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def test_inventory_is_canonical_deterministic_and_preserves_host_block_types():
    first = _artifact()
    second = _artifact()
    inventory = _parse(first)

    assert first == second == inventory.to_json_bytes()
    assert json.loads(first)["schema_version"] == OCR_BLOCK_INVENTORY_SCHEMA
    assert inventory.selected_pages == (3, 7)
    assert tuple(inventory.pages_by_id) == (
        "ocr-page-000001", "ocr-page-000002"
    )
    assert inventory.pages[0].blocks[0].block_type is PageBlockType.LIST_ITEM
    projection = inventory.native_source_block_projection()
    assert [item["plain_text"] for item in projection] == [
        "1. ordinary numbered list item", "1. Introduction", "Body text"
    ]
    assert projection[0]["block_type"] == "LIST_ITEM"
    assert projection[0]["source_sha256"] == (
        inventory.pages[0].blocks[0].source_object_hash
    )
    with pytest.raises(TypeError):
        projection[0]["block_type"] = "HEADING_TEXT"


@pytest.mark.parametrize(
    "mutation",
    ["missing-page", "extra-page", "page-order", "block-order", "cross-page"],
)
def test_inventory_rejects_missing_extra_unordered_and_cross_page_blocks(mutation):
    value = json.loads(_artifact())
    if mutation == "missing-page":
        value["pages"].pop()
    elif mutation == "extra-page":
        value["pages"].append(dict(value["pages"][-1]))
    elif mutation == "page-order":
        value["pages"].reverse()
    elif mutation == "block-order":
        value["pages"][0]["blocks"].reverse()
    else:
        value["pages"][0]["blocks"][0]["block_id"] = (
            "ocr-page-000002-block-0001-0123456789ab"
        )

    with pytest.raises(OcrBlockInventoryError):
        _parse(_canonical(value))


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("expected_run_id", "c" * 32),
        ("expected_source_sha256", "d" * 64),
        ("expected_selected_pages", (3,)),
    ],
)
def test_inventory_rejects_independent_identity_and_hash_mismatch(
    override, value,
):
    with pytest.raises(OcrBlockInventoryError):
        _parse(_artifact(), **{override: value})


def test_inventory_rejects_noncanonical_and_snapshot_hash_tamper():
    artifact = _artifact()
    noncanonical = json.dumps(json.loads(artifact), indent=2).encode("utf-8")
    with pytest.raises(OcrBlockInventoryError, match="canonical"):
        _parse(noncanonical)

    snapshot_pages = source_classification().snapshot_contract_pages()
    snapshot_pages[0]["source_page_object_hash"] = "f" * 64
    with pytest.raises(OcrBlockInventoryError, match="source_page_object_hash"):
        _parse(artifact, expected_snapshot_pages=snapshot_pages)


def test_inventory_rejects_duplicate_json_keys_and_invalid_scalar_values():
    artifact = _artifact()
    duplicate = artifact.replace(
        b'"run_id":"' + RUN_ID.encode("ascii") + b'"',
        b'"run_id":"' + RUN_ID.encode("ascii") + b'","run_id":"'
        + RUN_ID.encode("ascii") + b'"',
        1,
    )
    with pytest.raises(OcrBlockInventoryError, match="duplicate JSON key"):
        _parse(duplicate)

    value = json.loads(artifact)
    value["pages"][0]["blocks"][0]["bbox"][0] = -1
    with pytest.raises(OcrBlockInventoryError, match="bbox"):
        _parse(_canonical(value))
