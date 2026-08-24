"""Host orchestration helpers for OCR-only source classification.

These helpers perform local deterministic work only.  They never call a model,
compile TeX, infer document structure, or mutate project state.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Sequence

from .ocr_classifier import classify_document, classify_page
from .ocr_extraction import (
    DEFAULT_EXTRACTION_WORKERS,
    extract_image_page,
    extract_pdf_pages,
)
from .ocr_schema import DocumentStrategy, PageClassification, PageStrategy
from .ocr_schema import PageFeatures


@dataclass(frozen=True, slots=True)
class SourceClassification:
    source_sha256: str
    source_type: str
    document_strategy: DocumentStrategy
    pages: tuple[PageClassification, ...]

    @property
    def strategy_counts(self) -> dict[str, int]:
        return {
            strategy.value: sum(page.strategy is strategy for page in self.pages)
            for strategy in PageStrategy
        }

    @property
    def text_layer_status(self) -> str:
        with_text = sum(page.features.has_text_objects for page in self.pages)
        if with_text == len(self.pages):
            return "PRESENT"
        if with_text:
            return "PARTIAL"
        return "ABSENT"

    def snapshot_page_sizes(self) -> tuple[dict[str, object], ...]:
        return tuple({
            "page_id": page.page_id,
            "source_page": page.source_page_number,
            "width_points": page.features.page_width,
            "height_points": page.features.page_height,
            "rotation": page.features.rotation,
        } for page in self.pages)

    def snapshot_contract_pages(self) -> list[dict[str, object]]:
        return [{
            "page_id": page.page_id,
            "source_page": page.source_page_number,
            "strategy": page.strategy.value,
            "source_page_object_hash": page.source_page_object_hash,
            "source_text_layer_sha256": page.source_text_layer_sha256,
            "candidate_tex_sha256": hashlib.sha256(
                page.candidate_tex.encode("utf-8")
            ).hexdigest(),
            "block_count": len(page.blocks),
            "features": page.features.to_dict(),
        } for page in self.pages]


def classify_source_pages(
    *,
    source_type: str,
    source_bytes: bytes,
    selected_pages: Sequence[int],
    visual_source_bytes: bytes = b"",
    extraction_workers: int = DEFAULT_EXTRACTION_WORKERS,
) -> SourceClassification:
    """Create frozen selected-page classifications before any paid request."""
    normalized = str(source_type or "").strip().casefold()
    payload = bytes(source_bytes)
    pages = tuple(selected_pages)
    if not payload:
        raise ValueError("OCR source bytes cannot be empty")
    if not pages:
        raise ValueError("OCR selected_pages cannot be empty")
    if normalized == "pdf":
        classifications = extract_pdf_pages(
            payload,
            pages,
            extraction_workers=extraction_workers,
        )
    elif normalized == "image":
        if pages != (1,):
            raise ValueError("single-image OCR must select exactly page 1")
        classifications = (extract_image_page(payload),)
    elif normalized == "images":
        visual = bytes(visual_source_bytes)
        if not visual.startswith(b"%PDF-"):
            raise ValueError("multi-image OCR requires its frozen visual PDF")
        extracted = extract_pdf_pages(
            visual,
            pages,
            extraction_workers=extraction_workers,
        )
        classifications = tuple(
            classify_page(page.candidate, source_type="images") for page in extracted
        )
    else:
        raise ValueError("unsupported OCR source type")
    expected_ids = [f"ocr-page-{index:06d}" for index in range(1, len(pages) + 1)]
    if [page.page_id for page in classifications] != expected_ids:
        raise ValueError("source classifications are not in stable page_id order")
    if [page.source_page_number for page in classifications] != list(pages):
        raise ValueError("source classifications do not match selected source pages")
    return SourceClassification(
        source_sha256=hashlib.sha256(payload).hexdigest(),
        source_type=normalized,
        document_strategy=classify_document(classifications),
        pages=classifications,
    )


def visual_strict_fallback_classification(
    *,
    source_type: str,
    source_bytes: bytes,
    selected_pages: Sequence[int],
) -> SourceClassification:
    """Create an explicit UNKNOWN/IMAGE_ONLY full-OCR fallback.

    This is used only when deterministic object extraction is unavailable.  It
    carries no candidate text and therefore can never enter the verifier PASS
    path or be mistaken for successful text-layer coverage.
    """
    normalized = str(source_type or "").strip().casefold()
    payload = bytes(source_bytes)
    pages = tuple(selected_pages)
    if normalized not in {"pdf", "image", "images"} or not payload or not pages:
        raise ValueError("visual fallback requires a supported non-empty source")
    source_sha = hashlib.sha256(payload).hexdigest()
    strategy = (
        PageStrategy.IMAGE_ONLY
        if normalized in {"image", "images"}
        else PageStrategy.UNKNOWN
    )
    features = PageFeatures(
        page_width=1.0,
        page_height=1.0,
        rotation=0,
        has_text_objects=False,
        text_character_count=0,
        printable_character_ratio=0.0,
        unicode_replacement_ratio=0.0,
        garbled_character_ratio=0.0,
        font_mapping_health=0.0,
        text_block_count=0,
        image_count=1 if strategy is PageStrategy.IMAGE_ONLY else 0,
        image_coverage_ratio=1.0 if strategy is PageStrategy.IMAGE_ONLY else 0.0,
        single_full_page_image=strategy is PageStrategy.IMAGE_ONLY,
        math_symbol_density=0.0,
        formula_region_count=0,
        double_column_likelihood=0.0,
        text_pixel_alignment_confidence=0.0,
        reading_order_confidence=0.0,
    )
    classifications = tuple(
        PageClassification(
            page_id=f"ocr-page-{selected_index:06d}",
            source_page_number=source_page,
            selected_index=selected_index,
            strategy=strategy,
            features=features,
            blocks=(),
            source_page_object_hash=hashlib.sha256(
                f"{source_sha}:{source_page}:visual-fallback".encode("utf-8")
            ).hexdigest(),
            source_text_layer_sha256=hashlib.sha256(b"").hexdigest(),
            candidate_tex="",
        )
        for selected_index, source_page in enumerate(pages, 1)
    )
    return SourceClassification(
        source_sha256=source_sha,
        source_type=normalized,
        document_strategy=DocumentStrategy.VISUAL_STRICT,
        pages=classifications,
    )


def estimate_ocr_requests(
    classification: SourceClassification,
    *,
    verifier_batch_size: int = 4,
    full_ocr_batch_size: int = 3,
) -> dict[str, object]:
    """Return call-count bounds only; unavailable time/token/cost stay null."""
    verifier_batch_size = max(1, min(8, int(verifier_batch_size)))
    full_ocr_batch_size = max(1, min(3, int(full_ocr_batch_size)))
    verifier_pages = sum(page.strategy in {
        PageStrategy.BORN_DIGITAL_CLEAN,
        PageStrategy.BORN_DIGITAL_RISKY,
        PageStrategy.HYBRID,
    } for page in classification.pages)
    mandatory_full_pages = sum(page.strategy in {
        PageStrategy.SCANNED,
        PageStrategy.IMAGE_ONLY,
        PageStrategy.UNKNOWN,
    } for page in classification.pages)
    possible_full_pages = mandatory_full_pages + sum(page.strategy in {
        PageStrategy.BORN_DIGITAL_RISKY,
        PageStrategy.HYBRID,
    } for page in classification.pages)
    verifier_requests_min = math.ceil(verifier_pages / verifier_batch_size)
    verifier_requests_max = verifier_pages
    full_requests_min = math.ceil(mandatory_full_pages / full_ocr_batch_size)
    full_requests_max = possible_full_pages
    return {
        "selected_pages": len(classification.pages),
        "document_strategy": classification.document_strategy.value,
        "page_strategy_counts": classification.strategy_counts,
        "visual_verification_requests": {
            "min": verifier_requests_min,
            "max": verifier_requests_max,
        },
        "full_ocr_requests": {"min": full_requests_min, "max": full_requests_max},
        "high_resolution_retry_requests": {"min": 0, "max": len(classification.pages)},
        "estimated_time_seconds": None,
        "estimated_input_tokens": None,
        "estimated_output_tokens": None,
        "estimated_cost": None,
        "estimate_basis": "request topology only; no verified local history",
    }


__all__ = [
    "SourceClassification",
    "classify_source_pages",
    "estimate_ocr_requests",
    "visual_strict_fallback_classification",
]
