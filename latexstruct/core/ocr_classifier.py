"""Deterministic page and document strategy selection.

The thresholds are deliberately conservative: damaged text layers and pages
with material image coverage are escalated, never silently accepted as a
clean object-layer page.  A later visual verifier remains mandatory even for
``BORN_DIGITAL_CLEAN`` pages.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .ocr_schema import (
    DocumentStrategy,
    PageCandidate,
    PageClassification,
    PageFeatures,
    PageStrategy,
)


def classify_page_features(
    features: PageFeatures,
    *,
    source_type: str = "pdf",
) -> PageStrategy:
    """Choose a fail-safe page path from host-extracted evidence."""
    normalized_source = str(source_type or "pdf").strip().casefold()
    if normalized_source in {"image", "images", "image_only"}:
        return PageStrategy.IMAGE_ONLY
    if normalized_source != "pdf":
        return PageStrategy.UNKNOWN

    has_usable_text = features.has_text_objects and features.text_character_count >= 4
    corrupt_text = (
        features.unicode_replacement_ratio > 0.01
        or features.garbled_character_ratio > 0.08
        or features.printable_character_ratio < 0.88
        or features.font_mapping_health < 0.72
    )
    risky_layout = (
        features.reading_order_confidence < 0.58
        or features.text_pixel_alignment_confidence < 0.70
    )

    if not has_usable_text:
        if features.single_full_page_image or features.image_coverage_ratio >= 0.55:
            return PageStrategy.SCANNED
        return PageStrategy.UNKNOWN

    # Substantial raster content coexisting with usable text is hybrid even
    # when the text layer itself looks healthy.  It requires regional visual
    # coverage instead of trusting the object layer alone.
    if features.image_coverage_ratio >= 0.18:
        return PageStrategy.HYBRID
    if corrupt_text:
        if features.image_count or features.image_coverage_ratio >= 0.05:
            return PageStrategy.HYBRID
        return PageStrategy.BORN_DIGITAL_RISKY
    if risky_layout or features.double_column_likelihood >= 0.55:
        return PageStrategy.BORN_DIGITAL_RISKY
    if (
        features.printable_character_ratio >= 0.96
        and features.font_mapping_health >= 0.90
        and features.garbled_character_ratio <= 0.02
        and features.unicode_replacement_ratio <= 0.002
    ):
        return PageStrategy.BORN_DIGITAL_CLEAN
    return PageStrategy.BORN_DIGITAL_RISKY


def classify_page(
    candidate: PageCandidate,
    *,
    source_type: str = "pdf",
) -> PageClassification:
    """Bind a host-created candidate to its deterministic page strategy."""
    return PageClassification(
        page_id=candidate.page_id,
        source_page_number=candidate.source_page_number,
        selected_index=candidate.selected_index,
        strategy=classify_page_features(candidate.features, source_type=source_type),
        features=candidate.features,
        blocks=candidate.blocks,
        source_page_object_hash=candidate.source_page_object_hash,
        source_text_layer_sha256=candidate.source_text_layer_sha256,
        candidate_tex=candidate.candidate_tex,
    )


def classify_document(
    pages: Iterable[PageClassification | PageStrategy],
) -> DocumentStrategy:
    """Aggregate frozen page decisions without averaging away risky pages."""
    strategies = tuple(
        page.strategy if isinstance(page, PageClassification) else PageStrategy(page)
        for page in pages
    )
    if not strategies:
        raise ValueError("document classification requires at least one page")
    counts = Counter(strategies)
    total = len(strategies)
    visual_count = sum(
        counts[item]
        for item in (PageStrategy.SCANNED, PageStrategy.IMAGE_ONLY, PageStrategy.UNKNOWN)
    )
    if visual_count * 2 >= total:
        return DocumentStrategy.VISUAL_STRICT

    digital_count = counts[PageStrategy.BORN_DIGITAL_CLEAN] + counts[
        PageStrategy.BORN_DIGITAL_RISKY
    ]
    if (
        digital_count == total
        and counts[PageStrategy.BORN_DIGITAL_CLEAN] * 2 >= total
    ):
        return DocumentStrategy.BORN_DIGITAL_FAST
    return DocumentStrategy.HYBRID_MIXED


__all__ = ["classify_document", "classify_page", "classify_page_features"]
