"""Host-owned schemas for deterministic OCR page classification.

This module contains no model output and grants no semantic authority.  In
particular, :class:`PageBlock` records visible PDF objects; it does not infer
document sections or theorem-like LaTeX environments from their wording.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
StyleValue = str | int | float | bool


class PageStrategy(str, Enum):
    BORN_DIGITAL_CLEAN = "BORN_DIGITAL_CLEAN"
    BORN_DIGITAL_RISKY = "BORN_DIGITAL_RISKY"
    HYBRID = "HYBRID"
    SCANNED = "SCANNED"
    IMAGE_ONLY = "IMAGE_ONLY"
    UNKNOWN = "UNKNOWN"


class DocumentStrategy(str, Enum):
    BORN_DIGITAL_FAST = "BORN_DIGITAL_FAST"
    HYBRID_MIXED = "HYBRID_MIXED"
    VISUAL_STRICT = "VISUAL_STRICT"


class PageBlockType(str, Enum):
    TEXT = "TEXT"
    MIXED_TEXT_MATH = "MIXED_TEXT_MATH"
    INLINE_MATH = "INLINE_MATH"
    DISPLAY_MATH = "DISPLAY_MATH"
    HEADING_TEXT = "HEADING_TEXT"
    LIST_ITEM = "LIST_ITEM"
    PRINTED_PAGE_NUMBER = "PRINTED_PAGE_NUMBER"
    FOOTNOTE = "FOOTNOTE"
    CAPTION = "CAPTION"
    BIBLIOGRAPHY_ITEM = "BIBLIOGRAPHY_ITEM"
    FIGURE = "FIGURE"
    TABLE = "TABLE"
    UNKNOWN = "UNKNOWN"


def _ratio(value: float, name: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return number


def _digest(value: str, name: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _bbox(value: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
    if len(value) != 4:
        raise ValueError("bbox must contain four coordinates")
    result = tuple(float(item) for item in value)
    if not all(math.isfinite(item) for item in result):
        raise ValueError("bbox coordinates must be finite")
    if result[2] < result[0] or result[3] < result[1]:
        raise ValueError("bbox coordinates are reversed")
    return result


def _style_features(
    value: Mapping[str, StyleValue] | tuple[tuple[str, StyleValue], ...],
) -> tuple[tuple[str, StyleValue], ...]:
    items = value.items() if isinstance(value, Mapping) else value
    normalized: list[tuple[str, StyleValue]] = []
    for raw_key, raw_value in items:
        key = str(raw_key).strip()
        if not key:
            raise ValueError("style feature names cannot be empty")
        if not isinstance(raw_value, (str, int, float, bool)):
            raise ValueError("style feature values must be scalar")
        if isinstance(raw_value, float) and not math.isfinite(raw_value):
            raise ValueError("style feature values must be finite")
        normalized.append((key, raw_value))
    keys = [key for key, _value in normalized]
    if len(keys) != len(set(keys)):
        raise ValueError("style feature names must be unique")
    return tuple(sorted(normalized))


@dataclass(frozen=True, slots=True)
class PageBlock:
    block_id: str
    block_type: PageBlockType
    bbox: tuple[float, float, float, float]
    reading_order: int
    plain_text: str
    style_features: tuple[tuple[str, StyleValue], ...]
    math_likelihood: float
    source_object_hash: str
    candidate_latex: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"ocr-page-\d{6}-block-\d{4}-[0-9a-f]{12}", self.block_id):
            raise ValueError("block_id is not a stable OCR block id")
        object.__setattr__(self, "block_type", PageBlockType(self.block_type))
        object.__setattr__(self, "bbox", _bbox(self.bbox))
        if self.reading_order < 1:
            raise ValueError("reading_order must be positive")
        object.__setattr__(self, "style_features", _style_features(self.style_features))
        object.__setattr__(
            self,
            "math_likelihood",
            _ratio(self.math_likelihood, "math_likelihood"),
        )
        object.__setattr__(
            self,
            "source_object_hash",
            _digest(self.source_object_hash, "source_object_hash"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "block_type": self.block_type.value,
            "bbox": list(self.bbox),
            "reading_order": self.reading_order,
            "plain_text": self.plain_text,
            "style_features": dict(self.style_features),
            "math_likelihood": self.math_likelihood,
            "source_object_hash": self.source_object_hash,
            "candidate_latex": self.candidate_latex,
        }


@dataclass(frozen=True, slots=True)
class PageFeatures:
    page_width: float
    page_height: float
    rotation: int
    has_text_objects: bool
    text_character_count: int
    printable_character_ratio: float
    unicode_replacement_ratio: float
    garbled_character_ratio: float
    font_mapping_health: float
    text_block_count: int
    image_count: int
    image_coverage_ratio: float
    single_full_page_image: bool
    math_symbol_density: float
    formula_region_count: int
    double_column_likelihood: float
    text_pixel_alignment_confidence: float
    reading_order_confidence: float

    def __post_init__(self) -> None:
        if (
            not math.isfinite(float(self.page_width))
            or not math.isfinite(float(self.page_height))
            or self.page_width <= 0
            or self.page_height <= 0
        ):
            raise ValueError("page dimensions must be positive and finite")
        if int(self.rotation) % 90:
            raise ValueError("rotation must be a multiple of 90 degrees")
        object.__setattr__(self, "rotation", int(self.rotation) % 360)
        for name in (
            "text_character_count",
            "text_block_count",
            "image_count",
            "formula_region_count",
        ):
            value = int(getattr(self, name))
            if value < 0:
                raise ValueError(f"{name} cannot be negative")
            object.__setattr__(self, name, value)
        for name in (
            "printable_character_ratio",
            "unicode_replacement_ratio",
            "garbled_character_ratio",
            "font_mapping_health",
            "image_coverage_ratio",
            "math_symbol_density",
            "double_column_likelihood",
            "text_pixel_alignment_confidence",
            "reading_order_confidence",
        ):
            object.__setattr__(self, name, _ratio(getattr(self, name), name))
        if bool(self.has_text_objects) != bool(self.text_block_count):
            raise ValueError("has_text_objects must agree with text_block_count")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PageCandidate:
    page_id: str
    source_page_number: int
    selected_index: int
    features: PageFeatures
    blocks: tuple[PageBlock, ...]
    source_page_object_hash: str
    source_text_layer_sha256: str
    candidate_tex: str

    def __post_init__(self) -> None:
        if self.page_id != f"ocr-page-{self.selected_index:06d}":
            raise ValueError("page_id must be derived from selected_index")
        if self.source_page_number < 1 or self.selected_index < 1:
            raise ValueError("page numbers and selected indexes must be positive")
        blocks = tuple(self.blocks)
        if [block.reading_order for block in blocks] != list(range(1, len(blocks) + 1)):
            raise ValueError("blocks must be stored in contiguous reading order")
        if len({block.block_id for block in blocks}) != len(blocks):
            raise ValueError("block ids must be unique within a page")
        prefix = f"{self.page_id}-block-"
        if any(not block.block_id.startswith(prefix) for block in blocks):
            raise ValueError("block ids must be bound to page_id")
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(
            self,
            "source_page_object_hash",
            _digest(self.source_page_object_hash, "source_page_object_hash"),
        )
        object.__setattr__(
            self,
            "source_text_layer_sha256",
            _digest(self.source_text_layer_sha256, "source_text_layer_sha256"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "page_id": self.page_id,
            "source_page_number": self.source_page_number,
            "selected_index": self.selected_index,
            "features": self.features.to_dict(),
            "blocks": [block.to_dict() for block in self.blocks],
            "source_page_object_hash": self.source_page_object_hash,
            "source_text_layer_sha256": self.source_text_layer_sha256,
            "candidate_tex": self.candidate_tex,
        }


@dataclass(frozen=True, slots=True)
class PageClassification:
    page_id: str
    source_page_number: int
    selected_index: int
    strategy: PageStrategy
    features: PageFeatures
    blocks: tuple[PageBlock, ...]
    source_page_object_hash: str
    source_text_layer_sha256: str
    candidate_tex: str

    def __post_init__(self) -> None:
        # Use one validator for both the extraction candidate and its strategy
        # decision so the two public representations cannot drift.
        candidate = PageCandidate(
            page_id=self.page_id,
            source_page_number=self.source_page_number,
            selected_index=self.selected_index,
            features=self.features,
            blocks=self.blocks,
            source_page_object_hash=self.source_page_object_hash,
            source_text_layer_sha256=self.source_text_layer_sha256,
            candidate_tex=self.candidate_tex,
        )
        object.__setattr__(self, "strategy", PageStrategy(self.strategy))
        object.__setattr__(self, "blocks", candidate.blocks)
        object.__setattr__(
            self,
            "source_page_object_hash",
            candidate.source_page_object_hash,
        )
        object.__setattr__(
            self,
            "source_text_layer_sha256",
            candidate.source_text_layer_sha256,
        )

    @property
    def candidate(self) -> PageCandidate:
        return PageCandidate(
            page_id=self.page_id,
            source_page_number=self.source_page_number,
            selected_index=self.selected_index,
            features=self.features,
            blocks=self.blocks,
            source_page_object_hash=self.source_page_object_hash,
            source_text_layer_sha256=self.source_text_layer_sha256,
            candidate_tex=self.candidate_tex,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = self.candidate.to_dict()
        payload["strategy"] = self.strategy.value
        return payload


__all__ = [
    "DocumentStrategy",
    "PageBlock",
    "PageBlockType",
    "PageCandidate",
    "PageClassification",
    "PageFeatures",
    "PageStrategy",
]
