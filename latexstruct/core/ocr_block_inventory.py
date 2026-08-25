"""Canonical host-owned OCR source-block inventory.

The inventory freezes deterministic object-layer evidence before analysis.  It
contains no model output and never interprets visible text as instructions or
as document structure.  In particular, a numbered text line keeps the
``PageBlockType`` assigned by the host extractor; this module does not promote
it to a heading by matching its wording.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from .ocr_pipeline import SourceClassification
from .ocr_schema import PageBlockType, StyleValue


OCR_BLOCK_INVENTORY_SCHEMA = "latexstruct-ocr-block-inventory-v1"
_RUN_ID_RE = re.compile(r"^[0-9a-f]{16,64}$")
_PAGE_ID_RE = re.compile(r"^ocr-page-(?P<index>[0-9]{6})$")
_BLOCK_ID_RE = re.compile(
    r"^ocr-page-(?P<page_index>[0-9]{6})-block-(?P<order>[0-9]{4})-[0-9a-f]{12}$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
_MAX_TEXT_BYTES = 8 * 1024 * 1024


class OcrBlockInventoryError(ValueError):
    """The native block inventory is malformed, stale, or non-canonical."""


def _fail(message: str) -> None:
    raise OcrBlockInventoryError(message)


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key in OCR block inventory: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise OcrBlockInventoryError(
            "OCR block inventory contains a non-JSON value"
        ) from exc
    return (body + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def _digest(value: object, label: str) -> str:
    digest = str(value or "").strip().lower()
    if _SHA256_RE.fullmatch(digest) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _bbox(value: object) -> tuple[float, float, float, float]:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        _fail("OCR block bbox must contain four coordinates")
    result: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            _fail("OCR block bbox coordinates must be numbers")
        number = float(item)
        if not math.isfinite(number) or number < 0:
            _fail("OCR block bbox coordinates must be finite and nonnegative")
        result.append(number)
    if result[2] < result[0] or result[3] < result[1]:
        _fail("OCR block bbox coordinates are reversed")
    return tuple(result)  # type: ignore[return-value]


def _style(value: object) -> Mapping[str, StyleValue]:
    if not isinstance(value, Mapping):
        _fail("OCR block style_features must be an object")
    normalized: dict[str, StyleValue] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if not key or key.strip() != key or key in normalized:
            _fail("OCR block style feature names must be non-empty and unique")
        if not isinstance(raw_value, (str, int, float, bool)):
            _fail("OCR block style feature values must be scalar")
        if isinstance(raw_value, float) and not math.isfinite(raw_value):
            _fail("OCR block style feature values must be finite")
        normalized[key] = raw_value
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True, slots=True)
class OcrBlockInventoryBlock:
    block_id: str
    block_type: PageBlockType
    reading_order: int
    plain_text: str
    style_features: Mapping[str, StyleValue]
    bbox: tuple[float, float, float, float]
    source_object_hash: str

    def __post_init__(self) -> None:
        match = _BLOCK_ID_RE.fullmatch(str(self.block_id or ""))
        if match is None:
            _fail("OCR block inventory block_id is invalid")
        order = _positive_int(self.reading_order, "OCR block reading_order")
        if int(match.group("order")) != order:
            _fail("OCR block_id order differs from reading_order")
        try:
            block_type = PageBlockType(self.block_type)
        except ValueError as exc:
            raise OcrBlockInventoryError(
                "OCR block inventory block_type is unsupported"
            ) from exc
        text = str(self.plain_text)
        if len(text.encode("utf-8")) > _MAX_TEXT_BYTES:
            _fail("OCR block plain_text exceeds its size bound")
        object.__setattr__(self, "block_type", block_type)
        object.__setattr__(self, "reading_order", order)
        object.__setattr__(self, "plain_text", text)
        object.__setattr__(self, "style_features", _style(self.style_features))
        object.__setattr__(self, "bbox", _bbox(self.bbox))
        object.__setattr__(
            self,
            "source_object_hash",
            _digest(self.source_object_hash, "OCR block source_object_hash"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "block_id": self.block_id,
            "block_type": self.block_type.value,
            "reading_order": self.reading_order,
            "plain_text": self.plain_text,
            "style_features": dict(self.style_features),
            "bbox": list(self.bbox),
            "source_object_hash": self.source_object_hash,
        }


@dataclass(frozen=True, slots=True)
class OcrBlockInventoryPage:
    page_id: str
    source_page: int
    selected_index: int
    source_page_object_hash: str
    source_text_layer_sha256: str
    blocks: tuple[OcrBlockInventoryBlock, ...]

    def __post_init__(self) -> None:
        match = _PAGE_ID_RE.fullmatch(str(self.page_id or ""))
        if match is None:
            _fail("OCR block inventory page_id is invalid")
        selected_index = _positive_int(
            self.selected_index, "OCR block inventory selected_index"
        )
        source_page = _positive_int(self.source_page, "OCR block source_page")
        if int(match.group("index")) != selected_index:
            _fail("OCR block inventory page_id differs from selected_index")
        blocks = tuple(self.blocks)
        expected_orders = tuple(range(1, len(blocks) + 1))
        if tuple(block.reading_order for block in blocks) != expected_orders:
            _fail("OCR blocks are not in contiguous reading order")
        if any(
            int(_BLOCK_ID_RE.fullmatch(block.block_id).group("page_index"))
            != selected_index
            for block in blocks
        ):
            _fail("OCR block belongs to a different page")
        identities = tuple(block.block_id for block in blocks)
        if len(identities) != len(set(identities)):
            _fail("OCR block ids are duplicated within a page")
        object.__setattr__(self, "selected_index", selected_index)
        object.__setattr__(self, "source_page", source_page)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(
            self,
            "source_page_object_hash",
            _digest(
                self.source_page_object_hash,
                "OCR inventory source_page_object_hash",
            ),
        )
        object.__setattr__(
            self,
            "source_text_layer_sha256",
            _digest(
                self.source_text_layer_sha256,
                "OCR inventory source_text_layer_sha256",
            ),
        )

    @property
    def blocks_by_id(self) -> Mapping[str, OcrBlockInventoryBlock]:
        return MappingProxyType({block.block_id: block for block in self.blocks})

    def to_dict(self) -> dict[str, object]:
        return {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "selected_index": self.selected_index,
            "source_page_object_hash": self.source_page_object_hash,
            "source_text_layer_sha256": self.source_text_layer_sha256,
            "blocks": [block.to_dict() for block in self.blocks],
        }


@dataclass(frozen=True, slots=True)
class OcrBlockInventory:
    run_id: str
    source_sha256: str
    selected_pages: tuple[int, ...]
    pages: tuple[OcrBlockInventoryPage, ...]
    schema_version: str = OCR_BLOCK_INVENTORY_SCHEMA

    def __post_init__(self) -> None:
        run_id = str(self.run_id or "").strip().lower()
        if _RUN_ID_RE.fullmatch(run_id) is None:
            _fail("OCR block inventory run_id is invalid")
        selected_pages = tuple(self.selected_pages)
        if (
            not selected_pages
            or any(type(page) is not int or page < 1 for page in selected_pages)
            or len(selected_pages) != len(set(selected_pages))
        ):
            _fail("OCR block inventory selected_pages are invalid")
        pages = tuple(self.pages)
        if len(pages) != len(selected_pages):
            _fail("OCR block inventory does not cover every selected page")
        for selected_index, (source_page, page) in enumerate(
            zip(selected_pages, pages, strict=True), start=1
        ):
            if (
                page.selected_index != selected_index
                or page.page_id != f"ocr-page-{selected_index:06d}"
                or page.source_page != source_page
            ):
                _fail("OCR block inventory page identity/order is stale")
        block_ids = tuple(
            block.block_id for page in pages for block in page.blocks
        )
        if len(block_ids) != len(set(block_ids)):
            _fail("OCR block ids are duplicated across pages")
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(
            self,
            "source_sha256",
            _digest(self.source_sha256, "OCR block inventory source_sha256"),
        )
        object.__setattr__(self, "selected_pages", selected_pages)
        object.__setattr__(self, "pages", pages)
        object.__setattr__(self, "schema_version", OCR_BLOCK_INVENTORY_SCHEMA)

    @property
    def pages_by_id(self) -> Mapping[str, OcrBlockInventoryPage]:
        return MappingProxyType({page.page_id: page for page in self.pages})

    @property
    def sha256(self) -> str:
        return _sha256(self.to_json_bytes())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": OCR_BLOCK_INVENTORY_SCHEMA,
            "run_id": self.run_id,
            "source_sha256": self.source_sha256,
            "selected_pages": list(self.selected_pages),
            "pages": [page.to_dict() for page in self.pages],
        }

    def to_json_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())

    def native_source_block_projection(self) -> tuple[Mapping[str, object], ...]:
        """Return analysis-visible native objects in selected-page/read order.

        Textless FIGURE/TABLE objects remain first-class evidence.  Their bbox,
        type, order, object hash, and optional host materialization path are
        retained without inventing body text.
        """
        rows: list[Mapping[str, object]] = []
        for page in self.pages:
            for block in page.blocks:
                if (
                    not block.plain_text.strip()
                    and block.block_type not in {
                        PageBlockType.FIGURE,
                        PageBlockType.TABLE,
                    }
                ):
                    continue
                style = dict(block.style_features)
                rows.append(MappingProxyType({
                    "page_id": page.page_id,
                    "source_page": page.source_page,
                    "block_id": block.block_id,
                    "block_type": block.block_type.value,
                    "reading_order": block.reading_order,
                    "plain_text": block.plain_text,
                    "bbox": list(block.bbox),
                    "object_path": str(style.get("host_figure_path") or ""),
                    "source_sha256": block.source_object_hash,
                }))
        return tuple(rows)


def _block_from_mapping(value: object) -> OcrBlockInventoryBlock:
    if not isinstance(value, Mapping) or set(value) != {
        "block_id",
        "block_type",
        "reading_order",
        "plain_text",
        "style_features",
        "bbox",
        "source_object_hash",
    }:
        _fail("OCR block inventory block fields are malformed")
    return OcrBlockInventoryBlock(
        block_id=str(value["block_id"]),
        block_type=PageBlockType(str(value["block_type"])),
        reading_order=value["reading_order"],
        plain_text=str(value["plain_text"]),
        style_features=value["style_features"],
        bbox=value["bbox"],
        source_object_hash=str(value["source_object_hash"]),
    )


def _page_from_mapping(value: object) -> OcrBlockInventoryPage:
    if not isinstance(value, Mapping) or set(value) != {
        "page_id",
        "source_page",
        "selected_index",
        "source_page_object_hash",
        "source_text_layer_sha256",
        "blocks",
    }:
        _fail("OCR block inventory page fields are malformed")
    raw_blocks = value["blocks"]
    if not isinstance(raw_blocks, list):
        _fail("OCR block inventory blocks must be an array")
    try:
        blocks = tuple(_block_from_mapping(block) for block in raw_blocks)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, OcrBlockInventoryError):
            raise
        raise OcrBlockInventoryError("OCR block inventory block is invalid") from exc
    return OcrBlockInventoryPage(
        page_id=str(value["page_id"]),
        source_page=value["source_page"],
        selected_index=value["selected_index"],
        source_page_object_hash=str(value["source_page_object_hash"]),
        source_text_layer_sha256=str(value["source_text_layer_sha256"]),
        blocks=blocks,
    )


def _bind_snapshot_pages(
    inventory: OcrBlockInventory,
    expected_snapshot_pages: Sequence[Mapping[str, object]] | None,
) -> None:
    if expected_snapshot_pages is None:
        return
    rows = tuple(expected_snapshot_pages)
    if len(rows) != len(inventory.pages):
        _fail("OCR block inventory differs from snapshot page coverage")
    for page, row in zip(inventory.pages, rows, strict=True):
        if not isinstance(row, Mapping) or row.get("page_id") != page.page_id:
            _fail("OCR block inventory page identity differs from snapshot")
        comparisons = {
            "source_page": page.source_page,
            "source_page_object_hash": page.source_page_object_hash,
            "source_text_layer_sha256": page.source_text_layer_sha256,
            "block_count": len(page.blocks),
        }
        for key, expected in comparisons.items():
            if key in row and row[key] != expected:
                _fail(f"OCR block inventory {key} differs from snapshot")


def build_ocr_block_inventory(
    *,
    run_id: str,
    source_classification: SourceClassification,
    selected_pages: Sequence[int] | None = None,
) -> bytes:
    """Freeze deterministic source classifications without model content."""
    if not isinstance(source_classification, SourceClassification):
        _fail("OCR block inventory requires a host SourceClassification")
    pages = tuple(source_classification.pages)
    expected_pages = (
        tuple(page.source_page_number for page in pages)
        if selected_pages is None
        else tuple(selected_pages)
    )
    inventory_pages: list[OcrBlockInventoryPage] = []
    for page in pages:
        inventory_pages.append(OcrBlockInventoryPage(
            page_id=page.page_id,
            source_page=page.source_page_number,
            selected_index=page.selected_index,
            source_page_object_hash=page.source_page_object_hash,
            source_text_layer_sha256=page.source_text_layer_sha256,
            blocks=tuple(OcrBlockInventoryBlock(
                block_id=block.block_id,
                block_type=block.block_type,
                reading_order=block.reading_order,
                plain_text=block.plain_text,
                style_features=dict(block.style_features),
                bbox=block.bbox,
                source_object_hash=block.source_object_hash,
            ) for block in page.blocks),
        ))
    inventory = OcrBlockInventory(
        run_id=run_id,
        source_sha256=source_classification.source_sha256,
        selected_pages=expected_pages,
        pages=tuple(inventory_pages),
    )
    return inventory.to_json_bytes()


def parse_ocr_block_inventory(
    data: bytes,
    *,
    expected_run_id: str,
    expected_source_sha256: str,
    expected_selected_pages: Sequence[int],
    expected_snapshot_pages: Sequence[Mapping[str, object]] | None = None,
) -> OcrBlockInventory:
    """Strictly parse and bind a canonical native block inventory."""
    raw = bytes(data)
    if not raw or len(raw) > _MAX_ARTIFACT_BYTES:
        _fail("OCR block inventory artifact is empty or exceeds its size bound")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=lambda token: _fail(
                f"OCR block inventory contains non-finite {token}"
            ),
        )
    except OcrBlockInventoryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrBlockInventoryError(
            "OCR block inventory is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version", "run_id", "source_sha256", "selected_pages", "pages"
    }:
        _fail("OCR block inventory top-level fields are malformed")
    if value.get("schema_version") != OCR_BLOCK_INVENTORY_SCHEMA:
        _fail("unsupported OCR block inventory schema")
    raw_pages = value.get("pages")
    raw_selected = value.get("selected_pages")
    if not isinstance(raw_pages, list) or not isinstance(raw_selected, list):
        _fail("OCR block inventory pages must be arrays")
    try:
        inventory = OcrBlockInventory(
            run_id=str(value.get("run_id") or ""),
            source_sha256=str(value.get("source_sha256") or ""),
            selected_pages=tuple(raw_selected),
            pages=tuple(_page_from_mapping(page) for page in raw_pages),
        )
    except OcrBlockInventoryError:
        raise
    except (TypeError, ValueError) as exc:
        raise OcrBlockInventoryError("OCR block inventory is invalid") from exc
    if not hmac.compare_digest(raw, inventory.to_json_bytes()):
        _fail("OCR block inventory is not canonical/recomputable")
    expected_source = _digest(
        expected_source_sha256, "expected OCR block inventory source_sha256"
    )
    if (
        inventory.run_id != str(expected_run_id)
        or not hmac.compare_digest(inventory.source_sha256, expected_source)
        or inventory.selected_pages != tuple(expected_selected_pages)
    ):
        _fail("OCR block inventory differs from the expected run/source/pages")
    _bind_snapshot_pages(inventory, expected_snapshot_pages)
    return inventory


__all__ = [
    "OCR_BLOCK_INVENTORY_SCHEMA",
    "OcrBlockInventory",
    "OcrBlockInventoryBlock",
    "OcrBlockInventoryError",
    "OcrBlockInventoryPage",
    "build_ocr_block_inventory",
    "parse_ocr_block_inventory",
]
