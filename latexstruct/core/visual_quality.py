# -*- coding: utf-8 -*-
"""Deterministic, byte-only visual preflight for compiled PDF artifacts.

The checker intentionally has a narrow authority boundary: it can identify
rendering, pagination and gross layout defects, but it cannot prove semantic
accuracy or independent reconstruction.  In particular, byte-identical PDFs
and candidates whose rendered pages are copied from the source are rejected as
source reuse instead of being reported as a successful rebuild.

Only in-memory PDF bytes are accepted.  No host path is retained or emitted.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .preview import COMPILED, PARTIAL_COMPILED


SCHEMA_VERSION = "latexstruct-visual-quality-v1"
DEFAULT_RENDER_DPI = 24
_GRID_WIDTH = 64
_GRID_HEIGHT = 80
_PDF_STATUSES = frozenset({COMPILED, PARTIAL_COMPILED})
_MOJIBAKE_MARKERS = ("\ufffd", "Ã", "Â", "â€", "ï¿½", "锟斤拷")
CANDIDATE_SCOPE_AUTO = "auto"
CANDIDATE_SCOPE_SELECTED_RANGE = "selected_range"
CANDIDATE_SCOPE_FULL_SOURCE = "full_source"
CANDIDATE_SCOPE_REFLOW = "reflow"
_CANDIDATE_SCOPES = frozenset({
    CANDIDATE_SCOPE_AUTO,
    CANDIDATE_SCOPE_SELECTED_RANGE,
    CANDIDATE_SCOPE_FULL_SOURCE,
    CANDIDATE_SCOPE_REFLOW,
})
GEOMETRY_POLICY_STRICT_SOURCE = "strict_source"
GEOMETRY_POLICY_DERIVED_IMAGE = "derived_image"
GEOMETRY_POLICY_TEMPLATE_REFLOW = "template_reflow"
_GEOMETRY_POLICIES = frozenset({
    GEOMETRY_POLICY_STRICT_SOURCE,
    GEOMETRY_POLICY_DERIVED_IMAGE,
    GEOMETRY_POLICY_TEMPLATE_REFLOW,
})


class VisualQualityStatus(str, Enum):
    """Outcome of the deterministic visual preflight."""

    PASS = "PASS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"
    UNAVAILABLE = "UNAVAILABLE"


class VisualSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


_SEVERITY_RANK = {
    VisualSeverity.INFO: 0,
    VisualSeverity.WARNING: 1,
    VisualSeverity.ERROR: 2,
    VisualSeverity.CRITICAL: 3,
}


def _rounded(value: float) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("visual evidence contains a non-finite number")
    return round(number, 6)


@dataclass(frozen=True, slots=True)
class VisualFinding:
    code: str
    severity: VisualSeverity
    message: str
    source_page: int | None = None
    candidate_page: int | None = None
    needs_model_review: bool = False
    evidence: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "needs_model_review": self.needs_model_review,
        }
        if self.source_page is not None:
            result["source_page"] = self.source_page
        if self.candidate_page is not None:
            result["candidate_page"] = self.candidate_page
        if self.evidence:
            result["evidence"] = dict(self.evidence)
        return result

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class PageVisualMetrics:
    page: int
    width_points: float
    height_points: float
    render_width: int
    render_height: int
    text_block_count: int
    text_character_count: int
    text_block_area_ratio: float
    ink_ratio: float
    replacement_character_count: int
    suspicious_character_ratio: float
    render_sha256: str
    low_resolution_sha256: str
    text_layout_sha256: str
    text_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "page": self.page,
            "width_points": self.width_points,
            "height_points": self.height_points,
            "render_width": self.render_width,
            "render_height": self.render_height,
            "text_block_count": self.text_block_count,
            "text_character_count": self.text_character_count,
            "text_block_area_ratio": self.text_block_area_ratio,
            "ink_ratio": self.ink_ratio,
            "replacement_character_count": self.replacement_character_count,
            "suspicious_character_ratio": self.suspicious_character_ratio,
            "render_sha256": self.render_sha256,
            "low_resolution_sha256": self.low_resolution_sha256,
            "text_layout_sha256": self.text_layout_sha256,
            "text_sha256": self.text_sha256,
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class PageDifferenceMetrics:
    width_relative_delta: float
    height_relative_delta: float
    orientation_changed: bool
    low_resolution_pixel_difference: float
    layout_occupancy_difference: float
    ink_ratio_delta: float
    text_character_ratio: float | None
    extracted_text_similarity: float | None
    text_block_delta_ratio: float | None
    text_block_area_delta: float
    pixel_identical: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "width_relative_delta": self.width_relative_delta,
            "height_relative_delta": self.height_relative_delta,
            "orientation_changed": self.orientation_changed,
            "low_resolution_pixel_difference": self.low_resolution_pixel_difference,
            "layout_occupancy_difference": self.layout_occupancy_difference,
            "ink_ratio_delta": self.ink_ratio_delta,
            "text_character_ratio": self.text_character_ratio,
            "extracted_text_similarity": self.extracted_text_similarity,
            "text_block_delta_ratio": self.text_block_delta_ratio,
            "text_block_area_delta": self.text_block_area_delta,
            "pixel_identical": self.pixel_identical,
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class VisualPageReport:
    source_page: int
    candidate_page: int | None
    source: PageVisualMetrics | None
    candidate: PageVisualMetrics | None
    difference: PageDifferenceMetrics | None
    findings: tuple[VisualFinding, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "source_page": self.source_page,
            "candidate_page": self.candidate_page,
            "source": self.source.to_dict() if self.source else None,
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "difference": self.difference.to_dict() if self.difference else None,
            "findings": [item.to_dict() for item in self.findings],
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class VisualPageMapping:
    source_page: int
    candidate_page: int | None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "source_page": self.source_page,
            "candidate_page": self.candidate_page,
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class VisualPageAlignment:
    policy: str
    expected_candidate_page_count: int
    selected_source_pages: tuple[int, ...]
    mappings: tuple[VisualPageMapping, ...]
    candidate_scope: str = CANDIDATE_SCOPE_AUTO
    source_page_count: int = 0
    candidate_page_count: int = 0
    strategy: str = "page_index"
    requires_model_review: bool = False
    mapping_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": self.policy,
            "expected_candidate_page_count": self.expected_candidate_page_count,
            "selected_source_pages": list(self.selected_source_pages),
            "mappings": [item.to_dict() for item in self.mappings],
            "candidate_scope": self.candidate_scope,
            "source_page_count": self.source_page_count,
            "candidate_page_count": self.candidate_page_count,
            "strategy": self.strategy,
            "requires_model_review": self.requires_model_review,
            "mapping_sha256": self.mapping_sha256,
        }

    as_dict = to_dict


@dataclass(frozen=True, slots=True)
class VisualQualityReport:
    status: VisualQualityStatus
    severity: VisualSeverity
    needs_model_review: bool
    preview_status: str
    partial_compiled: bool
    renderer: str
    renderer_version: str
    source_pdf_sha256: str
    candidate_pdf_sha256: str
    source_pdf_byte_count: int
    candidate_pdf_byte_count: int
    source_page_count: int
    candidate_page_count: int
    selected_source_pages: tuple[int, ...]
    alignment_policy: str
    compared_page_count: int
    source_reuse_detected: bool
    visual_preflight_passed: bool
    aggregate_metrics: Mapping[str, object]
    pages: tuple[VisualPageReport, ...]
    findings: tuple[VisualFinding, ...]
    page_alignment: VisualPageAlignment | None = None
    evidence_sha256: str = ""
    schema_version: str = SCHEMA_VERSION
    scope: str = "deterministic_visual_preflight_only"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope,
            "status": self.status.value,
            "severity": self.severity.value,
            "needs_model_review": self.needs_model_review,
            "preview_status": self.preview_status,
            "partial_compiled": self.partial_compiled,
            "renderer": self.renderer,
            "renderer_version": self.renderer_version,
            "source_pdf_sha256": self.source_pdf_sha256,
            "candidate_pdf_sha256": self.candidate_pdf_sha256,
            "source_pdf_byte_count": self.source_pdf_byte_count,
            "candidate_pdf_byte_count": self.candidate_pdf_byte_count,
            "source_page_count": self.source_page_count,
            "candidate_page_count": self.candidate_page_count,
            "selected_source_pages": list(self.selected_source_pages),
            "alignment_policy": self.alignment_policy,
            "compared_page_count": self.compared_page_count,
            "source_reuse_detected": self.source_reuse_detected,
            "visual_preflight_passed": self.visual_preflight_passed,
            "aggregate_metrics": dict(self.aggregate_metrics),
            "pages": [item.to_dict() for item in self.pages],
            "findings": [item.to_dict() for item in self.findings],
            "page_alignment": (
                self.page_alignment.to_dict() if self.page_alignment else None
            ),
            "evidence_sha256": self.evidence_sha256,
            "limitations": [
                "does_not_verify_semantic_accuracy",
                "does_not_establish_independent_reconstruction",
            ],
        }

    as_dict = to_dict

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
        )


@dataclass(frozen=True, slots=True)
class _RenderedPage:
    metrics: PageVisualMetrics
    grid: bytes
    text: str
    mojibake_hits: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _coerce_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return b""


def _load_pymupdf():
    try:
        import pymupdf  # type: ignore
    except Exception:  # noqa: BLE001 - optional native dependency boundary
        return None
    return pymupdf


def _renderer_identity(module) -> tuple[str, str]:
    version = str(
        getattr(module, "VersionBind", "")
        or getattr(module, "__version__", "")
        or "unknown"
    )
    # Version identifiers are bounded and never need host paths.
    return "PyMuPDF", re.sub(r"[^0-9A-Za-z.+_-]", "", version)[:64] or "unknown"


def _normalize_page_range(value: object, total_pages: int) -> tuple[int, ...]:
    if total_pages <= 0:
        return ()
    if value is None or (isinstance(value, str) and value.strip().casefold() == "all"):
        return tuple(range(1, total_pages + 1))

    pages: Iterable[object]
    if isinstance(value, Mapping):
        explicit = value.get("pages")
        if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
            pages = explicit
        else:
            start = int(value.get("start") or 1)
            end = int(value.get("end") or start)
            pages = range(start, end + 1)
    elif isinstance(value, str):
        parsed: list[int] = []
        for part in value.split(","):
            token = part.strip()
            if not token:
                continue
            match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", token)
            if match:
                start, end = (int(match.group(1)), int(match.group(2)))
                if end < start:
                    raise ValueError("page range end precedes start")
                parsed.extend(range(start, end + 1))
            elif token.isdigit():
                parsed.append(int(token))
            else:
                raise ValueError("page range must contain one-based page numbers")
        pages = parsed
    elif (
        isinstance(value, tuple)
        and len(value) == 2
        and all(isinstance(item, int) and not isinstance(item, bool) for item in value)
    ):
        start, end = value
        if end < start:
            raise ValueError("page range end precedes start")
        pages = range(start, end + 1)
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        pages = value
    else:
        raise ValueError("unsupported page range")

    result: list[int] = []
    seen: set[int] = set()
    for raw in pages:
        if isinstance(raw, bool):
            raise ValueError("page numbers must be integers")
        page = int(raw)
        if page < 1 or page > total_pages:
            raise ValueError("page range exceeds the source PDF")
        if page not in seen:
            result.append(page)
            seen.add(page)
    if not result:
        raise ValueError("page range is empty")
    return tuple(sorted(result))


def _page_alignment_sha256(
    *,
    policy: str,
    expected_candidate_page_count: int,
    selected_source_pages: Sequence[int],
    mappings: Sequence[VisualPageMapping],
    candidate_scope: str,
    source_page_count: int,
    candidate_page_count: int,
    strategy: str,
    requires_model_review: bool,
) -> str:
    payload = {
        "policy": policy,
        "expected_candidate_page_count": int(expected_candidate_page_count),
        "selected_source_pages": [int(page) for page in selected_source_pages],
        "mappings": [item.to_dict() for item in mappings],
        "candidate_scope": candidate_scope,
        "source_page_count": int(source_page_count),
        "candidate_page_count": int(candidate_page_count),
        "strategy": strategy,
        "requires_model_review": bool(requires_model_review),
    }
    return _sha256(json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _finish_alignment(
    *,
    policy: str,
    expected_candidate_page_count: int,
    selected_source_pages: tuple[int, ...],
    mappings: Sequence[VisualPageMapping],
    candidate_scope: str,
    source_page_count: int,
    candidate_page_count: int,
    strategy: str,
    requires_model_review: bool = False,
) -> VisualPageAlignment:
    frozen_mappings = tuple(mappings)
    digest = _page_alignment_sha256(
        policy=policy,
        expected_candidate_page_count=expected_candidate_page_count,
        selected_source_pages=selected_source_pages,
        mappings=frozen_mappings,
        candidate_scope=candidate_scope,
        source_page_count=source_page_count,
        candidate_page_count=candidate_page_count,
        strategy=strategy,
        requires_model_review=requires_model_review,
    )
    return VisualPageAlignment(
        policy=policy,
        expected_candidate_page_count=expected_candidate_page_count,
        selected_source_pages=selected_source_pages,
        mappings=frozen_mappings,
        candidate_scope=candidate_scope,
        source_page_count=source_page_count,
        candidate_page_count=candidate_page_count,
        strategy=strategy,
        requires_model_review=requires_model_review,
        mapping_sha256=digest,
    )


def _alignment_text(
    texts: Mapping[int, str] | Sequence[str] | None,
    page: int,
) -> str:
    if isinstance(texts, Mapping):
        return _normalized_text(str(texts.get(page) or ""))
    if isinstance(texts, Sequence) and not isinstance(texts, (str, bytes)):
        index = page - 1
        if 0 <= index < len(texts):
            return _normalized_text(str(texts[index] or ""))
    return ""


def _alignment_tokens(text: str) -> frozenset[str]:
    """Return bounded layout-insensitive host anchors for one extracted page."""

    normalized = _normalized_text(text).casefold()
    if not normalized:
        return frozenset()
    tokens = {
        token for token in re.findall(r"[^\W_]{4,}", normalized, flags=re.UNICODE)
        if not token.isdigit()
    }
    compact = re.sub(r"[^0-9a-z\u3400-\u9fff]+", "", normalized)
    # Character shingles preserve anchors in CJK and math-heavy pages where
    # whitespace tokenization is weak.  The stride and cap keep long books
    # linear in their extracted text size.
    for start in range(0, max(0, len(compact) - 11), 8):
        tokens.add("#" + compact[start:start + 12])
        if len(tokens) >= 256:
            break
    return frozenset(sorted(tokens)[:256])


def _monotonic_text_anchors(
    source_texts: Sequence[str],
    candidate_texts: Sequence[str],
) -> tuple[tuple[int, int], ...]:
    """Find a deterministic maximum-weight chain of rare shared page anchors."""

    source_tokens = [_alignment_tokens(text) for text in source_texts]
    candidate_tokens = [_alignment_tokens(text) for text in candidate_texts]
    source_occurrences: dict[str, list[int]] = {}
    candidate_occurrences: dict[str, list[int]] = {}
    for index, tokens in enumerate(source_tokens):
        for token in tokens:
            source_occurrences.setdefault(token, []).append(index)
    for index, tokens in enumerate(candidate_tokens):
        for token in tokens:
            candidate_occurrences.setdefault(token, []).append(index)

    scores: dict[tuple[int, int], int] = {}
    for token, source_pages in source_occurrences.items():
        candidate_pages = candidate_occurrences.get(token, ())
        if not candidate_pages or len(source_pages) > 4 or len(candidate_pages) > 4:
            continue
        for source_index in source_pages:
            for candidate_index in candidate_pages:
                key = (source_index, candidate_index)
                scores[key] = scores.get(key, 0) + 1
    exact_candidate_pages: dict[str, list[int]] = {}
    for candidate_index, candidate_text in enumerate(candidate_texts):
        normalized_candidate = _normalized_text(candidate_text)
        if len(normalized_candidate) >= 24:
            exact_candidate_pages.setdefault(normalized_candidate, []).append(
                candidate_index
            )
    for source_index, source_text in enumerate(source_texts):
        normalized_source = _normalized_text(source_text)
        if len(normalized_source) < 24:
            continue
        for candidate_index in exact_candidate_pages.get(normalized_source, ()):
            key = (source_index, candidate_index)
            scores[key] = scores.get(key, 0) + 1000

    by_source: dict[int, list[tuple[int, int]]] = {}
    for (source_index, candidate_index), score in scores.items():
        if score >= 2:
            by_source.setdefault(source_index, []).append((candidate_index, score))
    for source_index, items in by_source.items():
        by_source[source_index] = sorted(items, key=lambda item: (-item[1], item[0]))[:4]

    # Fenwick maximum-weight increasing subsequence.  Updates for one source
    # page are delayed so anchors are strictly increasing on both axes.
    size = len(candidate_texts)
    tree: list[int | None] = [None] * (size + 1)
    nodes: list[tuple[int, int, int, int | None]] = []

    def better(left: int | None, right: int | None) -> int | None:
        if left is None:
            return right
        if right is None:
            return left
        left_node = nodes[left]
        right_node = nodes[right]
        left_key = (left_node[2], -left_node[1], -left_node[0])
        right_key = (right_node[2], -right_node[1], -right_node[0])
        return right if right_key > left_key else left

    def query(candidate_index: int) -> int | None:
        result = None
        position = candidate_index
        while position > 0:
            result = better(result, tree[position])
            position -= position & -position
        return result

    def update(candidate_index: int, node_index: int) -> None:
        position = candidate_index + 1
        while position <= size:
            tree[position] = better(tree[position], node_index)
            position += position & -position

    for source_index in sorted(by_source):
        pending: list[tuple[int, int]] = []
        for candidate_index, score in by_source[source_index]:
            previous = query(candidate_index)
            total = score + (nodes[previous][2] if previous is not None else 0)
            nodes.append((source_index, candidate_index, total, previous))
            pending.append((candidate_index, len(nodes) - 1))
        for candidate_index, node_index in pending:
            update(candidate_index, node_index)
    best = None
    for node_index in range(len(nodes)):
        best = better(best, node_index)
    chain: list[tuple[int, int]] = []
    while best is not None:
        source_index, candidate_index, _score, best = nodes[best]
        chain.append((source_index, candidate_index))
    return tuple(reversed(chain))


def _weighted_monotonic_pairs(
    source_pages: Sequence[int],
    candidate_pages: Sequence[int],
    source_texts: Mapping[int, str],
    candidate_texts: Mapping[int, str],
    anchors: Sequence[tuple[int, int]] = (),
) -> list[VisualPageMapping]:
    """Return the minimum-size complete monotonic mapping.

    The larger side appears exactly once, so the number of vision calls is
    ``max(source pages, candidate pages)``.  A two-transition dynamic program
    chooses where the smaller side repeats using cumulative content position
    and host text anchors; memory is one byte per possible page pair.
    """

    if not source_pages or not candidate_pages:
        return []
    source_weights = [max(1, len(source_texts.get(page, ""))) for page in source_pages]
    candidate_weights = [
        max(1, len(candidate_texts.get(page, ""))) for page in candidate_pages
    ]
    def midpoints(weights: Sequence[int]) -> list[float]:
        total = max(1, sum(weights))
        consumed = 0
        result = []
        for weight in weights:
            result.append((consumed + weight / 2.0) / total)
            consumed += weight
        return result

    source_positions = midpoints(source_weights)
    candidate_positions = midpoints(candidate_weights)
    anchor_set = set(anchors)

    def local_cost(source_index: int, candidate_index: int) -> float:
        cost = abs(
            source_positions[source_index] - candidate_positions[candidate_index]
        )
        if (source_index, candidate_index) in anchor_set:
            cost -= 2.0
        return cost

    source_count = len(source_pages)
    candidate_count = len(candidate_pages)
    infinity = float("inf")
    if candidate_count >= source_count:
        # One mapping per candidate; source indices may repeat.
        previous = [infinity] * source_count
        previous[0] = local_cost(0, 0)
        choices = [bytearray(source_count) for _ in range(candidate_count)]
        for candidate_index in range(1, candidate_count):
            current = [infinity] * source_count
            lower = max(0, source_count - 1 - (candidate_count - 1 - candidate_index))
            upper = min(candidate_index, source_count - 1)
            for source_index in range(lower, upper + 1):
                stay = previous[source_index]
                advance = previous[source_index - 1] if source_index else infinity
                if advance <= stay:
                    current[source_index] = advance + local_cost(
                        source_index, candidate_index
                    )
                    choices[candidate_index][source_index] = 1
                else:
                    current[source_index] = stay + local_cost(
                        source_index, candidate_index
                    )
            previous = current
        source_index = source_count - 1
        reversed_result: list[VisualPageMapping] = []
        for candidate_index in range(candidate_count - 1, -1, -1):
            reversed_result.append(VisualPageMapping(
                int(source_pages[source_index]),
                int(candidate_pages[candidate_index]),
            ))
            if candidate_index and choices[candidate_index][source_index]:
                source_index -= 1
        return list(reversed(reversed_result))

    # One mapping per source; candidate indices may repeat.
    previous = [infinity] * candidate_count
    previous[0] = local_cost(0, 0)
    choices = [bytearray(candidate_count) for _ in range(source_count)]
    for source_index in range(1, source_count):
        current = [infinity] * candidate_count
        lower = max(0, candidate_count - 1 - (source_count - 1 - source_index))
        upper = min(source_index, candidate_count - 1)
        for candidate_index in range(lower, upper + 1):
            stay = previous[candidate_index]
            advance = previous[candidate_index - 1] if candidate_index else infinity
            if advance <= stay:
                current[candidate_index] = advance + local_cost(
                    source_index, candidate_index
                )
                choices[source_index][candidate_index] = 1
            else:
                current[candidate_index] = stay + local_cost(
                    source_index, candidate_index
                )
        previous = current
    candidate_index = candidate_count - 1
    reversed_result = []
    for source_index in range(source_count - 1, -1, -1):
        reversed_result.append(VisualPageMapping(
            int(source_pages[source_index]),
            int(candidate_pages[candidate_index]),
        ))
        if source_index and choices[source_index][candidate_index]:
            candidate_index -= 1
    return list(reversed(reversed_result))


def _reflow_mappings(
    selected: tuple[int, ...],
    candidate_count: int,
    source_page_texts: Mapping[int, str] | Sequence[str] | None,
    candidate_page_texts: Mapping[int, str] | Sequence[str] | None,
) -> tuple[tuple[VisualPageMapping, ...], str, bool]:
    if candidate_count <= 0:
        return (
            tuple(VisualPageMapping(page, None) for page in selected),
            "proportional_no_candidate_pages",
            True,
        )
    source_text = {
        page: _alignment_text(source_page_texts, page) for page in selected
    }
    candidate_text = {
        page: _alignment_text(candidate_page_texts, page)
        for page in range(1, candidate_count + 1)
    }
    ordered_source_text = [source_text[page] for page in selected]
    ordered_candidate_text = [
        candidate_text[page] for page in range(1, candidate_count + 1)
    ]
    anchors = _monotonic_text_anchors(ordered_source_text, ordered_candidate_text)
    unique = _weighted_monotonic_pairs(
        selected,
        tuple(range(1, candidate_count + 1)),
        source_text,
        candidate_text,
        anchors,
    )
    no_text_layer = not any(ordered_source_text) or not any(ordered_candidate_text)
    strategy = (
        "proportional_no_text_layer"
        if no_text_layer
        else "content_anchor_monotonic"
        if anchors
        else "content_weighted_monotonic"
    )
    return tuple(unique), strategy, no_text_layer


def build_page_alignment(
    source_page_count: int,
    candidate_page_count: int,
    page_range: object = None,
    *,
    candidate_scope: str = CANDIDATE_SCOPE_AUTO,
    source_page_texts: Mapping[int, str] | Sequence[str] | None = None,
    candidate_page_texts: Mapping[int, str] | Sequence[str] | None = None,
) -> VisualPageAlignment:
    """Map one-based source pages to candidate pages without guessing content.

    A candidate whose page count equals the selected range is interpreted as a
    selected-range build.  A full-size candidate uses identical page indices.
    Partial documents retain explicit ``None`` mappings for unavailable pages.
    """

    source_count = int(source_page_count)
    candidate_count = int(candidate_page_count)
    if source_count <= 0 or candidate_count < 0:
        raise ValueError("page counts must describe a non-empty source PDF")
    normalized_scope = str(candidate_scope or "").strip().lower()
    if normalized_scope not in _CANDIDATE_SCOPES:
        raise ValueError(
            "candidate_scope must be auto, selected_range, full_source, or reflow"
        )
    selected = _normalize_page_range(page_range, source_count)
    full_source_range = selected == tuple(range(1, source_count + 1))
    strategy = "page_index"
    requires_model_review = False
    if normalized_scope == CANDIDATE_SCOPE_REFLOW:
        policy = "content_anchor_monotonic_reflow"
        expected = candidate_count
        mappings, strategy, requires_model_review = _reflow_mappings(
            selected,
            candidate_count,
            source_page_texts,
            candidate_page_texts,
        )
        return _finish_alignment(
            policy=policy,
            expected_candidate_page_count=expected,
            selected_source_pages=selected,
            mappings=mappings,
            candidate_scope=normalized_scope,
            source_page_count=source_count,
            candidate_page_count=candidate_count,
            strategy=strategy,
            requires_model_review=requires_model_review,
        )
    if normalized_scope == CANDIDATE_SCOPE_SELECTED_RANGE:
        policy = "selected_range_sequence_explicit"
        expected = len(selected)
        candidate_pages = tuple(
            index if index <= candidate_count else None
            for index in range(1, len(selected) + 1)
        )
    elif normalized_scope == CANDIDATE_SCOPE_FULL_SOURCE:
        policy = "same_page_index_explicit"
        expected = source_count
        candidate_pages = tuple(
            page if page <= candidate_count else None for page in selected
        )
    elif candidate_count == source_count:
        policy = "same_page_index"
        candidate_pages: tuple[int | None, ...] = tuple(selected)
        expected = source_count
    elif len(selected) == candidate_count:
        policy = "selected_range_sequence"
        candidate_pages = tuple(range(1, candidate_count + 1))
        expected = len(selected)
    elif not full_source_range and candidate_count > len(selected):
        policy = "same_page_index_partial_document"
        candidate_pages = tuple(
            page if page <= candidate_count else None for page in selected
        )
        expected = source_count
    else:
        policy = "selected_range_sequence_partial"
        candidate_pages = tuple(
            index if index <= candidate_count else None
            for index in range(1, len(selected) + 1)
        )
        expected = len(selected)
    return _finish_alignment(
        policy=policy,
        expected_candidate_page_count=expected,
        selected_source_pages=selected,
        mappings=tuple(
            VisualPageMapping(source_page=source_page, candidate_page=candidate_page)
            for source_page, candidate_page in zip(selected, candidate_pages)
        ),
        candidate_scope=normalized_scope,
        source_page_count=source_count,
        candidate_page_count=candidate_count,
        strategy=strategy,
        requires_model_review=requires_model_review,
    )


def _downsample_gray(samples: bytes, width: int, height: int) -> bytes:
    """Area-average one grayscale render into a stable small evidence grid."""
    if width <= 0 or height <= 0 or len(samples) < width * height:
        raise ValueError("invalid grayscale render")
    output = bytearray(_GRID_WIDTH * _GRID_HEIGHT)
    for target_y in range(_GRID_HEIGHT):
        y0 = target_y * height // _GRID_HEIGHT
        y1 = max(y0 + 1, (target_y + 1) * height // _GRID_HEIGHT)
        y1 = min(y1, height)
        for target_x in range(_GRID_WIDTH):
            x0 = target_x * width // _GRID_WIDTH
            x1 = max(x0 + 1, (target_x + 1) * width // _GRID_WIDTH)
            x1 = min(x1, width)
            total = 0
            count = 0
            for row in range(y0, y1):
                start = row * width + x0
                stop = row * width + x1
                chunk = samples[start:stop]
                total += sum(chunk)
                count += len(chunk)
            output[target_y * _GRID_WIDTH + target_x] = total // max(1, count)
    return bytes(output)


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _extract_page_alignment_text(page) -> str:
    """Extract bounded host-only alignment text without rendering page pixels."""

    try:
        value = page.get_text("text", sort=True)
    except TypeError:  # pragma: no cover - older PyMuPDF compatibility
        value = page.get_text("text")
    except Exception:  # noqa: BLE001 - absence becomes explicit fallback evidence
        return ""
    return _normalized_text(str(value or ""))[:20000]


def _suspicious_text_facts(text: str) -> tuple[int, float, int]:
    if not text:
        return 0, 0.0, 0
    replacement_count = text.count("\ufffd")
    controls = sum(
        1 for character in text
        if ord(character) < 32 and character not in "\n\r\t"
    )
    private_use = sum(1 for character in text if 0xE000 <= ord(character) <= 0xF8FF)
    mojibake_hits = sum(text.count(marker) for marker in _MOJIBAKE_MARKERS)
    suspicious = replacement_count + controls + private_use + mojibake_hits
    return replacement_count, suspicious / max(1, len(text)), mojibake_hits


def _render_page(module, page, page_number: int, render_dpi: int) -> _RenderedPage:
    rect = page.rect
    page_width = float(rect.width)
    page_height = float(rect.height)
    if (
        not math.isfinite(page_width)
        or not math.isfinite(page_height)
        or page_width <= 0
        or page_height <= 0
        or page_width > 4000
        or page_height > 4000
    ):
        raise ValueError("page dimensions are outside the safe render range")
    scale = float(render_dpi) / 72.0
    pixmap = page.get_pixmap(
        matrix=module.Matrix(scale, scale),
        colorspace=module.csGRAY,
        alpha=False,
    )
    width = int(pixmap.width)
    height = int(pixmap.height)
    stride = int(getattr(pixmap, "stride", width))
    raw_samples = bytes(pixmap.samples)
    if stride == width:
        samples = raw_samples[: width * height]
    else:
        samples = b"".join(
            raw_samples[row * stride:row * stride + width]
            for row in range(height)
        )
    grid = _downsample_gray(samples, width, height)
    try:
        raw_blocks = page.get_text("blocks", sort=True)
    except TypeError:  # pragma: no cover - compatibility with older PyMuPDF
        raw_blocks = page.get_text("blocks")
    texts: list[str] = []
    block_layout: list[str] = []
    block_area = 0.0
    block_count = 0
    for block in raw_blocks or ():
        if len(block) < 5:
            continue
        text = str(block[4] or "")
        if not text.strip():
            continue
        # PyMuPDF's seventh field is block type: 0 text, 1 image.  Old
        # versions may omit it, in which case non-empty text remains evidence.
        if len(block) > 6 and block[6] not in (0, None):
            continue
        texts.append(text)
        x0, y0, x1, y1 = (float(block[index]) for index in range(4))
        clipped_x0 = min(page_width, max(0.0, x0))
        clipped_y0 = min(page_height, max(0.0, y0))
        clipped_x1 = min(page_width, max(clipped_x0, x1))
        clipped_y1 = min(page_height, max(clipped_y0, y1))
        block_area += (clipped_x1 - clipped_x0) * (clipped_y1 - clipped_y0)
        block_layout.append(
            ",".join(
                f"{value:.5f}"
                for value in (
                    clipped_x0 / page_width,
                    clipped_y0 / page_height,
                    clipped_x1 / page_width,
                    clipped_y1 / page_height,
                )
            )
        )
        block_count += 1
    text = _normalized_text("\n".join(texts))
    replacement_count, suspicious_ratio, mojibake_hits = _suspicious_text_facts(text)
    ink_ratio = sum(1 for value in samples if value < 245) / max(1, len(samples))
    render_digest = hashlib.sha256(
        f"{width}x{height}:".encode("ascii") + samples
    ).hexdigest()
    metrics = PageVisualMetrics(
        page=page_number,
        width_points=_rounded(page_width),
        height_points=_rounded(page_height),
        render_width=width,
        render_height=height,
        text_block_count=block_count,
        text_character_count=len(text),
        text_block_area_ratio=_rounded(
            min(1.0, block_area / max(1.0, page_width * page_height))
        ),
        ink_ratio=_rounded(ink_ratio),
        replacement_character_count=replacement_count,
        suspicious_character_ratio=_rounded(suspicious_ratio),
        render_sha256=render_digest,
        low_resolution_sha256=_sha256(grid),
        text_layout_sha256=_sha256("\n".join(block_layout).encode("ascii")),
        text_sha256=_sha256(text.encode("utf-8")),
    )
    return _RenderedPage(metrics=metrics, grid=grid, text=text, mojibake_hits=mojibake_hits)


def _relative_delta(left: float, right: float) -> float:
    return abs(float(left) - float(right)) / max(abs(float(left)), 1e-9)


def _grid_differences(source: bytes, candidate: bytes) -> tuple[float, float]:
    if len(source) != len(candidate) or not source:
        return 1.0, 1.0
    pixel = sum(abs(left - right) for left, right in zip(source, candidate))
    pixel_difference = pixel / (255.0 * len(source))
    occupancy = sum(
        (left < 240) != (right < 240)
        for left, right in zip(source, candidate)
    ) / len(source)
    return _rounded(pixel_difference), _rounded(occupancy)


def _text_similarity(source: str, candidate: str) -> float | None:
    if not source and not candidate:
        return None
    return _rounded(
        difflib.SequenceMatcher(None, source, candidate, autojunk=False).ratio()
    )


def _page_comparison(
    source_page: int,
    candidate_page: int,
    source: _RenderedPage,
    candidate: _RenderedPage,
    *,
    geometry_policy: str,
) -> VisualPageReport:
    source_geometry_authoritative = geometry_policy == GEOMETRY_POLICY_STRICT_SOURCE
    source_metrics = source.metrics
    candidate_metrics = candidate.metrics
    width_delta = _relative_delta(
        source_metrics.width_points, candidate_metrics.width_points
    )
    height_delta = _relative_delta(
        source_metrics.height_points, candidate_metrics.height_points
    )
    source_landscape = source_metrics.width_points > source_metrics.height_points
    candidate_landscape = candidate_metrics.width_points > candidate_metrics.height_points
    pixel_difference, occupancy_difference = _grid_differences(
        source.grid, candidate.grid
    )
    text_similarity = _text_similarity(source.text, candidate.text)
    character_ratio = (
        candidate_metrics.text_character_count / source_metrics.text_character_count
        if source_metrics.text_character_count
        else None
    )
    block_delta = (
        abs(candidate_metrics.text_block_count - source_metrics.text_block_count)
        / source_metrics.text_block_count
        if source_metrics.text_block_count
        else None
    )
    pixel_identical = (
        source_metrics.render_sha256 == candidate_metrics.render_sha256
        and source_metrics.render_width == candidate_metrics.render_width
        and source_metrics.render_height == candidate_metrics.render_height
    )
    difference = PageDifferenceMetrics(
        width_relative_delta=_rounded(width_delta),
        height_relative_delta=_rounded(height_delta),
        orientation_changed=source_landscape != candidate_landscape,
        low_resolution_pixel_difference=pixel_difference,
        layout_occupancy_difference=occupancy_difference,
        ink_ratio_delta=_rounded(
            abs(candidate_metrics.ink_ratio - source_metrics.ink_ratio)
        ),
        text_character_ratio=(
            _rounded(character_ratio) if character_ratio is not None else None
        ),
        extracted_text_similarity=text_similarity,
        text_block_delta_ratio=(
            _rounded(block_delta) if block_delta is not None else None
        ),
        text_block_area_delta=_rounded(abs(
            candidate_metrics.text_block_area_ratio
            - source_metrics.text_block_area_ratio
        )),
        pixel_identical=pixel_identical,
    )
    findings: list[VisualFinding] = []
    page_evidence = {"source_page": source_page, "candidate_page": candidate_page}

    if pixel_identical:
        findings.append(VisualFinding(
            code="PIXEL_IDENTICAL_TO_SOURCE",
            severity=VisualSeverity.INFO,
            message="The candidate page render is pixel-identical to the source page.",
            source_page=source_page,
            candidate_page=candidate_page,
            evidence=page_evidence,
        ))
    if difference.orientation_changed:
        findings.append(VisualFinding(
            code="PAGE_ORIENTATION_MISMATCH",
            severity=VisualSeverity.ERROR,
            message="Candidate page orientation differs from the source page.",
            source_page=source_page,
            candidate_page=candidate_page,
            evidence=page_evidence,
        ))
    elif max(width_delta, height_delta) >= 0.20:
        if geometry_policy == GEOMETRY_POLICY_STRICT_SOURCE:
            size_code = "PAGE_SIZE_MISMATCH"
            size_severity = VisualSeverity.ERROR
            size_message = "Candidate page dimensions differ materially from the source."
        elif geometry_policy == GEOMETRY_POLICY_TEMPLATE_REFLOW:
            size_code = "TEMPLATE_REFLOW_PAGE_SIZE"
            size_severity = VisualSeverity.WARNING
            size_message = (
                "An explicit layout-changing template owns candidate paper geometry; "
                "the size difference requires visual review."
            )
        else:
            size_code = "SOURCE_PAGE_SIZE_NON_AUTHORITATIVE"
            size_severity = VisualSeverity.WARNING
            size_message = (
                "The source is an image wrapper whose PDF point dimensions are not "
                "authoritative; the size difference requires visual review."
            )
        findings.append(VisualFinding(
            code=size_code,
            severity=size_severity,
            message=size_message,
            source_page=source_page,
            candidate_page=candidate_page,
            needs_model_review=not source_geometry_authoritative,
            evidence={
                **page_evidence,
                "width_relative_delta": _rounded(width_delta),
                "height_relative_delta": _rounded(height_delta),
                "source_geometry_authoritative": source_geometry_authoritative,
                "geometry_policy": geometry_policy,
            },
        ))
    elif max(width_delta, height_delta) >= 0.08:
        findings.append(VisualFinding(
            code="PAGE_SIZE_CHANGED",
            severity=VisualSeverity.WARNING,
            message="Candidate page dimensions changed enough to require visual review.",
            source_page=source_page,
            candidate_page=candidate_page,
            needs_model_review=True,
            evidence={
                **page_evidence,
                "width_relative_delta": _rounded(width_delta),
                "height_relative_delta": _rounded(height_delta),
                "source_geometry_authoritative": source_geometry_authoritative,
                "geometry_policy": geometry_policy,
            },
        ))

    source_has_content = (
        source_metrics.text_character_count >= 10 or source_metrics.ink_ratio >= 0.005
    )
    candidate_is_blank = (
        candidate_metrics.text_character_count == 0
        and candidate_metrics.ink_ratio < 0.0015
    )
    if source_has_content and candidate_is_blank:
        findings.append(VisualFinding(
            code="BLANK_CANDIDATE_PAGE",
            severity=VisualSeverity.CRITICAL,
            message="A source page with visible content became blank in the candidate PDF.",
            source_page=source_page,
            candidate_page=candidate_page,
            evidence={
                **page_evidence,
                "source_ink_ratio": source_metrics.ink_ratio,
                "candidate_ink_ratio": candidate_metrics.ink_ratio,
            },
        ))

    template_reflow_text_review = bool(
        geometry_policy == GEOMETRY_POLICY_TEMPLATE_REFLOW
    )
    if (
        candidate_metrics.replacement_character_count >= 2
        or candidate_metrics.suspicious_character_ratio >= 0.04
        or candidate.mojibake_hits >= 3
    ):
        findings.append(VisualFinding(
            code=(
                "TEMPLATE_REFLOW_TEXT_LAYER_REVIEW"
                if template_reflow_text_review
                else "GARBLED_TEXT_LAYER"
            ),
            severity=(
                VisualSeverity.WARNING
                if template_reflow_text_review
                else VisualSeverity.ERROR
            ),
            message=(
                "The reflowed mathematical PDF exposes suspicious text-extraction "
                "indicators; visual review must confirm the rendered page before "
                "the result can pass."
                if template_reflow_text_review
                else "The candidate text layer contains deterministic mojibake indicators."
            ),
            source_page=source_page,
            candidate_page=candidate_page,
            needs_model_review=template_reflow_text_review,
            evidence={
                **page_evidence,
                "replacement_characters": candidate_metrics.replacement_character_count,
                "suspicious_character_ratio": candidate_metrics.suspicious_character_ratio,
                "mojibake_hits": candidate.mojibake_hits,
                "geometry_policy": geometry_policy,
            },
        ))

    if (
        character_ratio is not None
        and source_metrics.text_character_count >= 40
        and character_ratio < 0.25
        and (text_similarity or 0.0) < 0.30
        and not candidate_is_blank
    ):
        findings.append(VisualFinding(
            code="PAGE_TEXT_LOSS_OR_REFLOW",
            severity=VisualSeverity.WARNING,
            message="This page has substantially less matching extracted text than its source page.",
            source_page=source_page,
            candidate_page=candidate_page,
            needs_model_review=True,
            evidence={
                **page_evidence,
                "text_character_ratio": _rounded(character_ratio),
                "extracted_text_similarity": text_similarity,
            },
        ))

    if (
        not pixel_identical
        and (pixel_difference >= 0.30 or occupancy_difference >= 0.45)
    ):
        findings.append(VisualFinding(
            code="LARGE_LAYOUT_DIFFERENCE",
            severity=VisualSeverity.WARNING,
            message="Low-resolution page layout differs substantially and needs visual review.",
            source_page=source_page,
            candidate_page=candidate_page,
            needs_model_review=True,
            evidence={
                **page_evidence,
                "pixel_difference": pixel_difference,
                "layout_occupancy_difference": occupancy_difference,
            },
        ))

    if (
        candidate_metrics.ink_ratio > 0.75
        and source_metrics.ink_ratio < 0.50
    ):
        findings.append(VisualFinding(
            code="ABNORMAL_INK_COVERAGE",
            severity=VisualSeverity.ERROR,
            message="Candidate page has abnormal near-solid ink coverage.",
            source_page=source_page,
            candidate_page=candidate_page,
            evidence={
                **page_evidence,
                "candidate_ink_ratio": candidate_metrics.ink_ratio,
            },
        ))

    return VisualPageReport(
        source_page=source_page,
        candidate_page=candidate_page,
        source=source_metrics,
        candidate=candidate_metrics,
        difference=difference,
        findings=tuple(findings),
    )


def _worst_severity(findings: Iterable[VisualFinding]) -> VisualSeverity:
    result = VisualSeverity.INFO
    for finding in findings:
        if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[result]:
            result = finding.severity
    return result


def _all_findings(
    global_findings: Iterable[VisualFinding],
    pages: Iterable[VisualPageReport],
) -> tuple[VisualFinding, ...]:
    return tuple(global_findings) + tuple(
        finding for page in pages for finding in page.findings
    )


def visual_evidence_sha256(
    report: VisualQualityReport | Mapping[str, object],
) -> str:
    """Recompute the canonical evidence digest from an object or loaded JSON."""

    payload = report.to_dict() if isinstance(report, VisualQualityReport) else dict(report)
    payload["evidence_sha256"] = ""
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(encoded)


def verify_visual_evidence_hash(
    report: VisualQualityReport | Mapping[str, object],
) -> bool:
    recorded = (
        report.evidence_sha256
        if isinstance(report, VisualQualityReport)
        else str(report.get("evidence_sha256") or "")
    )
    return len(recorded) == 64 and recorded == visual_evidence_sha256(report)


def frozen_page_alignment_from_report(
    report: Mapping[str, object],
    *,
    source_page_count: int,
    candidate_page_count: int,
    page_range: object,
    candidate_scope: str,
    source_pdf_sha256: str,
    candidate_pdf_sha256: str,
) -> VisualPageAlignment:
    """Validate and load the exact host-frozen alignment consumed by AI audit.

    This parser deliberately does not repair or regenerate a malformed mapping.
    A deterministic report and its rendered PDF bytes form one immutable audit
    input; any mismatch fails before a vision-model call.
    """

    if not isinstance(report, Mapping) or not verify_visual_evidence_hash(report):
        raise ValueError("deterministic visual evidence hash is invalid")
    if (
        str(report.get("source_pdf_sha256") or "") != source_pdf_sha256
        or str(report.get("candidate_pdf_sha256") or "") != candidate_pdf_sha256
    ):
        raise ValueError("deterministic visual evidence is bound to different PDFs")
    if (
        report.get("source_page_count") != source_page_count
        or report.get("candidate_page_count") != candidate_page_count
    ):
        raise ValueError("deterministic visual evidence page counts changed")
    normalized_scope = str(candidate_scope or "").strip().lower()
    selected = _normalize_page_range(page_range, source_page_count)
    raw_alignment = report.get("page_alignment")
    if not isinstance(raw_alignment, Mapping):
        raise ValueError("deterministic visual evidence lacks a frozen page alignment")
    raw_selected = raw_alignment.get("selected_source_pages")
    if raw_selected != list(selected) or report.get("selected_source_pages") != list(selected):
        raise ValueError("frozen page alignment source scope changed")
    if raw_alignment.get("candidate_scope") != normalized_scope:
        raise ValueError("frozen page alignment candidate scope changed")
    if (
        raw_alignment.get("source_page_count") != source_page_count
        or raw_alignment.get("candidate_page_count") != candidate_page_count
    ):
        raise ValueError("frozen page alignment page counts changed")

    raw_mappings = raw_alignment.get("mappings")
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise ValueError("frozen page alignment has no mappings")
    mappings: list[VisualPageMapping] = []
    for raw_mapping in raw_mappings:
        if not isinstance(raw_mapping, Mapping) or set(raw_mapping) != {
            "source_page", "candidate_page",
        }:
            raise ValueError("frozen page mapping structure is invalid")
        source_page = raw_mapping.get("source_page")
        candidate_page = raw_mapping.get("candidate_page")
        if (
            isinstance(source_page, bool)
            or not isinstance(source_page, int)
            or source_page not in selected
            or isinstance(candidate_page, bool)
            or (
                candidate_page is not None
                and (
                    not isinstance(candidate_page, int)
                    or not 1 <= candidate_page <= candidate_page_count
                )
            )
        ):
            raise ValueError("frozen page mapping contains an out-of-scope page")
        mappings.append(VisualPageMapping(source_page, candidate_page))

    non_null = [item for item in mappings if item.candidate_page is not None]
    if any(
        left.source_page > right.source_page
        or int(left.candidate_page) > int(right.candidate_page)
        for left, right in zip(non_null, non_null[1:])
    ):
        raise ValueError("frozen page alignment is not monotonic")
    if {item.source_page for item in mappings} != set(selected):
        raise ValueError("frozen page alignment does not cover every source page")
    if normalized_scope == CANDIDATE_SCOPE_REFLOW:
        if len(non_null) != len(mappings) or {
            int(item.candidate_page) for item in non_null
        } != set(range(1, candidate_page_count + 1)):
            raise ValueError("frozen reflow alignment does not cover every candidate page")
        if len(mappings) != max(len(selected), candidate_page_count):
            raise ValueError("frozen reflow alignment is not minimum-size")

    policy = str(raw_alignment.get("policy") or "")
    strategy = str(raw_alignment.get("strategy") or "")
    expected = raw_alignment.get("expected_candidate_page_count")
    requires_review = raw_alignment.get("requires_model_review")
    if (
        not policy
        or not strategy
        or isinstance(expected, bool)
        or not isinstance(expected, int)
        or not isinstance(requires_review, bool)
        or report.get("alignment_policy") != policy
    ):
        raise ValueError("frozen page alignment metadata is invalid")
    if normalized_scope == CANDIDATE_SCOPE_REFLOW and expected != candidate_page_count:
        raise ValueError("frozen reflow candidate scope is invalid")
    alignment = _finish_alignment(
        policy=policy,
        expected_candidate_page_count=expected,
        selected_source_pages=selected,
        mappings=mappings,
        candidate_scope=normalized_scope,
        source_page_count=source_page_count,
        candidate_page_count=candidate_page_count,
        strategy=strategy,
        requires_model_review=requires_review,
    )
    if raw_alignment.get("mapping_sha256") != alignment.mapping_sha256:
        raise ValueError("frozen page alignment digest is invalid")
    frozen_pairs = [
        (item.source_page, item.candidate_page) for item in alignment.mappings
    ]
    report_pairs = [
        (page.get("source_page"), page.get("candidate_page"))
        for page in report.get("pages") or []
        if isinstance(page, Mapping)
    ]
    if report_pairs != frozen_pairs:
        raise ValueError("deterministic page evidence and frozen alignment disagree")
    if report.get("compared_page_count") != len(non_null):
        raise ValueError("deterministic compared-page count and alignment disagree")
    return alignment


def _finish_report(report: VisualQualityReport) -> VisualQualityReport:
    return replace(report, evidence_sha256=visual_evidence_sha256(report))


def _unavailable_report(
    *,
    source: bytes,
    candidate: bytes,
    preview_status: str,
    renderer: str,
    renderer_version: str,
    code: str,
    message: str,
    source_page_count: int = 0,
    candidate_page_count: int = 0,
    selected_source_pages: tuple[int, ...] = (),
) -> VisualQualityReport:
    finding = VisualFinding(
        code=code,
        severity=VisualSeverity.CRITICAL,
        message=message,
        needs_model_review=True,
    )
    return _finish_report(VisualQualityReport(
        status=VisualQualityStatus.UNAVAILABLE,
        severity=VisualSeverity.CRITICAL,
        needs_model_review=True,
        preview_status=preview_status,
        partial_compiled=preview_status == PARTIAL_COMPILED,
        renderer=renderer,
        renderer_version=renderer_version,
        source_pdf_sha256=_sha256(source),
        candidate_pdf_sha256=_sha256(candidate),
        source_pdf_byte_count=len(source),
        candidate_pdf_byte_count=len(candidate),
        source_page_count=source_page_count,
        candidate_page_count=candidate_page_count,
        selected_source_pages=selected_source_pages,
        alignment_policy="unavailable",
        compared_page_count=0,
        source_reuse_detected=False,
        visual_preflight_passed=False,
        aggregate_metrics={},
        pages=(),
        findings=(finding,),
    ))


def _open_document(module, data: bytes):
    return module.open(stream=data, filetype="pdf")


def _document_is_locked(document) -> bool:
    return bool(getattr(document, "needs_pass", False))


def evaluate_visual_quality(
    source_pdf_bytes: bytes,
    candidate_pdf_bytes: bytes,
    page_range: object = None,
    *,
    preview_status: str = COMPILED,
    render_dpi: int = DEFAULT_RENDER_DPI,
    source_geometry_authoritative: bool = True,
    geometry_policy: str | None = None,
    candidate_scope: str = CANDIDATE_SCOPE_AUTO,
) -> VisualQualityReport:
    """Render and compare source/candidate PDF bytes without asserting semantics.

    ``page_range`` is one-based and accepts ``None``/``"all"``, ``"2-5"``,
    ``(2, 5)``, a sequence of page numbers, or a mapping with ``start``/``end``
    or ``pages``.  A partial compiled PDF is still inspected, but it can never
    receive ``PASS`` merely because its available pages render.
    """

    source = _coerce_bytes(source_pdf_bytes)
    candidate = _coerce_bytes(candidate_pdf_bytes)
    normalized_preview_status = str(preview_status or "").strip().upper()
    if not isinstance(source_geometry_authoritative, bool):
        return _unavailable_report(
            source=source,
            candidate=candidate,
            preview_status=normalized_preview_status,
            renderer="none",
            renderer_version="unavailable",
            code="INVALID_SOURCE_GEOMETRY_AUTHORITY",
            message="Source geometry authority must be an explicit boolean.",
        )
    if geometry_policy is None:
        normalized_geometry_policy = (
            GEOMETRY_POLICY_STRICT_SOURCE
            if source_geometry_authoritative
            else GEOMETRY_POLICY_DERIVED_IMAGE
        )
    else:
        normalized_geometry_policy = str(geometry_policy or "").strip().lower()
        if normalized_geometry_policy not in _GEOMETRY_POLICIES:
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer="none",
                renderer_version="unavailable",
                code="INVALID_GEOMETRY_POLICY",
                message="Geometry policy must be strict_source, derived_image, or template_reflow.",
            )
    source_geometry_authoritative = (
        normalized_geometry_policy == GEOMETRY_POLICY_STRICT_SOURCE
    )
    if normalized_preview_status not in _PDF_STATUSES:
        return _unavailable_report(
            source=source,
            candidate=candidate,
            preview_status=normalized_preview_status,
            renderer="none",
            renderer_version="unavailable",
            code="NOT_A_COMPILED_PREVIEW",
            message="Visual quality requires COMPILED or PARTIAL_COMPILED PDF bytes.",
        )
    if not isinstance(render_dpi, int) or isinstance(render_dpi, bool) or not 12 <= render_dpi <= 96:
        return _unavailable_report(
            source=source,
            candidate=candidate,
            preview_status=normalized_preview_status,
            renderer="none",
            renderer_version="unavailable",
            code="INVALID_RENDER_DPI",
            message="Render DPI must be an integer between 12 and 96.",
        )

    module = _load_pymupdf()
    if module is None:
        return _unavailable_report(
            source=source,
            candidate=candidate,
            preview_status=normalized_preview_status,
            renderer="none",
            renderer_version="unavailable",
            code="RENDERER_UNAVAILABLE",
            message="No supported in-memory PDF renderer is available.",
        )
    renderer, renderer_version = _renderer_identity(module)

    source_document = None
    candidate_document = None
    try:
        try:
            source_document = _open_document(module, source)
        except Exception:  # noqa: BLE001 - untrusted PDF parser boundary
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer=renderer,
                renderer_version=renderer_version,
                code="SOURCE_PDF_OPEN_FAILED",
                message="The source PDF bytes could not be opened by the renderer.",
            )
        try:
            candidate_document = _open_document(module, candidate)
        except Exception:  # noqa: BLE001 - untrusted PDF parser boundary
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer=renderer,
                renderer_version=renderer_version,
                code="CANDIDATE_PDF_OPEN_FAILED",
                message="The candidate PDF bytes could not be opened by the renderer.",
                source_page_count=int(getattr(source_document, "page_count", 0) or 0),
            )

        source_page_count = int(getattr(source_document, "page_count", 0) or 0)
        candidate_page_count = int(getattr(candidate_document, "page_count", 0) or 0)
        if _document_is_locked(source_document) or _document_is_locked(candidate_document):
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer=renderer,
                renderer_version=renderer_version,
                code="ENCRYPTED_PDF_UNAVAILABLE",
                message="An encrypted PDF cannot be inspected without credentials.",
                source_page_count=source_page_count,
                candidate_page_count=candidate_page_count,
            )
        if source_page_count <= 0 or candidate_page_count <= 0:
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer=renderer,
                renderer_version=renderer_version,
                code="EMPTY_PDF_UNAVAILABLE",
                message="Both PDFs must contain at least one renderable page.",
                source_page_count=source_page_count,
                candidate_page_count=candidate_page_count,
            )
        try:
            normalized_candidate_scope = str(candidate_scope or "").strip().lower()
            alignment_source_texts = None
            alignment_candidate_texts = None
            if normalized_candidate_scope == CANDIDATE_SCOPE_REFLOW:
                reflow_source_pages = _normalize_page_range(
                    page_range,
                    source_page_count,
                )
                alignment_source_texts = {
                    page: _extract_page_alignment_text(
                        source_document.load_page(page - 1)
                    )
                    for page in reflow_source_pages
                }
                alignment_candidate_texts = {
                    page: _extract_page_alignment_text(
                        candidate_document.load_page(page - 1)
                    )
                    for page in range(1, candidate_page_count + 1)
                }
            alignment = build_page_alignment(
                source_page_count,
                candidate_page_count,
                page_range,
                candidate_scope=candidate_scope,
                source_page_texts=alignment_source_texts,
                candidate_page_texts=alignment_candidate_texts,
            )
        except (TypeError, ValueError, OverflowError):
            return _unavailable_report(
                source=source,
                candidate=candidate,
                preview_status=normalized_preview_status,
                renderer=renderer,
                renderer_version=renderer_version,
                code="INVALID_PAGE_RANGE",
                message="The requested page range is invalid for the source PDF.",
                source_page_count=source_page_count,
                candidate_page_count=candidate_page_count,
            )

        selected_source_pages = alignment.selected_source_pages
        alignment_policy = alignment.policy
        expected_candidate_pages = alignment.expected_candidate_page_count

        global_findings: list[VisualFinding] = []
        if source == candidate:
            global_findings.append(VisualFinding(
                code="IDENTICAL_PDF_BYTES",
                severity=VisualSeverity.CRITICAL,
                message="Candidate bytes are identical to the source and do not prove reconstruction.",
            ))
        if normalized_preview_status == PARTIAL_COMPILED:
            global_findings.append(VisualFinding(
                code="PARTIAL_COMPILED_INPUT",
                severity=VisualSeverity.WARNING,
                message="Only a partial compiler artifact is available; completed-page evidence is retained.",
                needs_model_review=True,
            ))

        strict_page_count = alignment.candidate_scope != CANDIDATE_SCOPE_REFLOW
        if strict_page_count and candidate_page_count < expected_candidate_pages:
            global_findings.append(VisualFinding(
                code="PAGE_COUNT_MISMATCH",
                severity=VisualSeverity.ERROR,
                message="Candidate PDF contains fewer pages than the selected source scope.",
                evidence={
                    "expected_pages": expected_candidate_pages,
                    "candidate_pages": candidate_page_count,
                },
            ))
        elif strict_page_count and candidate_page_count > expected_candidate_pages:
            global_findings.append(VisualFinding(
                code="EXTRA_CANDIDATE_PAGES",
                severity=VisualSeverity.ERROR,
                message="Candidate PDF contains additional pages outside the expected scope.",
                evidence={
                    "expected_pages": expected_candidate_pages,
                    "candidate_pages": candidate_page_count,
                },
            ))
        if alignment.requires_model_review:
            global_findings.append(VisualFinding(
                code="REFLOW_ALIGNMENT_PROPORTIONAL_FALLBACK",
                severity=VisualSeverity.WARNING,
                message=(
                    "Reflow page alignment used the host proportional fallback because "
                    "a usable PDF text layer was unavailable; every candidate page must "
                    "be closed by visual review."
                ),
                needs_model_review=True,
                evidence={
                    "strategy": alignment.strategy,
                    "mapping_sha256": alignment.mapping_sha256,
                },
            ))

        rendered_source: dict[int, _RenderedPage] = {}
        rendered_candidate: dict[int, _RenderedPage] = {}
        page_reports: list[VisualPageReport] = []
        render_failed = False
        for mapping in alignment.mappings:
            source_page = mapping.source_page
            candidate_page = mapping.candidate_page
            try:
                source_render = rendered_source.setdefault(
                    source_page,
                    _render_page(
                        module,
                        source_document.load_page(source_page - 1),
                        source_page,
                        render_dpi,
                    ),
                )
            except Exception:  # noqa: BLE001 - untrusted renderer boundary
                render_failed = True
                page_reports.append(VisualPageReport(
                    source_page=source_page,
                    candidate_page=candidate_page,
                    source=None,
                    candidate=None,
                    difference=None,
                    findings=(VisualFinding(
                        code="SOURCE_PAGE_RENDER_FAILED",
                        severity=VisualSeverity.CRITICAL,
                        message="A selected source page could not be rendered.",
                        source_page=source_page,
                        candidate_page=candidate_page,
                        needs_model_review=True,
                    ),),
                ))
                continue
            if candidate_page is None:
                page_reports.append(VisualPageReport(
                    source_page=source_page,
                    candidate_page=None,
                    source=source_render.metrics,
                    candidate=None,
                    difference=None,
                    findings=(VisualFinding(
                        code="MISSING_CANDIDATE_PAGE",
                        severity=VisualSeverity.CRITICAL,
                        message="No candidate page exists for this selected source page.",
                        source_page=source_page,
                    ),),
                ))
                continue
            try:
                candidate_render = rendered_candidate.setdefault(
                    candidate_page,
                    _render_page(
                        module,
                        candidate_document.load_page(candidate_page - 1),
                        candidate_page,
                        render_dpi,
                    ),
                )
            except Exception:  # noqa: BLE001 - untrusted renderer boundary
                render_failed = True
                page_reports.append(VisualPageReport(
                    source_page=source_page,
                    candidate_page=candidate_page,
                    source=source_render.metrics,
                    candidate=None,
                    difference=None,
                    findings=(VisualFinding(
                        code="CANDIDATE_PAGE_RENDER_FAILED",
                        severity=VisualSeverity.CRITICAL,
                        message="A candidate page could not be rendered.",
                        source_page=source_page,
                        candidate_page=candidate_page,
                        needs_model_review=True,
                    ),),
                ))
                continue
            page_reports.append(_page_comparison(
                source_page,
                candidate_page,
                source_render,
                candidate_render,
                geometry_policy=normalized_geometry_policy,
            ))

        compared = [
            page for page in page_reports
            if page.source is not None
            and page.candidate is not None
            and page.difference is not None
        ]
        source_text = "\n".join(
            rendered_source[page].text
            for page in selected_source_pages
            if page in rendered_source
        )
        candidate_text = "\n".join(
            rendered_candidate[page].text
            for page in sorted(rendered_candidate)
        )
        aggregate_text_similarity = _text_similarity(source_text, candidate_text)
        text_character_ratio = (
            len(candidate_text) / len(source_text) if source_text else None
        )
        aggregate_metrics: dict[str, object] = {
            "render_dpi": render_dpi,
            "source_geometry_authoritative": source_geometry_authoritative,
            "geometry_policy": normalized_geometry_policy,
            "candidate_scope": alignment.candidate_scope,
            "expected_candidate_page_count": expected_candidate_pages,
            "alignment_strategy": alignment.strategy,
            "alignment_mapping_sha256": alignment.mapping_sha256,
            "alignment_requires_model_review": alignment.requires_model_review,
            "grid_width": _GRID_WIDTH,
            "grid_height": _GRID_HEIGHT,
            "source_selected_text_characters": len(source_text),
            "candidate_compared_text_characters": len(candidate_text),
            "text_character_ratio": (
                _rounded(text_character_ratio)
                if text_character_ratio is not None else None
            ),
            "extracted_text_similarity": aggregate_text_similarity,
            "source_selected_render_sha256": _sha256(
                "\n".join(
                    rendered_source[page].metrics.render_sha256
                    for page in selected_source_pages
                    if page in rendered_source
                ).encode("ascii")
            ),
            "candidate_compared_render_sha256": _sha256(
                "\n".join(
                    rendered_candidate[page].metrics.render_sha256
                    for page in sorted(rendered_candidate)
                ).encode("ascii")
            ),
        }

        if len(source_text) >= 80 and text_character_ratio is not None:
            if (
                text_character_ratio < 0.50
                or (
                    aggregate_text_similarity is not None
                    and aggregate_text_similarity < 0.35
                    and text_character_ratio < 0.80
                )
            ):
                global_findings.append(VisualFinding(
                    code="SUBSTANTIAL_TEXT_LOSS",
                    severity=VisualSeverity.ERROR,
                    message="Aggregate extracted text indicates substantial candidate content loss.",
                    evidence={
                        "text_character_ratio": _rounded(text_character_ratio),
                        "extracted_text_similarity": aggregate_text_similarity,
                    },
                ))
            elif (
                aggregate_text_similarity is not None
                and aggregate_text_similarity < 0.70
            ):
                global_findings.append(VisualFinding(
                    code="TEXT_DIFFERENCE_REQUIRES_REVIEW",
                    severity=VisualSeverity.WARNING,
                    message="Aggregate extracted text differs enough to require model review.",
                    needs_model_review=True,
                    evidence={
                        "text_character_ratio": _rounded(text_character_ratio),
                        "extracted_text_similarity": aggregate_text_similarity,
                    },
                ))
        elif not source_text:
            global_findings.append(VisualFinding(
                code="SOURCE_TEXT_LAYER_UNAVAILABLE",
                severity=VisualSeverity.WARNING,
                message="Source pages have no extractable text layer; pixel evidence needs model review.",
                needs_model_review=True,
            ))

        source_render_hashes = {
            item.metrics.render_sha256 for item in rendered_source.values()
        }
        candidate_render_hashes = [
            item.metrics.render_sha256 for item in rendered_candidate.values()
        ]
        render_overlap = (
            sum(value in source_render_hashes for value in candidate_render_hashes)
            / len(candidate_render_hashes)
            if candidate_render_hashes else 0.0
        )
        aggregate_metrics["source_render_overlap_ratio"] = _rounded(render_overlap)
        source_reuse_detected = source == candidate or (
            bool(candidate_render_hashes)
            and render_overlap == 1.0
            and candidate_page_count <= len(selected_source_pages)
        )
        if source_reuse_detected and source != candidate:
            global_findings.append(VisualFinding(
                code="SOURCE_PAGE_REUSE_DETECTED",
                severity=VisualSeverity.CRITICAL,
                message="Every candidate render matches a selected source page; this may be a source-page slice.",
                evidence={"source_render_overlap_ratio": 1.0},
            ))
        elif render_overlap >= 0.80:
            global_findings.append(VisualFinding(
                code="HIGH_SOURCE_RENDER_OVERLAP",
                severity=VisualSeverity.ERROR,
                message="Most candidate pages are pixel-identical to source renders; reconstruction provenance is not trustworthy.",
                evidence={"source_render_overlap_ratio": _rounded(render_overlap)},
            ))

        all_findings = _all_findings(global_findings, page_reports)
        severity = _worst_severity(all_findings)
        if render_failed:
            status = VisualQualityStatus.UNAVAILABLE
        elif severity in {VisualSeverity.ERROR, VisualSeverity.CRITICAL}:
            status = VisualQualityStatus.FAIL
        elif severity is VisualSeverity.WARNING:
            status = VisualQualityStatus.REVIEW
        else:
            status = VisualQualityStatus.PASS
        needs_model_review = (
            status is VisualQualityStatus.UNAVAILABLE
            or any(item.needs_model_review for item in all_findings)
        )
        report = VisualQualityReport(
            status=status,
            severity=severity,
            needs_model_review=needs_model_review,
            preview_status=normalized_preview_status,
            partial_compiled=normalized_preview_status == PARTIAL_COMPILED,
            renderer=renderer,
            renderer_version=renderer_version,
            source_pdf_sha256=_sha256(source),
            candidate_pdf_sha256=_sha256(candidate),
            source_pdf_byte_count=len(source),
            candidate_pdf_byte_count=len(candidate),
            source_page_count=source_page_count,
            candidate_page_count=candidate_page_count,
            selected_source_pages=selected_source_pages,
            alignment_policy=alignment_policy,
            compared_page_count=len(compared),
            source_reuse_detected=source_reuse_detected,
            visual_preflight_passed=status is VisualQualityStatus.PASS,
            aggregate_metrics=aggregate_metrics,
            pages=tuple(page_reports),
            findings=tuple(global_findings),
            page_alignment=alignment,
        )
        return _finish_report(report)
    finally:
        for document in (candidate_document, source_document):
            if document is not None:
                try:
                    document.close()
                except Exception:  # noqa: BLE001 - close must not mask evidence
                    pass


def assess_visual_quality(
    source_pdf_bytes: bytes,
    generated_pdf_bytes: bytes,
    page_range: object = None,
    *,
    preview_status: str = COMPILED,
    render_dpi: int = DEFAULT_RENDER_DPI,
    source_geometry_authoritative: bool = True,
    geometry_policy: str | None = None,
    candidate_scope: str = CANDIDATE_SCOPE_AUTO,
) -> VisualQualityReport:
    """Keyword-friendly wrapper using the host's ``generated_pdf`` vocabulary."""

    return evaluate_visual_quality(
        source_pdf_bytes,
        generated_pdf_bytes,
        page_range,
        preview_status=preview_status,
        render_dpi=render_dpi,
        source_geometry_authoritative=source_geometry_authoritative,
        geometry_policy=geometry_policy,
        candidate_scope=candidate_scope,
    )


__all__ = [
    "CANDIDATE_SCOPE_AUTO",
    "CANDIDATE_SCOPE_FULL_SOURCE",
    "CANDIDATE_SCOPE_REFLOW",
    "CANDIDATE_SCOPE_SELECTED_RANGE",
    "GEOMETRY_POLICY_DERIVED_IMAGE",
    "GEOMETRY_POLICY_STRICT_SOURCE",
    "GEOMETRY_POLICY_TEMPLATE_REFLOW",
    "PageDifferenceMetrics",
    "PageVisualMetrics",
    "VisualFinding",
    "VisualPageAlignment",
    "VisualPageMapping",
    "VisualPageReport",
    "VisualQualityReport",
    "VisualQualityStatus",
    "VisualSeverity",
    "assess_visual_quality",
    "build_page_alignment",
    "evaluate_visual_quality",
    "frozen_page_alignment_from_report",
    "verify_visual_evidence_hash",
    "visual_evidence_sha256",
]
