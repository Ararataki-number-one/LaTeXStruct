"""Deterministic, model-agnostic evidence preparation for formula OCR.

This module deliberately stops before inference.  It locates likely complex
display mathematics in born-digital PDFs, renders bounded crops directly from
the source PDF at high DPI, builds strict batch contracts, and stores only
validated result metadata in a content-addressed cache.  Callers remain in
control of the visual model, retries, usage accounting, and page assembly.

The detector uses only PDF font and geometry evidence.  A scanned page without
a useful text/font layer therefore yields no candidates instead of guessing.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import struct
import time
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FORMULA_DETECTOR_VERSION = "font-geometry-display-formulas-v1"
FORMULA_CROP_VERSION = "direct-pdf-formula-crop-v1"
FORMULA_RESULT_SCHEMA_VERSION = "formula-ocr-result-v1"
FORMULA_CACHE_SCHEMA_VERSION = "formula-ocr-cache-v1"
DEFAULT_FORMULA_DPI = 420

_MATH_FONT_RE = re.compile(
    r"(?:cmmi|cmsy|cmex|msam|msbm|math|symbol|stix|euler|rsfs|wasy)", re.I
)
_CONTROL_GLYPH_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_MATH_OPERATOR_RE = re.compile(
    r"[=<>\u2260\u2264\u2265\u2208\u2209\u2211\u220f\u222b\u221a"
    r"\u2192\u21d2\u2229\u222a\u2282-\u2287+\u2212*/^_|{}()[\]]"
)
_CONNECTOR_RE = re.compile(
    r"^(?:\s*|[0-9\s.,:;!?+\-=<>/|*^_{}()[\]\u2212\u2260\u2264\u2265]+|"
    r"(?:log|ln|exp|max|min|sup|inf|lim|sin|cos|tan|det|dim|ker|rank|Pr|P|E|V))$"
)
_FORBIDDEN_TEX_RE = re.compile(
    r"\\(?:documentclass|usepackage|RequirePackage|input|include|includegraphics|"
    r"includepdf|write\d*|immediate|openin\d*|openout\d*|closein\d*|closeout\d*|"
    r"read\d*|readline|"
    r"newread|newwrite|special|directlua|luadirect|ShellEscape|pdf[a-zA-Z]*|"
    r"href|url|csname|endcsname|expandafter|newcommand|renewcommand|providecommand|"
    r"DeclareRobustCommand|def|edef|gdef|xdef|catcode|makeatletter|makeatother|"
    r"ExplSyntaxOn|ExplSyntaxOff|endinput|jobname)\b",
    re.I,
)
_BEGIN_END_RE = re.compile(r"\\(begin|end)\{([A-Za-z*]+)\}")
_SAFE_MATH_ENVIRONMENTS = frozenset(
    {
        "aligned",
        "alignedat",
        "array",
        "bmatrix",
        "Bmatrix",
        "cases",
        "gathered",
        "matrix",
        "pmatrix",
        "smallmatrix",
        "split",
        "subarray",
        "vmatrix",
        "Vmatrix",
    }
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CACHE_KEY_RE = re.compile(r"[0-9a-f]{64}")
_REGION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


class FormulaEvidenceError(ValueError):
    """Formula evidence or cached model output failed a closed validation."""


@dataclasses.dataclass(frozen=True)
class FormulaDetectionConfig:
    """Conservative detector bounds for complex display mathematics."""

    max_regions_per_page: int = 4
    min_score: float = 3.0
    top_margin_points: float = 38.0
    bottom_margin_points: float = 24.0
    max_width_ratio: float = 0.90
    max_height_ratio: float = 0.30

    def validate(self) -> "FormulaDetectionConfig":
        if not 0 <= self.max_regions_per_page <= 64:
            raise FormulaEvidenceError("max_regions_per_page must be between 0 and 64")
        if not math.isfinite(float(self.min_score)) or self.min_score < 0:
            raise FormulaEvidenceError("min_score must be a finite non-negative number")
        if not 0 <= self.top_margin_points <= 300:
            raise FormulaEvidenceError("top_margin_points is outside the safe range")
        if not 0 <= self.bottom_margin_points <= 300:
            raise FormulaEvidenceError("bottom_margin_points is outside the safe range")
        if not 0.1 <= self.max_width_ratio <= 0.92:
            raise FormulaEvidenceError("max_width_ratio must be between 0.1 and 0.92")
        if not 0.02 <= self.max_height_ratio <= 0.50:
            raise FormulaEvidenceError("max_height_ratio must be between 0.02 and 0.50")
        return self


@dataclasses.dataclass(frozen=True)
class FormulaRegion:
    region_id: str
    page: int
    bbox_points: tuple[float, float, float, float]
    score: float
    text_hint: str = ""
    fonts: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    detector_version: str = FORMULA_DETECTOR_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.region_id,
            "page": self.page,
            "bbox_points": [round(value, 3) for value in self.bbox_points],
            "kind": "display",
            "score": round(float(self.score), 3),
            "text_hint": self.text_hint,
            "fonts": list(self.fonts),
            "evidence": list(self.evidence),
            "detector_version": self.detector_version,
        }


@dataclasses.dataclass(frozen=True)
class FormulaEvidence:
    region: FormulaRegion
    crop_path: Path
    crop_bbox_points: tuple[float, float, float, float]
    image_sha256: str
    image_size_pixels: tuple[int, int]
    dpi: int

    def to_dict(self, *, include_local_path: bool = True) -> dict[str, Any]:
        value = {
            "region": self.region.to_dict(),
            "crop_bbox_points": [round(item, 3) for item in self.crop_bbox_points],
            "image_sha256": self.image_sha256,
            "image_size_pixels": list(self.image_size_pixels),
            "dpi": self.dpi,
        }
        if include_local_path:
            value["crop_path"] = str(self.crop_path)
        return value


@dataclasses.dataclass(frozen=True)
class PreparedFormulaEvidence:
    source_sha256: str
    regions: tuple[FormulaRegion, ...]
    evidence: tuple[FormulaEvidence, ...]

    def by_page(self) -> dict[int, list[FormulaEvidence]]:
        output: dict[int, list[FormulaEvidence]] = {}
        for item in self.evidence:
            output.setdefault(item.region.page, []).append(item)
        return output


@dataclasses.dataclass(frozen=True)
class FormulaCacheIdentity:
    """Model/prompt identity required for a reusable per-region result."""

    backend: str
    model: str
    reasoning_effort: str
    prompt_version: str
    prompt_sha256: str
    schema_version: str = FORMULA_RESULT_SCHEMA_VERSION
    schema_sha256: str = ""

    def to_dict(self) -> dict[str, str]:
        prompt_hash = _validated_sha256(self.prompt_sha256, "prompt_sha256")
        schema_hash = _validated_sha256(self.schema_sha256, "schema_sha256")
        backend = _bounded_identity(self.backend, "backend", 80)
        model = _bounded_identity(self.model or "backend-default", "model", 160)
        effort = _bounded_identity(self.reasoning_effort, "reasoning_effort", 40)
        prompt_version = _bounded_identity(self.prompt_version, "prompt_version", 120)
        schema_version = _bounded_identity(self.schema_version, "schema_version", 120)
        return {
            "backend": backend,
            "model": model,
            "reasoning_effort": effort,
            "prompt_version": prompt_version,
            "prompt_sha256": prompt_hash,
            "schema_version": schema_version,
            "schema_sha256": schema_hash,
        }


@dataclasses.dataclass
class _Candidate:
    bbox: tuple[float, float, float, float]
    text: str
    fonts: set[str]
    score: float
    evidence: set[str]
    baselines: set[float]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_identity(value: str, name: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ord(char) < 32 for char in text):
        raise FormulaEvidenceError(f"{name} is empty or invalid")
    return text


def _validated_sha256(value: str, name: str) -> str:
    text = str(value or "").lower()
    if _SHA256_RE.fullmatch(text) is None:
        raise FormulaEvidenceError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _validated_region_id(value: str) -> str:
    text = str(value or "")
    if _REGION_ID_RE.fullmatch(text) is None:
        raise FormulaEvidenceError("formula region id is invalid")
    return text


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    data = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _finite_bbox(value: Iterable[Any]) -> tuple[float, float, float, float] | None:
    try:
        values = tuple(float(item) for item in value)
    except (TypeError, ValueError):
        return None
    if len(values) != 4 or not all(math.isfinite(item) for item in values):
        return None
    x0, y0, x1, y1 = values
    if x1 <= x0 or y1 <= y0:
        return None
    return x0, y0, x1, y1


def _bbox_union(
    values: Iterable[tuple[float, float, float, float]],
) -> tuple[float, float, float, float]:
    boxes = tuple(values)
    return (
        min(item[0] for item in boxes),
        min(item[1] for item in boxes),
        max(item[2] for item in boxes),
        max(item[3] for item in boxes),
    )


def _bbox_overlap_x(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
) -> float:
    overlap = max(0.0, min(left[2], right[2]) - max(left[0], right[0]))
    return overlap / max(1e-6, min(left[2] - left[0], right[2] - right[0]))


def _bbox_overlap_y(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
) -> float:
    overlap = max(0.0, min(left[3], right[3]) - max(left[1], right[1]))
    return overlap / max(1e-6, min(left[3] - left[1], right[3] - right[1]))


def _is_math_font(font: str) -> bool:
    return bool(_MATH_FONT_RE.search(str(font or "")))


def _sanitize_hint(value: str, limit: int = 240) -> str:
    cleaned = "".join(
        " " if (ord(char) < 32 and char not in "\t\n") else char
        for char in str(value or "")
    )
    return re.sub(r"\s+", " ", cleaned).strip()[:limit]


def _connector_span(span: Mapping[str, Any], base_size: float) -> bool:
    text = str(span.get("text") or "")
    try:
        size = float(span.get("size") or 0.0)
    except (TypeError, ValueError):
        return False
    return bool(
        _CONNECTOR_RE.fullmatch(text)
        and size <= max(base_size * 1.15, base_size + 1.5)
    )


def _candidate_from_spans(
    spans: Sequence[Mapping[str, Any]],
    indices: Sequence[int],
    *,
    display_like: bool,
    baseline: float,
) -> _Candidate | None:
    selected = [spans[index] for index in indices]
    boxes = [_finite_bbox(span.get("bbox") or ()) for span in selected]
    valid_boxes = [box for box in boxes if box is not None]
    if not valid_boxes:
        return None
    text = "".join(str(span.get("text") or "") for span in selected)
    math_spans = [
        span for span in selected if _is_math_font(str(span.get("font") or ""))
    ]
    math_chars = len(
        re.sub(
            r"\s+",
            "",
            "".join(str(item.get("text") or "") for item in math_spans),
        )
    )
    fonts = {str(span.get("font") or "") for span in selected if span.get("font")}
    sizes = {
        round(float(span.get("size") or 0.0), 2)
        for span in selected
        if isinstance(span.get("size"), (int, float))
    }
    evidence: set[str] = {"math-font"}
    score = 0.8 + min(12, math_chars) / 4.0
    if display_like:
        score += 2.0
        evidence.add("display-geometry")
    if any("cmex" in font.lower() for font in fonts):
        score += 2.5
        evidence.add("extensible-glyph")
    if len(sizes) > 1:
        score += 1.0
        evidence.add("script-size")
    operator_count = len(_MATH_OPERATOR_RE.findall(text))
    if operator_count:
        score += min(2.0, operator_count * 0.3)
        evidence.add("operator")
    if _CONTROL_GLYPH_RE.search(text):
        score += 1.5
        evidence.add("unmapped-control-glyph")
    compact = re.sub(r"\s+", "", text)
    if not (
        len(compact) >= 2
        or operator_count
        or "script-size" in evidence
        or "extensible-glyph" in evidence
    ):
        return None
    return _Candidate(
        bbox=_bbox_union(valid_boxes),
        text=_sanitize_hint(text),
        fonts=fonts,
        score=score,
        evidence=evidence,
        baselines={round(float(baseline), 2)},
    )


def _line_candidates(
    spans: Sequence[Mapping[str, Any]], page_width: float
) -> list[_Candidate]:
    visible = [span for span in spans if str(span.get("text") or "")]
    if not visible:
        return []
    math_indices = [
        index
        for index, span in enumerate(visible)
        if _is_math_font(str(span.get("font") or ""))
    ]
    if not math_indices:
        return []
    boxes = [_finite_bbox(span.get("bbox") or ()) for span in visible]
    valid_boxes = [box for box in boxes if box is not None]
    if not valid_boxes:
        return []
    line_bbox = _bbox_union(valid_boxes)
    all_text = "".join(str(item.get("text") or "") for item in visible)
    total_chars = max(1, len(re.sub(r"\s+", "", all_text)))
    math_text = "".join(str(visible[index].get("text") or "") for index in math_indices)
    math_chars = len(re.sub(r"\s+", "", math_text))
    center = (line_bbox[0] + line_bbox[2]) / 2.0
    display_like = bool(
        any(
            "cmex" in str(visible[index].get("font") or "").lower()
            for index in math_indices
        )
        or (
            math_chars / total_chars >= 0.34
            and line_bbox[2] - line_bbox[0] <= page_width * 0.82
            and abs(center - page_width / 2.0) <= page_width * 0.28
        )
    )
    base_size = max(float(visible[index].get("size") or 0.0) for index in math_indices)
    selected: set[int] = set(math_indices)
    for index in math_indices:
        for step in (-1, 1):
            cursor = index + step
            while 0 <= cursor < len(visible) and _connector_span(
                visible[cursor], base_size
            ):
                current_box = boxes[cursor]
                neighbor_box = boxes[cursor - step]
                if current_box is None or neighbor_box is None:
                    break
                horizontal_gap = (
                    current_box[0] - neighbor_box[2]
                    if step > 0
                    else neighbor_box[0] - current_box[2]
                )
                if horizontal_gap > max(5.0, base_size * 0.65):
                    break
                selected.add(cursor)
                cursor += step

    groups: list[list[int]] = []
    for index in sorted(selected):
        if not groups:
            groups.append([index])
            continue
        previous = groups[-1][-1]
        previous_box = boxes[previous]
        current_box = boxes[index]
        gap = (
            current_box[0] - previous_box[2]
            if current_box is not None and previous_box is not None
            else float("inf")
        )
        if index == previous + 1 and gap <= max(5.0, base_size * 0.7):
            groups[-1].append(index)
        else:
            groups.append([index])
    if display_like and len(groups) > 1:
        first = boxes[groups[0][0]]
        last = boxes[groups[-1][-1]]
        if first is not None and last is not None and last[2] - first[0] <= page_width * 0.84:
            groups = [[item for group in groups for item in group]]
    baseline = max(
        float(
            (
                span.get("origin")
                or (0.0, (_finite_bbox(span.get("bbox") or ()) or (0, 0, 0, 0))[3])
            )[1]
        )
        for span in visible
    )
    return [
        candidate
        for group in groups
        if (
            candidate := _candidate_from_spans(
                visible, group, display_like=display_like, baseline=baseline
            )
        )
        is not None
    ]


def _drawing_rules(drawings: Iterable[Any]) -> list[tuple[float, float, float, float]]:
    rules: list[tuple[float, float, float, float]] = []
    for drawing in drawings:
        raw = drawing.get("rect") if isinstance(drawing, Mapping) else drawing
        if hasattr(raw, "x0"):
            raw = (raw.x0, raw.y0, raw.x1, raw.y1)
        try:
            values = tuple(float(item) for item in (raw or ()))
        except (TypeError, ValueError):
            continue
        if len(values) != 4 or not all(math.isfinite(item) for item in values):
            continue
        x0, y0, x1, y1 = values
        if x1 <= x0 or y1 < y0:
            continue
        box = x0, y0, x1, y1
        width, height = x1 - x0, y1 - y0
        if 3.0 <= width <= 180.0 and height <= 2.2:
            rules.append(box)
    return rules


def _merge_candidates(
    candidates: list[_Candidate],
    rules: Sequence[tuple[float, float, float, float]],
) -> list[_Candidate]:
    for candidate in candidates:
        nearby = [
            rule
            for rule in rules
            if -10.0 <= rule[1] - candidate.bbox[3] <= 12.0
            and (
                _bbox_overlap_x(candidate.bbox, rule) >= 0.18
                or abs(
                    (candidate.bbox[0] + candidate.bbox[2])
                    - (rule[0] + rule[2])
                )
                <= 42.0
            )
        ]
        if nearby:
            candidate.bbox = _bbox_union([candidate.bbox, *nearby])
            candidate.score += 1.5
            candidate.evidence.add("nearby-horizontal-rule")

    changed = True
    while changed:
        changed = False
        candidates.sort(key=lambda item: (item.bbox[1], item.bbox[0]))
        for left_index, left in enumerate(candidates):
            for right_index in range(left_index + 1, len(candidates)):
                right = candidates[right_index]
                vertical_gap = max(0.0, right.bbox[1] - left.bbox[3])
                horizontal_gap = max(
                    0.0,
                    right.bbox[0] - left.bbox[2],
                    left.bbox[0] - right.bbox[2],
                )
                display_pair = bool(
                    "display-geometry" in left.evidence
                    or "display-geometry" in right.evidence
                    or "nearby-horizontal-rule" in left.evidence
                    or "nearby-horizontal-rule" in right.evidence
                )
                same_line = bool(
                    _bbox_overlap_y(left.bbox, right.bbox) >= 0.58
                    and (
                        horizontal_gap <= 5.0
                        or (display_pair and horizontal_gap <= 20.0)
                    )
                )
                separating_rule = any(
                    left.bbox[3] - 3.0 <= rule[1] <= right.bbox[1] + 3.0
                    and _bbox_overlap_x(left.bbox, rule) >= 0.18
                    and _bbox_overlap_x(right.bbox, rule) >= 0.18
                    for rule in rules
                )
                stacked = bool(
                    vertical_gap <= 15.0
                    and separating_rule
                    and (
                        _bbox_overlap_x(left.bbox, right.bbox) >= 0.12
                        or abs(
                            (left.bbox[0] + left.bbox[2]) / 2.0
                            - (right.bbox[0] + right.bbox[2]) / 2.0
                        )
                        <= 24.0
                    )
                )
                if not (same_line or stacked):
                    continue
                candidates[left_index] = _Candidate(
                    bbox=_bbox_union((left.bbox, right.bbox)),
                    text=_sanitize_hint(f"{left.text} {right.text}"),
                    fonts=left.fonts | right.fonts,
                    score=max(left.score, right.score)
                    + min(left.score, right.score) * 0.35,
                    evidence=left.evidence | right.evidence | {"merged-geometry"},
                    baselines=left.baselines | right.baselines,
                )
                del candidates[right_index]
                changed = True
                break
            if changed:
                break
    return candidates


def detect_formula_regions_from_payload(
    payload: Mapping[str, Any],
    *,
    page_no: int,
    page_width: float,
    page_height: float,
    drawings: Iterable[Any] = (),
    config: FormulaDetectionConfig | None = None,
) -> list[FormulaRegion]:
    """Detect conservative complex display regions from a PyMuPDF text dict."""

    cfg = (config or FormulaDetectionConfig()).validate()
    if page_no < 1 or page_width <= 0 or page_height <= 0:
        raise FormulaEvidenceError("invalid physical page geometry")
    candidates: list[_Candidate] = []
    for block in payload.get("blocks") or []:
        if not isinstance(block, Mapping) or block.get("type") != 0:
            continue
        for line in block.get("lines") or []:
            if isinstance(line, Mapping):
                candidates.extend(_line_candidates(line.get("spans") or [], page_width))
    candidates = [
        item
        for item in candidates
        if item.bbox[1] >= cfg.top_margin_points
        and item.bbox[3] <= page_height - cfg.bottom_margin_points
    ]
    candidates = _merge_candidates(candidates, _drawing_rules(drawings))
    complexity = {
        "operator",
        "extensible-glyph",
        "nearby-horizontal-rule",
        "unmapped-control-glyph",
    }
    candidates = [
        item
        for item in candidates
        if item.score >= cfg.min_score
        and bool(item.evidence & complexity)
        and (
            "display-geometry" in item.evidence
            or "extensible-glyph" in item.evidence
            or "nearby-horizontal-rule" in item.evidence
        )
        and item.bbox[2] - item.bbox[0] < page_width * cfg.max_width_ratio
        and item.bbox[3] - item.bbox[1] < page_height * cfg.max_height_ratio
    ]
    if cfg.max_regions_per_page and len(candidates) > cfg.max_regions_per_page:
        candidates = sorted(
            candidates, key=lambda item: (-item.score, item.bbox[1], item.bbox[0])
        )[: cfg.max_regions_per_page]
    candidates.sort(key=lambda item: (item.bbox[1], item.bbox[0]))
    output = []
    for index, candidate in enumerate(candidates, start=1):
        output.append(
            FormulaRegion(
                region_id=f"p{page_no:04d}-f{index:03d}",
                page=page_no,
                bbox_points=tuple(round(value, 3) for value in candidate.bbox),
                score=round(candidate.score, 3),
                text_hint=candidate.text,
                fonts=tuple(sorted(candidate.fonts)),
                evidence=tuple(sorted(candidate.evidence)),
            )
        )
    return output


def _load_fitz():
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError as exc:
            raise FormulaEvidenceError("PyMuPDF is required for PDF formula evidence") from exc
    return fitz


def detect_pdf_formula_regions(
    source: Path | str,
    pages: Sequence[int],
    *,
    config: FormulaDetectionConfig | None = None,
) -> list[FormulaRegion]:
    """Detect regions on physical 1-based PDF pages without raster OCR."""

    cfg = (config or FormulaDetectionConfig()).validate()
    requested = tuple(sorted(set(int(page) for page in pages)))
    if not requested or requested[0] < 1:
        raise FormulaEvidenceError("at least one positive physical page is required")
    fitz = _load_fitz()
    regions: list[FormulaRegion] = []
    with fitz.open(Path(source)) as document:
        for page_no in requested:
            if page_no > document.page_count:
                raise FormulaEvidenceError(
                    f"physical page {page_no} is outside 1-{document.page_count}"
                )
            page = document[page_no - 1]
            regions.extend(
                detect_formula_regions_from_payload(
                    page.get_text("dict", sort=True),
                    page_no=page_no,
                    page_width=float(page.rect.width),
                    page_height=float(page.rect.height),
                    drawings=page.get_drawings(),
                    config=cfg,
                )
            )
    return regions


def _padded_crop_bbox(
    bbox: tuple[float, float, float, float], page_rect: Any
) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = bbox
    width, height = x1 - x0, y1 - y0
    pad_x = max(10.0, min(24.0, width * 0.12))
    pad_y = max(7.0, min(18.0, height * 0.35))
    target_width = max(60.0, width + 2 * pad_x)
    target_height = max(24.0, height + 2 * pad_y)
    cx, cy = (x0 + x1) / 2.0, (y0 + y1) / 2.0
    return tuple(
        round(value, 3)
        for value in (
            max(float(page_rect.x0), cx - target_width / 2.0),
            max(float(page_rect.y0), cy - target_height / 2.0),
            min(float(page_rect.x1), cx + target_width / 2.0),
            min(float(page_rect.y1), cy + target_height / 2.0),
        )
    )


def _png_size(path: Path) -> tuple[int, int]:
    with path.open("rb") as stream:
        header = stream.read(24)
    if len(header) < 24 or not header.startswith(b"\x89PNG\r\n\x1a\n"):
        raise FormulaEvidenceError(f"formula crop is not a valid PNG: {path.name}")
    return struct.unpack(">II", header[16:24])


def render_pdf_formula_evidence(
    source: Path | str,
    source_sha256: str,
    regions: Sequence[FormulaRegion],
    evidence_dir: Path | str,
    *,
    dpi: int = DEFAULT_FORMULA_DPI,
) -> list[FormulaEvidence]:
    """Render bounded formula crops directly from the source PDF at high DPI."""

    source_path = Path(source).resolve(strict=True)
    source_hash = _validated_sha256(source_sha256, "source_sha256")
    if not 144 <= int(dpi) <= 600:
        raise FormulaEvidenceError("formula crop DPI must be between 144 and 600")
    fitz = _load_fitz()
    crops_dir = Path(evidence_dir).resolve() / "formula-crops"
    output: list[FormulaEvidence] = []
    with fitz.open(source_path) as document:
        for region in regions:
            region_id = _validated_region_id(region.region_id)
            if region.page < 1 or region.page > document.page_count:
                raise FormulaEvidenceError(
                    f"physical page {region.page} is outside 1-{document.page_count}"
                )
            page = document[region.page - 1]
            raw_bbox = _finite_bbox(region.bbox_points)
            if raw_bbox is None:
                raise FormulaEvidenceError(f"invalid formula bbox for {region.region_id}")
            page_bbox = (
                float(page.rect.x0),
                float(page.rect.y0),
                float(page.rect.x1),
                float(page.rect.y1),
            )
            if (
                raw_bbox[0] < page_bbox[0]
                or raw_bbox[1] < page_bbox[1]
                or raw_bbox[2] > page_bbox[2]
                or raw_bbox[3] > page_bbox[3]
            ):
                raise FormulaEvidenceError(f"formula bbox leaves page for {region.region_id}")
            crop_bbox = _padded_crop_bbox(raw_bbox, page.rect)
            crop_identity = {
                "crop_version": FORMULA_CROP_VERSION,
                "source_sha256": source_hash,
                "page": region.page,
                "formula_bbox_points": list(raw_bbox),
                "crop_bbox_points": list(crop_bbox),
                "dpi": int(dpi),
            }
            crop_digest = sha256_bytes(canonical_json_bytes(crop_identity))[:16]
            crop_path = crops_dir / f"{region_id}-{crop_digest}.png"
            valid_existing = False
            if crop_path.is_file() and not crop_path.is_symlink():
                try:
                    _png_size(crop_path)
                    valid_existing = True
                except (OSError, FormulaEvidenceError):
                    valid_existing = False
            if not valid_existing:
                clip = fitz.Rect(*crop_bbox) & page.rect
                if (
                    clip.is_empty
                    or clip.width >= page.rect.width * 0.92
                    or clip.height >= page.rect.height * 0.92
                ):
                    raise FormulaEvidenceError(
                        f"refusing non-local formula crop {region.region_id}"
                    )
                pixmap = page.get_pixmap(
                    matrix=fitz.Matrix(int(dpi) / 72.0, int(dpi) / 72.0),
                    clip=clip,
                    alpha=False,
                )
                crops_dir.mkdir(parents=True, exist_ok=True)
                temporary = crop_path.with_name(
                    f".{crop_path.stem}.{os.getpid()}.{time.time_ns()}.png"
                )
                try:
                    pixmap.save(temporary)
                    os.replace(temporary, crop_path)
                finally:
                    if temporary.exists():
                        temporary.unlink()
            size = _png_size(crop_path)
            if size[0] < 24 or size[1] < 16:
                raise FormulaEvidenceError(f"formula crop is too small: {region.region_id}")
            output.append(
                FormulaEvidence(
                    region=region,
                    crop_path=crop_path.resolve(),
                    crop_bbox_points=crop_bbox,
                    image_sha256=sha256_file(crop_path),
                    image_size_pixels=size,
                    dpi=int(dpi),
                )
            )
    return output


def prepare_pdf_formula_evidence(
    source: Path | str,
    pages: Sequence[int],
    evidence_dir: Path | str,
    *,
    dpi: int = DEFAULT_FORMULA_DPI,
    detection_config: FormulaDetectionConfig | None = None,
) -> PreparedFormulaEvidence:
    """Detect and render a reusable set of page-local formula crops."""

    source_path = Path(source).resolve(strict=True)
    source_hash = sha256_file(source_path)
    regions = detect_pdf_formula_regions(
        source_path, pages, config=detection_config
    )
    evidence = render_pdf_formula_evidence(
        source_path, source_hash, regions, evidence_dir, dpi=dpi
    )
    return PreparedFormulaEvidence(source_hash, tuple(regions), tuple(evidence))


def target_bbox_normalized(evidence: FormulaEvidence) -> tuple[float, float, float, float]:
    bx0, by0, bx1, by1 = evidence.region.bbox_points
    cx0, cy0, cx1, cy1 = evidence.crop_bbox_points
    width, height = max(1e-6, cx1 - cx0), max(1e-6, cy1 - cy0)
    values = (
        (bx0 - cx0) / width,
        (by0 - cy0) / height,
        (bx1 - cx0) / width,
        (by1 - cy0) / height,
    )
    if not (0 <= values[0] < values[2] <= 1 and 0 <= values[1] < values[3] <= 1):
        raise FormulaEvidenceError("formula target bbox is outside its crop")
    return tuple(round(value, 6) for value in values)


def formula_batch_records(batch: Sequence[FormulaEvidence]) -> list[dict[str, Any]]:
    """Return model-neutral request records in the same order as crop images."""

    return [
        {
            "image_index": index,
            "id": _validated_region_id(item.region.region_id),
            "physical_page": item.region.page,
            "target_bbox_normalized": list(target_bbox_normalized(item)),
            "untrusted_pdf_text_hint": _sanitize_hint(item.region.text_hint),
        }
        for index, item in enumerate(batch, start=1)
    ]


def balanced_formula_batches(
    items: Sequence[Any], preferred_size: int = 4
) -> list[list[Any]]:
    """Partition work into 2-4 items, except the unavoidable one-item total."""

    if preferred_size not in {2, 3, 4}:
        raise FormulaEvidenceError("preferred formula batch size must be 2, 3, or 4")
    count = len(items)
    if count <= 1:
        return [list(items)] if items else []
    batch_count = math.ceil(count / preferred_size)
    while batch_count > 1 and count / batch_count < 2:
        batch_count -= 1
    base, remainder = divmod(count, batch_count)
    sizes = [base + (1 if index < remainder else 0) for index in range(batch_count)]
    if min(sizes) < 2 or max(sizes) > 4:
        raise FormulaEvidenceError(f"cannot form bounded batches for {count} formulas")
    output: list[list[Any]] = []
    cursor = 0
    for size in sizes:
        output.append(list(items[cursor : cursor + size]))
        cursor += size
    return output


def formula_result_schema(ids: Sequence[str]) -> dict[str, Any]:
    unique = [_validated_region_id(item) for item in ids]
    if not unique or len(set(unique)) != len(unique):
        raise FormulaEvidenceError("formula schema ids must be non-empty and unique")
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["results"],
        "properties": {
            "results": {
                "type": "array",
                "minItems": len(unique),
                "maxItems": len(unique),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "latex", "confidence", "uncertain", "notes"],
                    "properties": {
                        "id": {"type": "string", "enum": unique},
                        "latex": {"type": "string", "minLength": 1, "maxLength": 20000},
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "uncertain": {"type": "boolean"},
                        "notes": {"type": "string", "maxLength": 500},
                    },
                },
            }
        },
    }


def _balanced_braces(value: str) -> bool:
    depth = 0
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _safe_math_environments(value: str) -> bool:
    stack: list[str] = []
    for action, environment in _BEGIN_END_RE.findall(value):
        if environment not in _SAFE_MATH_ENVIRONMENTS:
            return False
        if action == "begin":
            stack.append(environment)
        elif not stack or stack.pop() != environment:
            return False
    return not stack


def validate_formula_batch_result(
    value: Mapping[str, Any], expected_ids: Sequence[str]
) -> list[dict[str, Any]]:
    """Validate and order an untrusted model response for per-region caching."""

    ids_expected = [_validated_region_id(item) for item in expected_ids]
    if not ids_expected or len(set(ids_expected)) != len(ids_expected):
        raise FormulaEvidenceError("expected formula ids must be non-empty and unique")
    results = value.get("results") if isinstance(value, Mapping) else None
    if not isinstance(results, list) or len(results) != len(ids_expected):
        raise FormulaEvidenceError("formula response has the wrong result count")
    normalized: list[dict[str, Any]] = []
    for raw in results:
        if not isinstance(raw, Mapping):
            raise FormulaEvidenceError("formula result is not an object")
        result_id = str(raw.get("id") or "")
        latex = str(raw.get("latex") or "").strip()
        confidence = str(raw.get("confidence") or "")
        uncertain = raw.get("uncertain")
        notes = str(raw.get("notes") or "")
        if result_id not in ids_expected:
            raise FormulaEvidenceError(f"unexpected formula result id: {result_id}")
        if not latex or len(latex) > 20_000:
            raise FormulaEvidenceError(f"formula {result_id} has invalid LaTeX length")
        if (
            "```" in latex
            or "\x00" in latex
            or _FORBIDDEN_TEX_RE.search(latex)
            or not _balanced_braces(latex)
            or not _safe_math_environments(latex)
            or re.search(r"(?<!\\)\$|\\[\[(]", latex)
            or re.search(r"(?<!\\)%", latex)
        ):
            raise FormulaEvidenceError(
                f"formula {result_id} contains unsafe, wrapped, or unbalanced LaTeX"
            )
        if confidence not in {"high", "medium", "low"} or not isinstance(
            uncertain, bool
        ):
            raise FormulaEvidenceError(f"formula {result_id} has invalid confidence")
        if confidence == "high" and uncertain:
            raise FormulaEvidenceError(
                f"formula {result_id} cannot be both high-confidence and uncertain"
            )
        if len(notes) > 500 or any(ord(char) < 32 and char not in "\n\t" for char in notes):
            raise FormulaEvidenceError(f"formula {result_id} has invalid notes")
        normalized.append(
            {
                "id": result_id,
                "latex": latex,
                "confidence": confidence,
                "uncertain": uncertain,
                "notes": notes,
            }
        )
    result_ids = [item["id"] for item in normalized]
    if len(set(result_ids)) != len(result_ids) or set(result_ids) != set(ids_expected):
        raise FormulaEvidenceError("formula response has duplicate or missing ids")
    by_id = {item["id"]: item for item in normalized}
    return [by_id[item] for item in ids_expected]


def formula_cache_inputs(
    source_sha256: str,
    evidence: FormulaEvidence,
    identity: FormulaCacheIdentity,
) -> dict[str, Any]:
    """Return every explicit dimension of a reusable formula result."""

    return {
        "source_sha256": _validated_sha256(source_sha256, "source_sha256"),
        "physical_page": int(evidence.region.page),
        "formula_bbox_points": [round(value, 3) for value in evidence.region.bbox_points],
        "crop_bbox_points": [round(value, 3) for value in evidence.crop_bbox_points],
        "image_sha256": _validated_sha256(evidence.image_sha256, "image_sha256"),
        "image_size_pixels": list(evidence.image_size_pixels),
        "dpi": int(evidence.dpi),
        "detector_version": evidence.region.detector_version,
        "crop_version": FORMULA_CROP_VERSION,
        **identity.to_dict(),
    }


def formula_cache_key(
    source_sha256: str,
    evidence: FormulaEvidence,
    identity: FormulaCacheIdentity,
) -> str:
    return sha256_bytes(
        canonical_json_bytes(formula_cache_inputs(source_sha256, evidence, identity))
    )


class FormulaResultCache:
    """Atomic metadata-only cache for strictly validated per-formula results."""

    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()

    def path_for(self, cache_key: str) -> Path:
        key = str(cache_key or "").lower()
        if _CACHE_KEY_RE.fullmatch(key) is None:
            raise FormulaEvidenceError("invalid formula cache key")
        return self.root / key[:2] / key[2:4] / f"{key}.json"

    def load(self, cache_key: str, expected_id: str) -> dict[str, Any] | None:
        path = self.path_for(cache_key)
        if not path.is_file():
            return None
        try:
            if path.stat().st_size > 1_000_000:
                return None
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(record, dict):
            return None
        if (
            record.get("schema") != FORMULA_CACHE_SCHEMA_VERSION
            or record.get("cache_key") != cache_key
        ):
            return None
        try:
            if sha256_bytes(canonical_json_bytes(record["cache_inputs"])) != cache_key:
                return None
            validated = validate_formula_batch_result(
                {"results": [record["result"]]}, [expected_id]
            )[0]
        except (KeyError, TypeError, FormulaEvidenceError):
            return None
        return {**record, "result": validated}

    def store(
        self,
        cache_key: str,
        cache_inputs: Mapping[str, Any],
        evidence: FormulaEvidence,
        result: Mapping[str, Any],
    ) -> Path:
        path = self.path_for(cache_key)
        inputs = dict(cache_inputs)
        if sha256_bytes(canonical_json_bytes(inputs)) != cache_key:
            raise FormulaEvidenceError("cache inputs do not match the cache key")
        if inputs.get("image_sha256") != evidence.image_sha256:
            raise FormulaEvidenceError("cache inputs do not match the evidence image")
        validated = validate_formula_batch_result(
            {"results": [dict(result)]}, [evidence.region.region_id]
        )[0]
        record = {
            "schema": FORMULA_CACHE_SCHEMA_VERSION,
            "cache_key": cache_key,
            "created_at": _utc_now(),
            "cache_inputs": inputs,
            "region": evidence.region.to_dict(),
            "crop": {
                "bbox_points": list(evidence.crop_bbox_points),
                "sha256": evidence.image_sha256,
                "size_pixels": list(evidence.image_size_pixels),
                "dpi": evidence.dpi,
            },
            "result": validated,
        }
        # Deliberately omit crop_path and pixel bytes from persistent cache data.
        _atomic_json(path, record)
        return path

    def lookup(
        self,
        source_sha256: str,
        evidence: FormulaEvidence,
        identity: FormulaCacheIdentity,
    ) -> dict[str, Any] | None:
        key = formula_cache_key(source_sha256, evidence, identity)
        return self.load(key, evidence.region.region_id)

    def store_for(
        self,
        source_sha256: str,
        evidence: FormulaEvidence,
        identity: FormulaCacheIdentity,
        result: Mapping[str, Any],
    ) -> Path:
        inputs = formula_cache_inputs(source_sha256, evidence, identity)
        key = sha256_bytes(canonical_json_bytes(inputs))
        return self.store(key, inputs, evidence, result)
