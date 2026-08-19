# -*- coding: utf-8 -*-
"""Deterministic layout data for the ``faithfulbook`` OCR template.

The style is kept as a reviewed package asset, but is rendered inline into the
exported TEX.  Inline rendering matters for desktop exports: a user can compile
the TEX/project without an unregistered runtime-only ``.sty`` dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Mapping

FAITHFULBOOK_STYLE_FILENAME = "faithfulbook-preamble.tex"
FAITHFULBOOK_STYLE_MARKER = "% LaTeXStruct template: faithfulbook v1"

_ASSET_PATH = (
    Path(__file__).resolve().parent.parent
    / "assets"
    / "faithfulbook"
    / FAITHFULBOOK_STYLE_FILENAME
)
_EXPECTED_SHA256 = "3ad6c359258631bfc8363e4d729a6af8c8aaf0b226dad63146b108dfb3be5d73"
_PT_TO_MM = 25.4 / 72.0


@dataclass(frozen=True)
class FaithfulBookLayout:
    """Safe, serializable geometry for a compact two-sided mathematics book."""

    paper_width_mm: float = 155.0
    paper_height_mm: float = 235.0
    body_font_pt: int = 10
    body_leading_pt: float = 12.0
    inner_margin_mm: float = 16.0
    outer_margin_mm: float = 14.0
    top_margin_mm: float = 15.0
    bottom_margin_mm: float = 17.0

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _finite_number(value: Any, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} 必须是数值") from exc
    if not math.isfinite(number):
        raise ValueError(f"{name} 必须是有限数值")
    return number


def _first(source: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    return None


def _layout_values(source: Mapping[str, Any]) -> dict[str, Any]:
    """Read common explicit/PDF-metadata spellings without accepting TeX text."""

    result: dict[str, Any] = {}
    page_size = _first(source, "page_size_mm", "paper_size_mm", "source_page_size_mm")
    if isinstance(page_size, (list, tuple)) and len(page_size) == 2:
        result["paper_width_mm"], result["paper_height_mm"] = page_size
    elif isinstance(page_size, Mapping):
        result["paper_width_mm"] = _first(page_size, "width", "width_mm")
        result["paper_height_mm"] = _first(page_size, "height", "height_mm")

    aliases = {
        "paper_width_mm": (
            "paper_width_mm", "page_width_mm", "source_page_width_mm", "width_mm",
        ),
        "paper_height_mm": (
            "paper_height_mm", "page_height_mm", "source_page_height_mm", "height_mm",
        ),
        "body_font_pt": ("body_font_pt", "font_size_pt", "body_size_pt"),
        "body_leading_pt": ("body_leading_pt", "leading_pt", "line_height_pt"),
        "inner_margin_mm": ("inner_margin_mm", "inside_margin_mm"),
        "outer_margin_mm": ("outer_margin_mm", "outside_margin_mm"),
        "top_margin_mm": ("top_margin_mm",),
        "bottom_margin_mm": ("bottom_margin_mm",),
    }
    for target, keys in aliases.items():
        value = _first(source, *keys)
        if value not in (None, ""):
            result[target] = value

    # PyMuPDF/PDF metadata commonly reports points rather than millimetres.
    if "paper_width_mm" not in result:
        width_pt = _first(source, "paper_width_pt", "page_width_pt", "source_page_width_pt")
        if width_pt not in (None, ""):
            result["paper_width_mm"] = _finite_number(width_pt, "页面宽度") * _PT_TO_MM
    if "paper_height_mm" not in result:
        height_pt = _first(source, "paper_height_pt", "page_height_pt", "source_page_height_pt")
        if height_pt not in (None, ""):
            result["paper_height_mm"] = _finite_number(height_pt, "页面高度") * _PT_TO_MM

    margin = _first(source, "margin_mm", "margins_mm")
    if margin not in (None, "") and not isinstance(margin, Mapping):
        for key in (
            "inner_margin_mm", "outer_margin_mm", "top_margin_mm", "bottom_margin_mm",
        ):
            result.setdefault(key, margin)
    elif isinstance(margin, Mapping):
        margin_aliases = {
            "inner_margin_mm": ("inner", "inside", "left"),
            "outer_margin_mm": ("outer", "outside", "right"),
            "top_margin_mm": ("top",),
            "bottom_margin_mm": ("bottom",),
        }
        for target, keys in margin_aliases.items():
            value = _first(margin, *keys)
            if value not in (None, ""):
                result[target] = value
    return {key: value for key, value in result.items() if value not in (None, "")}


def resolve_faithfulbook_layout(
    context: Mapping[str, Any] | None = None,
) -> FaithfulBookLayout:
    """Resolve defaults < OCR/PDF metadata < explicit context < ``layout``.

    ``context`` is deliberately data-only.  Supported values are numeric and
    are formatted by this module, so no caller-controlled LaTeX is interpolated.
    Existing importers can pass their metadata under ``ocr_metadata`` or
    ``pdf_metadata`` without changing the OCR text protocol.
    """

    root = _mapping(context)
    merged: dict[str, Any] = {}
    for source in (
        _mapping(root.get("ocr_metadata")),
        _mapping(root.get("pdf_metadata")),
        root,
        _mapping(root.get("layout")),
    ):
        merged.update(_layout_values(source))

    layout = FaithfulBookLayout()
    numeric_fields = {
        key: _finite_number(value, key)
        for key, value in merged.items()
        if key != "body_font_pt"
    }
    if "body_font_pt" in merged:
        raw_font = _finite_number(merged["body_font_pt"], "body_font_pt")
        if raw_font not in (10.0, 12.0):
            raise ValueError("faithfulbook 正文字号仅支持 10pt 或 12pt")
        numeric_fields["body_font_pt"] = int(raw_font)
        if "body_leading_pt" not in merged:
            numeric_fields["body_leading_pt"] = 12.0 if raw_font == 10.0 else 14.4
    layout = replace(layout, **numeric_fields)

    if not (100.0 <= layout.paper_width_mm <= 260.0):
        raise ValueError("faithfulbook 页面宽度必须在 100–260mm 之间")
    if not (140.0 <= layout.paper_height_mm <= 360.0):
        raise ValueError("faithfulbook 页面高度必须在 140–360mm 之间")
    if layout.paper_width_mm >= layout.paper_height_mm:
        raise ValueError("faithfulbook 仅接受纵向书籍页面（宽度必须小于高度）")
    for label, value in (
        ("内侧", layout.inner_margin_mm),
        ("外侧", layout.outer_margin_mm),
        ("上侧", layout.top_margin_mm),
        ("下侧", layout.bottom_margin_mm),
    ):
        if not (8.0 <= value <= 40.0):
            raise ValueError(f"faithfulbook {label}边距必须在 8–40mm 之间")
    if layout.inner_margin_mm + layout.outer_margin_mm > layout.paper_width_mm - 60.0:
        raise ValueError("faithfulbook 左右边距使正文宽度不足 60mm")
    if layout.top_margin_mm + layout.bottom_margin_mm > layout.paper_height_mm - 80.0:
        raise ValueError("faithfulbook 上下边距使正文高度不足 80mm")
    if not (layout.body_font_pt + 1.0 <= layout.body_leading_pt <= layout.body_font_pt * 1.6):
        raise ValueError("faithfulbook 行距必须介于字号 +1pt 与字号的 1.6 倍之间")
    return layout


def faithfulbook_style_asset_bytes() -> bytes:
    try:
        data = _ASSET_PATH.read_bytes()
    except OSError as exc:
        raise RuntimeError("faithfulbook 样式资源缺失") from exc
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, _EXPECTED_SHA256):
        raise RuntimeError("faithfulbook 样式资源校验失败")
    return data


def _tex_number(value: float | int) -> str:
    return f"{float(value):.3f}".rstrip("0").rstrip(".")


def render_faithfulbook_style(layout: FaithfulBookLayout) -> str:
    text = faithfulbook_style_asset_bytes().decode("utf-8")
    replacements = {
        "@@PAPER_WIDTH_MM@@": layout.paper_width_mm,
        "@@PAPER_HEIGHT_MM@@": layout.paper_height_mm,
        "@@BODY_FONT_PT@@": layout.body_font_pt,
        "@@BODY_LEADING_PT@@": layout.body_leading_pt,
        "@@INNER_MARGIN_MM@@": layout.inner_margin_mm,
        "@@OUTER_MARGIN_MM@@": layout.outer_margin_mm,
        "@@TOP_MARGIN_MM@@": layout.top_margin_mm,
        "@@BOTTOM_MARGIN_MM@@": layout.bottom_margin_mm,
    }
    for token, value in replacements.items():
        text = text.replace(token, _tex_number(value))
    if "@@" in text:
        raise RuntimeError("faithfulbook 样式资源含未解析占位符")
    return text.rstrip("\r\n")
