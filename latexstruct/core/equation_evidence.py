# -*- coding: utf-8 -*-
"""Recover legacy OCR equation-tag evidence from immutable source PDF bytes.

This migration is deliberately narrower than OCR.  It never invents a label or
rewrites mathematics.  A legacy literal/active TeX inventory must already exist,
and every ``(page, label)`` must match exactly one isolated PDF text word in the
outer page margin.  The complete source page is rendered and hash-bound before
the host upgrades the metadata to version 2.  The existing semantic-IR gate then
performs the actual reversible rewrite and verifies the resulting active tags.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .ocrstruct import (
    LEGACY_EQUATION_TAG_EVIDENCE_STATUS,
    LEGACY_EQUATION_TAG_EVIDENCE_VERIFIER,
    META_RE,
    encode_ocr_metadata,
    parse_ocr_metadata,
)
from .patch import PendingOp
from .semantic_ir import _equation_plan


@dataclass(frozen=True)
class LegacyEquationEvidenceResult:
    checked: bool
    upgraded: bool
    ok: bool
    status: str
    evidence: Tuple[dict, ...]
    issues: Tuple[dict, ...]
    source_pdf_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "upgraded": self.upgraded,
            "ok": self.ok,
            "status": self.status,
            "evidence_count": len(self.evidence),
            "evidence": [dict(item) for item in self.evidence],
            "issues": [dict(item) for item in self.issues],
            "source_pdf_sha256": self.source_pdf_sha256,
        }


def _failure(status: str, message: str, *, checked: bool = True):
    return [], LegacyEquationEvidenceResult(
        checked=checked,
        upgraded=False,
        ok=False,
        status=status,
        evidence=(),
        issues=({"line": 1, "reason": message},),
    )


def _load_renderer():
    try:
        import pymupdf  # type: ignore
    except Exception:  # noqa: BLE001 - optional native boundary
        return None
    return pymupdf


def _full_page_render_sha256(module, page) -> str:
    pixmap = page.get_pixmap(
        matrix=module.Matrix(1, 1),
        colorspace=module.csGRAY,
        alpha=False,
    )
    payload = (
        f"{pixmap.width}x{pixmap.height}:".encode("ascii")
        + bytes(pixmap.samples)
    )
    return hashlib.sha256(payload).hexdigest()


def _outer_equation_words(page) -> Dict[str, List[Tuple[float, float, float, float]]]:
    width = float(page.rect.width)
    height = float(page.rect.height)
    if width <= 0 or height <= 0:
        return {}
    raw_words = list(page.get_text("words"))
    line_counts: Dict[Tuple[int, int], int] = {}
    for word in raw_words:
        if len(word) >= 7:
            key = (int(word[5]), int(word[6]))
            line_counts[key] = line_counts.get(key, 0) + 1
    found: Dict[str, List[Tuple[float, float, float, float]]] = {}
    for word in raw_words:
        if len(word) < 5:
            continue
        token = str(word[4]).strip()
        match = re.fullmatch(r"\(([0-9]{1,4}[A-Za-z]?)\)", token)
        if match is None:
            continue
        x0, y0, x1, y1 = (float(value) for value in word[:4])
        normalized = (x0 / width, y0 / height, x1 / width, y1 / height)
        # Equation labels live in the outer margin.  This excludes numbered
        # prose, citations and displayed tuples inside the text block.
        if normalized[0] > 0.22 and normalized[2] < 0.78:
            continue
        if not 0.04 <= normalized[1] < normalized[3] <= 0.94:
            continue
        # A printed equation number is an isolated margin token.  Reject prose
        # such as ``(1) first case`` even when it happens to begin near a margin.
        if len(word) >= 7 and line_counts.get((int(word[5]), int(word[6])), 0) != 1:
            continue
        found.setdefault(match.group(1), []).append(normalized)
    return found


def _bbox_matches(left, right, tolerance: float = 0.035) -> bool:
    if not (
        isinstance(left, (list, tuple))
        and isinstance(right, (list, tuple))
        and len(left) == len(right) == 4
    ):
        return False
    try:
        return all(
            abs(float(a) - float(b)) <= tolerance
            for a, b in zip(left, right)
        )
    except (TypeError, ValueError):
        return False


def _revalidate_v2_equation_evidence(
    text: str,
    metadata: dict,
    source: bytes,
    module,
) -> LegacyEquationEvidenceResult:
    """Bind existing v2 metadata to the source PDF supplied for this run."""

    evidence = list(metadata.get("equation_tags") or [])
    _operations, _notes, inventory = _equation_plan(text, metadata)
    actual_pairs = [tuple(item) for item in inventory.get("actual_pairs") or ()]
    expected_pairs = [
        (int(item["page"]), str(item["label"])) for item in evidence
    ]
    if inventory.get("issues") or actual_pairs != expected_pairs:
        return LegacyEquationEvidenceResult(
            checked=True,
            upgraded=False,
            ok=False,
            status="v2_inventory_mismatch",
            evidence=tuple(evidence),
            issues=({
                "line": 1,
                "reason": "metadata v2 公式清单与本次 TEX 活动/普通标签不一致",
            },),
            source_pdf_sha256=hashlib.sha256(source).hexdigest(),
        )
    source_sha256 = hashlib.sha256(source).hexdigest()
    literal_sha256 = hashlib.sha256(
        "\n".join(f"{page}:{label}" for page, label in expected_pairs).encode("utf-8")
    ).hexdigest()
    document = None
    runtime_evidence = []
    try:
        document = module.open(stream=source, filetype="pdf")
        if getattr(document, "needs_pass", False):
            raise ValueError("locked")
        if any(page > int(document.page_count) for page, _label in expected_pairs):
            raise ValueError("missing-page")
        page_cache = {}
        for item in evidence:
            page_number = int(item["page"])
            label = str(item["label"])
            if page_number not in page_cache:
                page = document[page_number - 1]
                page_cache[page_number] = (
                    _outer_equation_words(page),
                    _full_page_render_sha256(module, page),
                )
            words, render_sha256 = page_cache[page_number]
            matches = [
                bbox for bbox in words.get(label, [])
                if _bbox_matches(bbox, item.get("bbox_normalized"))
            ]
            if len(matches) != 1:
                raise ValueError("geometry")
            if item.get("status") == LEGACY_EQUATION_TAG_EVIDENCE_STATUS:
                if (
                    item.get("source_pdf_sha256") != source_sha256
                    or item.get("page_render_sha256") != render_sha256
                    or item.get("literal_inventory_sha256") != literal_sha256
                ):
                    raise ValueError("legacy-binding")
            runtime_evidence.append({
                **dict(item),
                "runtime_source_pdf_sha256": source_sha256,
                "runtime_page_render_sha256": render_sha256,
                "runtime_geometry_reverified": True,
            })
    except Exception:  # noqa: BLE001 - untrusted source PDF boundary
        return LegacyEquationEvidenceResult(
            checked=True,
            upgraded=False,
            ok=False,
            status="v2_source_reverification_failed",
            evidence=tuple(evidence),
            issues=({
                "line": 1,
                "reason": "metadata v2 公式证据无法与本次不可变源 PDF 的几何/渲染重新绑定",
            },),
            source_pdf_sha256=source_sha256,
        )
    finally:
        if document is not None:
            document.close()
    return LegacyEquationEvidenceResult(
        checked=True,
        upgraded=False,
        ok=True,
        status="v2_source_reverified",
        evidence=tuple(runtime_evidence),
        issues=(),
        source_pdf_sha256=source_sha256,
    )


def build_legacy_equation_evidence_ops(
    text: str,
    source_pdf_bytes: bytes,
) -> tuple[List[PendingOp], LegacyEquationEvidenceResult]:
    """Return one metadata replacement op when legacy evidence is provable."""

    metadata = parse_ocr_metadata(text)
    if not metadata:
        return _failure("not_ocr_metadata", "没有可解析的 OCR metadata", checked=False)
    if not isinstance(source_pdf_bytes, (bytes, bytearray, memoryview)):
        return _failure("source_missing", "旧版公式证据升级需要原始 PDF 字节")
    source = bytes(source_pdf_bytes)
    if not source.startswith(b"%PDF-"):
        return _failure("source_invalid", "原始 PDF 字节无效")

    module = _load_renderer()
    if module is None:
        return _failure("renderer_unavailable", "无法渲染原始 PDF，证据校验已停止")
    if int(metadata.get("version", 1)) >= 2:
        return [], _revalidate_v2_equation_evidence(
            text,
            metadata,
            source,
            module,
        )

    _operations, _notes, inventory = _equation_plan(text, metadata)
    pairs = [tuple(item) for item in inventory.get("actual_pairs") or ()]
    if inventory.get("issues"):
        return _failure(
            "literal_inventory_invalid",
            "原始 TeX 的公式编号清单不唯一或不可安全迁移",
        )
    if not pairs:
        # A legacy document with no printed equation labels has nothing to
        # migrate.  Treating the empty, issue-free inventory as an evidence
        # failure would block every older OCR project that simply contains no
        # numbered display equations.
        return [], LegacyEquationEvidenceResult(
            checked=True,
            upgraded=False,
            ok=True,
            status="no_equation_tags",
            evidence=(),
            issues=(),
            source_pdf_sha256=hashlib.sha256(source).hexdigest(),
        )
    if any(
        not isinstance(page, int)
        or page <= 0
        or re.fullmatch(r"[0-9]{1,4}[A-Za-z]?", str(label)) is None
        for page, label in pairs
    ):
        return _failure(
            "literal_inventory_unbound",
            "原始 TeX 公式编号没有完整绑定到 PDF 页码",
        )
    if len(set(pairs)) != len(pairs):
        return _failure(
            "literal_inventory_duplicate",
            "原始 TeX 含重复的页码与公式编号组合",
        )

    source_sha256 = hashlib.sha256(source).hexdigest()
    literal_sha256 = hashlib.sha256(
        "\n".join(f"{page}:{label}" for page, label in pairs).encode("utf-8")
    ).hexdigest()
    document = None
    try:
        document = module.open(stream=source, filetype="pdf")
        if getattr(document, "needs_pass", False):
            return _failure("source_locked", "原始 PDF 已加密，无法验证公式编号")
        if any(page > int(document.page_count) for page, _label in pairs):
            return _failure("source_page_missing", "公式编号引用了原始 PDF 之外的页码")

        page_cache = {}
        evidence = []
        sides = set()
        for page_number, label in pairs:
            if page_number not in page_cache:
                page = document[page_number - 1]
                page_cache[page_number] = (
                    _outer_equation_words(page),
                    _full_page_render_sha256(module, page),
                )
            words, render_sha256 = page_cache[page_number]
            matches = words.get(str(label), [])
            if len(matches) != 1:
                return _failure(
                    "source_geometry_mismatch",
                    f"PDF 第 {page_number} 页外缘编号 ({label}) 不是唯一匹配",
                )
            bbox = matches[0]
            side = "left" if bbox[0] <= 0.22 else "right"
            sides.add(side)
            evidence_id = hashlib.sha256(
                (
                    f"{source_sha256}:{page_number}:{label}:"
                    + ",".join(f"{value:.6f}" for value in bbox)
                    + f":{render_sha256}:{literal_sha256}"
                ).encode("ascii")
            ).hexdigest()
            evidence.append({
                "page": page_number,
                "label": str(label),
                "evidence_id": evidence_id,
                "bbox_normalized": [round(value, 6) for value in bbox],
                "source": "immutable_source_pdf_text_geometry_and_full_page_render",
                "status": LEGACY_EQUATION_TAG_EVIDENCE_STATUS,
                "verifier": LEGACY_EQUATION_TAG_EVIDENCE_VERIFIER,
                "page_render_sha256": render_sha256,
                "source_pdf_sha256": source_sha256,
                "literal_inventory_sha256": literal_sha256,
            })
        if len(sides) != 1:
            return _failure(
                "source_side_inconsistent",
                "PDF 外缘公式编号左右位置不一致，已停止整类转换",
            )
    except Exception:  # noqa: BLE001 - untrusted PDF parser boundary
        return _failure("source_read_failed", "原始 PDF 的公式编号证据无法读取")
    finally:
        if document is not None:
            document.close()

    upgraded_line = encode_ocr_metadata(
        metadata.get("outline") or (),
        str(metadata.get("kind") or "article"),
        metadata.get("pages") or (),
        bool(metadata.get("source_has_toc")),
        equation_tag_evidence=evidence,
    )
    match = META_RE.search(text)
    if match is None:
        return _failure("metadata_anchor_missing", "OCR metadata 行无法复验")
    line_number = text.count("\n", 0, match.start()) + 1
    old_line = text.split("\n")[line_number - 1]
    result = LegacyEquationEvidenceResult(
        checked=True,
        upgraded=True,
        ok=True,
        status="upgraded_to_v2",
        evidence=tuple(evidence),
        issues=(),
        source_pdf_sha256=source_sha256,
    )
    return [PendingOp(
        "replace_line",
        line_number,
        old=old_line,
        new=upgraded_line,
    )], result
