"""Immutable multi-image OCR inputs and their derived visual PDF.

The ZIP is the canonical user input: it retains every original byte stream,
name, order and digest.  The PDF is a host-derived visual transport used by
the existing page renderer; it is never described as an uploaded PDF.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


MULTI_IMAGE_SOURCE_SCHEMA = "latexstruct-ocr-multi-image-source-v1"
MULTI_IMAGE_DERIVATION_ID = "original-images-to-page-preserving-pdf-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _safe_name(value: object, index: int) -> str:
    name = Path(str(value or "")).name.strip()
    name = "".join(char for char in name if ord(char) >= 32 and char not in "\x7f")
    if not name or name in {".", ".."}:
        name = f"image-{index:06d}.png"
    return name[:240]


def _image_kind(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png", "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg", "image/jpeg"
    raise ValueError("multi-image OCR accepts only PNG or JPEG bytes")


@dataclass(frozen=True, slots=True)
class MultiImageSource:
    bundle_bytes: bytes
    visual_pdf_bytes: bytes
    manifest: Mapping[str, object]

    @property
    def image_entries(self) -> tuple[Mapping[str, object], ...]:
        return tuple(self.manifest.get("images") or ())


def _visual_pdf(images: Sequence[bytes]) -> bytes:
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError as exc:  # pragma: no cover - packaged runtime includes it
            raise RuntimeError("PyMuPDF is required for multi-image OCR") from exc

    document = pymupdf.open()
    try:
        for data in images:
            pixmap = pymupdf.Pixmap(data)
            if pixmap.width < 1 or pixmap.height < 1:
                raise ValueError("multi-image source has invalid pixel dimensions")
            # Rendering this page at the v2 baseline 200 DPI reproduces the
            # original pixel dimensions; the 300-DPI retry is an explicit
            # 1.5x derived raster rather than an invented source resolution.
            width = float(pixmap.width) * 72.0 / 200.0
            height = float(pixmap.height) * 72.0 / 200.0
            page = document.new_page(width=width, height=height)
            page.insert_image(page.rect, stream=data, keep_proportion=True)
            pixmap = None
        payload = document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()
    if not payload.startswith(b"%PDF-"):
        raise RuntimeError("multi-image visual PDF generation failed")
    return payload


def build_multi_image_source(
    images: Sequence[tuple[str, bytes]],
) -> MultiImageSource:
    """Create a canonical originals ZIP plus a page-preserving visual PDF."""
    if len(images) < 2:
        raise ValueError("multi-image source requires at least two images")
    if len(images) > 2000:
        raise ValueError("multi-image source exceeds the 2000-page safety limit")

    rows: list[dict[str, object]] = []
    raw_images: list[bytes] = []
    for index, (raw_name, raw_bytes) in enumerate(images, 1):
        data = bytes(raw_bytes)
        if not data:
            raise ValueError(f"image {index} is empty")
        extension, media_type = _image_kind(data)
        path = f"images/{index:06d}{extension}"
        rows.append({
            "order": index,
            "original_filename": _safe_name(raw_name, index),
            "archive_path": path,
            "media_type": media_type,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        raw_images.append(data)

    visual_pdf = _visual_pdf(raw_images)
    manifest = {
        "schema": MULTI_IMAGE_SOURCE_SCHEMA,
        "image_count": len(rows),
        "images": rows,
        "derived_visual_source": {
            "kind": "HOST_DERIVED_VISUAL_PDF",
            "derivation_id": MULTI_IMAGE_DERIVATION_ID,
            "page_count": len(rows),
            "bytes": len(visual_pdf),
            "sha256": hashlib.sha256(visual_pdf).hexdigest(),
            "is_original_upload": False,
        },
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for row, data in zip(rows, raw_images):
            info = zipfile.ZipInfo(str(row["archive_path"]), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
        info = zipfile.ZipInfo("source-manifest.json", (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, _canonical_json(manifest))
    return MultiImageSource(output.getvalue(), visual_pdf, manifest)


def verify_multi_image_source(
    bundle_bytes: bytes,
    *,
    expected_images: Sequence[Mapping[str, object]] | None = None,
    expected_visual_sha256: str = "",
) -> dict[str, object]:
    """Recompute every original image digest and reject unsafe ZIP members."""
    data = bytes(bundle_bytes)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("multi-image source bundle is not a valid ZIP") from exc
    with archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "source-manifest.json" not in names:
            raise ValueError("multi-image source bundle has duplicate or missing members")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:
                raise ValueError("multi-image source bundle contains an unsafe path")
        try:
            manifest = json.loads(archive.read("source-manifest.json").decode("utf-8"))
        except (KeyError, OSError, UnicodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            raise ValueError("multi-image source manifest is missing or corrupt") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != MULTI_IMAGE_SOURCE_SCHEMA:
            raise ValueError("multi-image source manifest schema is invalid")
        rows = manifest.get("images")
        if not isinstance(rows, list) or len(rows) < 2:
            raise ValueError("multi-image source manifest has no ordered images")
        expected_names = {"source-manifest.json"}
        for index, row in enumerate(rows, 1):
            if not isinstance(row, dict) or row.get("order") != index:
                raise ValueError("multi-image source order is invalid")
            path = str(row.get("archive_path") or "")
            expected_names.add(path)
            try:
                payload = archive.read(path)
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                raise ValueError(
                    f"multi-image source member is missing or corrupt at order {index}"
                ) from exc
            digest = str(row.get("sha256") or "").lower()
            if (
                not _SHA256_RE.fullmatch(digest)
                or row.get("bytes") != len(payload)
                or hashlib.sha256(payload).hexdigest() != digest
                or _image_kind(payload)[1] != row.get("media_type")
            ):
                raise ValueError(f"multi-image source hash mismatch at order {index}")
        if set(names) != expected_names:
            raise ValueError("multi-image source bundle contains unmanifested files")
        derived = manifest.get("derived_visual_source")
        if not isinstance(derived, dict) or derived.get("is_original_upload") is not False:
            raise ValueError("multi-image visual derivation record is invalid")
        visual_sha = str(derived.get("sha256") or "").lower()
        if not _SHA256_RE.fullmatch(visual_sha):
            raise ValueError("multi-image visual source digest is invalid")
        if expected_visual_sha256 and visual_sha != str(expected_visual_sha256).lower():
            raise ValueError("multi-image visual source digest differs from snapshot")
        if expected_images is not None:
            normalized = [dict(item) for item in expected_images]
            if normalized != rows:
                raise ValueError("multi-image source manifest differs from snapshot")
        return manifest


def extract_multi_image_bytes(
    bundle_bytes: bytes, manifest: Mapping[str, object]
) -> list[tuple[dict[str, object], bytes]]:
    """Return verified originals in frozen order for audit packaging."""
    checked = verify_multi_image_source(
        bundle_bytes,
        expected_images=manifest.get("images") or (),
        expected_visual_sha256=str(
            (manifest.get("derived_visual_source") or {}).get("sha256") or ""
        ),
    )
    with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as archive:
        return [
            (dict(row), archive.read(str(row["archive_path"])))
            for row in checked["images"]
        ]


__all__ = [
    "MULTI_IMAGE_DERIVATION_ID",
    "MULTI_IMAGE_SOURCE_SCHEMA",
    "MultiImageSource",
    "build_multi_image_source",
    "extract_multi_image_bytes",
    "verify_multi_image_source",
]
