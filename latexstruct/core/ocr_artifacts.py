"""Verified access to the immutable artifacts of an OCR run.

The web layer deliberately asks this module for an allowlisted artifact role
instead of accepting a filename.  Every derived file is checked against the
write-once manifest before it can be downloaded.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .ocr_runtime import OcrPreviewStatus, OcrRunStore, OcrStoreError


@dataclass(frozen=True, slots=True)
class VerifiedOcrArtifact:
    role: str
    path: Path
    filename: str
    media_type: str
    sha256: str


_ROLE_METADATA: Mapping[str, tuple[str, str]] = {
    "source": ("source", "application/octet-stream"),
    "source-images-manifest": ("source-images-manifest.json", "application/json"),
    "visual-source": ("visual-source.pdf", "application/pdf"),
    "snapshot": ("run-snapshot.json", "application/json"),
    "raw-ocr": ("raw-ocr.tex", "application/x-tex"),
    "raw-manifest": ("raw-ocr-freeze.json", "application/json"),
    "baseline-tex": ("baseline.tex", "application/x-tex"),
    "baseline-pdf": ("baseline.pdf", "application/pdf"),
    "compile-log": ("compile-baseline.log", "text/plain"),
    "baseline-manifest": ("baseline-manifest.json", "application/json"),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OcrStoreError(f"{label} is missing or corrupt") from exc
    if not isinstance(value, dict):
        raise OcrStoreError(f"{label} must be a JSON object")
    return value


def _verified(path: Path, expected: object, label: str) -> str:
    if not path.is_file():
        raise OcrStoreError(f"{label} is not available")
    actual = _sha256(path)
    normalized = str(expected or "").strip().lower()
    if normalized and not hmac.compare_digest(actual, normalized):
        raise OcrStoreError(f"{label} SHA-256 verification failed")
    return actual


def resolve_ocr_artifact(
    store: OcrRunStore,
    run_id: str,
    role: str,
) -> VerifiedOcrArtifact:
    """Resolve one public artifact role and verify its immutable evidence."""
    normalized = str(role or "").strip().lower()
    if normalized not in _ROLE_METADATA:
        raise ValueError("unsupported OCR artifact role")
    run_dir = store.run_dir(run_id)
    artifacts = run_dir / "artifacts"
    configured_name, media_type = _ROLE_METADATA[normalized]

    if normalized == "source":
        path = store.verify_source(run_id)
        snapshot = store.load_snapshot(run_id)
        digest = _verified(path, snapshot.source_sha256, "OCR source")
        return VerifiedOcrArtifact(
            role=normalized,
            path=path,
            filename=snapshot.original_filename,
            media_type=(
                "application/pdf"
                if path.suffix.lower() == ".pdf"
                else "application/zip"
                if snapshot.source_type == "images"
                else media_type
            ),
            sha256=digest,
        )

    if normalized == "visual-source":
        path = store.verify_visual_source(run_id)
        snapshot = store.load_snapshot(run_id)
        digest = _verified(path, snapshot.visual_source_sha256, "OCR visual source")
        return VerifiedOcrArtifact(normalized, path, configured_name, media_type, digest)

    if normalized == "source-images-manifest":
        snapshot = store.load_snapshot(run_id)
        if snapshot.source_type != "images":
            raise OcrStoreError("OCR run has no source image manifest")
        path = run_dir / configured_name
        manifest = _load_json(path, "OCR source image manifest")
        expected_manifest = {
            "schema": "latexstruct-ocr-source-images-snapshot-v1",
            "run_id": snapshot.run_id,
            "source_sha256": snapshot.source_sha256,
            "visual_source_sha256": snapshot.visual_source_sha256,
            "images": snapshot.to_dict()["source_images"],
        }
        if manifest != expected_manifest:
            raise OcrStoreError("OCR source image manifest differs from immutable snapshot")
        digest = _verified(path, "", "OCR source image manifest")
        return VerifiedOcrArtifact(normalized, path, configured_name, media_type, digest)

    if normalized == "snapshot":
        # Parsing validates the schema and its host-computed configuration hash.
        store.load_snapshot(run_id)
        path = run_dir / configured_name
        digest = _verified(path, "", "OCR run snapshot")
        return VerifiedOcrArtifact(normalized, path, configured_name, media_type, digest)

    if normalized in {"raw-ocr", "raw-manifest"}:
        manifest_path = artifacts / "raw-ocr-freeze.json"
        manifest = _load_json(manifest_path, "OCR raw freeze manifest")
        path = artifacts / configured_name
        expected = manifest.get("raw_ocr_sha256") if normalized == "raw-ocr" else ""
        digest = _verified(path, expected, f"OCR artifact {normalized}")
        return VerifiedOcrArtifact(normalized, path, configured_name, media_type, digest)

    manifest_path = artifacts / "baseline-manifest.json"
    manifest = _load_json(manifest_path, "OCR baseline manifest")
    status = str(manifest.get("preview_status") or "")
    if normalized == "baseline-pdf":
        if status == OcrPreviewStatus.COMPILED.value:
            configured_name = "baseline.pdf"
        elif status == OcrPreviewStatus.PARTIAL_COMPILED.value:
            configured_name = "partial-baseline.pdf"
        elif status == OcrPreviewStatus.SOURCE_PREVIEW.value:
            configured_name = "source-preview.pdf"
        else:
            raise OcrStoreError("OCR baseline preview status is invalid")
        expected = manifest.get("pdf_sha256")
    elif normalized == "baseline-tex":
        expected = manifest.get("baseline_tex_sha256")
    elif normalized == "compile-log":
        expected = manifest.get("compile_log_sha256")
    else:
        expected = ""
    path = artifacts / configured_name
    digest = _verified(path, expected, f"OCR artifact {normalized}")
    return VerifiedOcrArtifact(normalized, path, configured_name, media_type, digest)


def available_ocr_artifacts(store: OcrRunStore, run_id: str) -> dict[str, dict[str, object]]:
    """Return only roles whose bytes pass their manifest/hash checks."""
    result: dict[str, dict[str, object]] = {}
    for role in _ROLE_METADATA:
        try:
            artifact = resolve_ocr_artifact(store, run_id, role)
        except (OcrStoreError, OSError, ValueError):
            continue
        result[role] = {
            "filename": artifact.filename,
            "media_type": artifact.media_type,
            "sha256": artifact.sha256,
            "size": artifact.path.stat().st_size,
        }
    return result
