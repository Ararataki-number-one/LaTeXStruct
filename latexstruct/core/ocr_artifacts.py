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
from types import MappingProxyType
from typing import Mapping

from .ocr_manifest import (
    DEFAULT_MANIFEST_PATH,
    ROLE_BASELINE_PDF,
    ROLE_BASELINE_TEX,
    OcrBaselineManifest,
    OcrBaselineManifestError,
    verify_ocr_baseline_manifest,
)
from .ocr_runtime import (
    _OCR_BASELINE_PACKAGE_DIRECTORY,
    _path_is_reparse_point,
    _scan_ocr_bundle_tree,
    _strict_ocr_bundle_relative_path,
    OcrPreviewStatus,
    OcrRunStore,
    OcrStoreError,
)


@dataclass(frozen=True, slots=True)
class VerifiedOcrArtifact:
    role: str
    path: Path
    filename: str
    media_type: str
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedOcrBaselineArtifact:
    """Exact bytes for one role in a verified OCR baseline package."""

    role: str
    logical_path: str
    path: Path
    data: bytes
    sha256: str
    media_type: str

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True, slots=True)
class VerifiedOcrBaselineBundle:
    """Fail-closed OCR baseline input for the optional analysis pipeline."""

    root: Path
    manifest_path: Path
    manifest: OcrBaselineManifest
    artifacts_by_role: Mapping[str, VerifiedOcrBaselineArtifact]

    def require_role(self, role: str) -> VerifiedOcrBaselineArtifact:
        try:
            return self.artifacts_by_role[str(role)]
        except KeyError as exc:
            raise OcrStoreError(f"OCR baseline package has no {role} artifact") from exc

    def get_role(self, role: str) -> VerifiedOcrBaselineArtifact | None:
        return self.artifacts_by_role.get(str(role))

    @property
    def baseline_tex(self) -> VerifiedOcrBaselineArtifact:
        return self.require_role(ROLE_BASELINE_TEX)

    @property
    def baseline_pdf(self) -> VerifiedOcrBaselineArtifact | None:
        return self.get_role(ROLE_BASELINE_PDF)

    def artifact_bytes(self) -> Mapping[str, bytes]:
        return MappingProxyType({
            artifact.logical_path: artifact.data
            for artifact in self.artifacts_by_role.values()
        })


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
    "ocr-baseline-manifest": (
        "ocr_baseline_manifest.json",
        "application/json",
    ),
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


def _reject_duplicate_manifest_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OcrStoreError(f"OCR baseline manifest has duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_manifest_constant(value: str) -> object:
    raise OcrStoreError(f"OCR baseline manifest contains non-finite {value}")


def _manifest_artifact_hints(manifest_bytes: bytes) -> list[tuple[str, str]]:
    """Read only the role/path closure needed for a safe package scan.

    These values are not trusted as evidence.  The complete canonical manifest
    and every exact artifact byte are verified after the filesystem closure has
    been established.
    """
    try:
        payload = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_manifest_pairs,
            parse_constant=_reject_nonfinite_manifest_constant,
        )
    except OcrStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrStoreError("OCR baseline manifest is missing or corrupt") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        raise OcrStoreError("OCR baseline manifest has no artifact descriptors")
    hints: list[tuple[str, str]] = []
    roles: set[str] = set()
    paths: set[str] = set()
    folded_paths: set[str] = set()
    for descriptor in payload["artifacts"]:
        if not isinstance(descriptor, dict):
            raise OcrStoreError("OCR baseline artifact descriptor is invalid")
        role = descriptor.get("role")
        if not isinstance(role, str) or not role or role in roles:
            raise OcrStoreError("OCR baseline artifact roles must be unique")
        path = _strict_ocr_bundle_relative_path(
            descriptor.get("path"),
            f"OCR baseline {role} path",
        )
        if path == DEFAULT_MANIFEST_PATH:
            raise OcrStoreError("OCR baseline artifact conflicts with its manifest")
        if path in paths or path.casefold() in folded_paths:
            raise OcrStoreError("OCR baseline artifact paths must be unique")
        roles.add(role)
        paths.add(path)
        folded_paths.add(path.casefold())
        hints.append((role, path))
    if not hints:
        raise OcrStoreError("OCR baseline manifest has no artifact descriptors")
    return hints


def _ocr_baseline_media_type(role: str, logical_path: str) -> str:
    if role.endswith("_TEX") or logical_path.lower().endswith(".tex"):
        return "application/x-tex"
    if role.endswith("_PDF") or logical_path.lower().endswith(".pdf"):
        return "application/pdf"
    if role.startswith("COMPILE_LOG_") or logical_path.lower().endswith(".log"):
        return "text/plain"
    if logical_path.lower().endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def load_verified_ocr_baseline_bundle(
    store: OcrRunStore,
    run_id: str,
) -> VerifiedOcrBaselineBundle:
    """Load and recompute the immutable OCR-only baseline package.

    The manifest is only a commit marker, never a trusted claim.  This loader
    requires the directory to contain exactly the described files, checks the
    independent source hash from the run snapshot, and returns the verified
    bytes that an analysis caller must consume.
    """
    snapshot = store.load_snapshot(run_id)
    store.verify_source(run_id)
    artifacts_root = store.run_dir(run_id) / "artifacts"
    if not artifacts_root.is_dir() or _path_is_reparse_point(artifacts_root):
        raise OcrStoreError("OCR artifacts root is not a plain directory")
    package_root = artifacts_root / _OCR_BASELINE_PACKAGE_DIRECTORY
    return load_verified_ocr_baseline_directory(
        package_root,
        expected_source_sha256=snapshot.source_sha256,
    )


def load_verified_ocr_baseline_directory(
    package_root: str | Path,
    *,
    expected_source_sha256: str | None = None,
) -> VerifiedOcrBaselineBundle:
    """Freeze and verify one standalone OCR baseline package directory.

    This is the filesystem-neutral counterpart of
    :func:`load_verified_ocr_baseline_bundle`.  It is intended for the exact
    package copied to ``evidence/ocr-baseline`` when an OCR project is imported
    for analysis.  The manifest is read once, every described artifact is read
    once, and all later parsing consumes those frozen bytes.  Missing or extra
    entries, links/reparse points, non-canonical manifests, stale hashes, and
    contradictory OCR evidence fail closed.

    ``expected_source_sha256`` is an optional trust anchor owned by the caller;
    it is never inferred from an unverified manifest claim.
    """
    root = Path(package_root)
    if not root.is_dir() or _path_is_reparse_point(root):
        raise OcrStoreError("OCR baseline package is not available")
    manifest_relative = _strict_ocr_bundle_relative_path(
        DEFAULT_MANIFEST_PATH,
        "OCR baseline manifest path",
    )
    manifest_path = root.joinpath(*manifest_relative.split("/"))
    manifest_parent = root
    for part in manifest_relative.split("/")[:-1]:
        manifest_parent = manifest_parent / part
        if (
            not manifest_parent.is_dir()
            or _path_is_reparse_point(manifest_parent)
        ):
            raise OcrStoreError("OCR baseline manifest parent is not a plain directory")
    if not manifest_path.is_file() or _path_is_reparse_point(manifest_path):
        raise OcrStoreError("OCR baseline manifest is not available")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise OcrStoreError("OCR baseline manifest cannot be read") from exc
    hints = _manifest_artifact_hints(manifest_bytes)
    expected_files = {manifest_relative, *(path for _, path in hints)}
    actual_files, _ = _scan_ocr_bundle_tree(
        root,
        expected_files=expected_files,
    )
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        raise OcrStoreError(
            f"OCR baseline package is missing required files: {missing}"
        )

    artifact_bytes: dict[str, bytes] = {}
    for _, logical_path in hints:
        path = root.joinpath(*logical_path.split("/"))
        if not path.is_file() or _path_is_reparse_point(path):
            raise OcrStoreError(
                f"OCR baseline artifact is not a plain file: {logical_path}"
            )
        try:
            artifact_bytes[logical_path] = path.read_bytes()
        except OSError as exc:
            raise OcrStoreError(
                f"OCR baseline artifact cannot be read: {logical_path}"
            ) from exc
    try:
        manifest = verify_ocr_baseline_manifest(
            manifest_bytes,
            artifact_bytes,
            expected_source_sha256=expected_source_sha256,
        )
    except OcrBaselineManifestError as exc:
        raise OcrStoreError("OCR baseline package failed verification") from exc

    verified_payload = manifest.to_dict()
    descriptors = verified_payload["artifacts"]
    artifacts_by_role: dict[str, VerifiedOcrBaselineArtifact] = {}
    for descriptor in descriptors:
        role = str(descriptor["role"])
        logical_path = str(descriptor["path"])
        data = artifact_bytes[logical_path]
        artifacts_by_role[role] = VerifiedOcrBaselineArtifact(
            role=role,
            logical_path=logical_path,
            path=root.joinpath(*logical_path.split("/")),
            data=data,
            sha256=str(descriptor["sha256"]),
            media_type=_ocr_baseline_media_type(role, logical_path),
        )
    return VerifiedOcrBaselineBundle(
        root=root,
        manifest_path=manifest_path,
        manifest=manifest,
        artifacts_by_role=MappingProxyType(artifacts_by_role),
    )


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

    if normalized == "ocr-baseline-manifest":
        bundle = load_verified_ocr_baseline_bundle(store, run_id)
        return VerifiedOcrArtifact(
            normalized,
            bundle.manifest_path,
            configured_name,
            media_type,
            bundle.manifest.sha256,
        )

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
