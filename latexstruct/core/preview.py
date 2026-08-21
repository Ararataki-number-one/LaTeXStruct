# -*- coding: utf-8 -*-
"""Honest compile-preview classification shared by artifact exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass

COMPILED = "COMPILED"
PARTIAL_COMPILED = "PARTIAL_COMPILED"
SOURCE_PREVIEW = "SOURCE_PREVIEW"
PREVIEW_STATUSES = frozenset({COMPILED, PARTIAL_COMPILED, SOURCE_PREVIEW})
PREVIEW_ARTIFACT_DIRECTORY = "LATEXSTRUCT-ARTIFACTS"


@dataclass(frozen=True)
class PreviewDescriptor:
    status: str
    filename: str
    is_latex_compilation: bool
    is_complete: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


_DESCRIPTORS = {
    COMPILED: PreviewDescriptor(
        status=COMPILED,
        filename="compiled.pdf",
        is_latex_compilation=True,
        is_complete=True,
    ),
    PARTIAL_COMPILED: PreviewDescriptor(
        status=PARTIAL_COMPILED,
        filename="partial-compiled.pdf",
        is_latex_compilation=True,
        is_complete=False,
    ),
    SOURCE_PREVIEW: PreviewDescriptor(
        status=SOURCE_PREVIEW,
        filename="source-preview.pdf",
        is_latex_compilation=False,
        is_complete=False,
    ),
}


def classify_compile_preview(*, ok: object, pdf_bytes: object) -> str:
    """Classify a preview without ever treating source rendering as compilation."""
    has_pdf = isinstance(pdf_bytes, (bytes, bytearray, memoryview)) and bool(pdf_bytes)
    if bool(ok) and has_pdf:
        return COMPILED
    if has_pdf:
        return PARTIAL_COMPILED
    return SOURCE_PREVIEW


def preview_descriptor(status: str) -> PreviewDescriptor:
    """Return the canonical filename and truth flags for a preview state."""
    try:
        return _DESCRIPTORS[str(status)]
    except KeyError as exc:
        raise ValueError(f"unknown compile preview status: {status!r}") from exc


def preview_artifact_path(status: str, sha256: str) -> str:
    """Return the collision-resistant package path for one compiled PDF."""
    descriptor = preview_descriptor(status)
    digest = str(sha256 or "").strip().lower()
    if status == SOURCE_PREVIEW or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError("compiled preview requires a valid SHA-256 digest")
    stem = descriptor.filename.removesuffix(".pdf")
    return f"{PREVIEW_ARTIFACT_DIRECTORY}/{stem}-{digest}.pdf"


def preview_storage_filename(status: str, sha256: str) -> str:
    """Return an attempt-safe private filename derived only from trusted inputs."""
    package_path = preview_artifact_path(status, sha256)
    return ".latexstruct-preview-" + package_path.rsplit("/", 1)[-1]
