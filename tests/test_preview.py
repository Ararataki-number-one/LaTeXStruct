import pytest

from latexstruct.core.preview import (
    COMPILED,
    PARTIAL_COMPILED,
    SOURCE_PREVIEW,
    classify_compile_preview,
    preview_artifact_path,
    preview_descriptor,
    preview_storage_filename,
)


@pytest.mark.parametrize(
    ("ok", "pdf_bytes", "expected"),
    [
        (True, b"%PDF-real", COMPILED),
        (False, b"%PDF-partial", PARTIAL_COMPILED),
        (None, b"%PDF-partial", PARTIAL_COMPILED),
        (True, b"", SOURCE_PREVIEW),
        (False, b"", SOURCE_PREVIEW),
        (None, b"", SOURCE_PREVIEW),
    ],
)
def test_compile_preview_classification_is_evidence_based(ok, pdf_bytes, expected):
    assert classify_compile_preview(ok=ok, pdf_bytes=pdf_bytes) == expected


def test_source_preview_is_never_named_or_described_as_compiled_pdf():
    descriptor = preview_descriptor(SOURCE_PREVIEW)

    assert descriptor.filename == "source-preview.pdf"
    assert "compiled" not in descriptor.filename
    assert descriptor.is_latex_compilation is False
    assert descriptor.is_complete is False
    assert descriptor.as_dict()["status"] == SOURCE_PREVIEW


def test_compiled_and_partial_filenames_are_unambiguous():
    complete = preview_descriptor(COMPILED)
    partial = preview_descriptor(PARTIAL_COMPILED)

    assert complete.filename == "compiled.pdf"
    assert complete.is_latex_compilation is True
    assert complete.is_complete is True
    assert partial.filename == "partial-compiled.pdf"
    assert partial.is_latex_compilation is True
    assert partial.is_complete is False


def test_unknown_preview_status_fails_closed():
    with pytest.raises(ValueError, match="unknown compile preview status"):
        preview_descriptor("MAYBE_COMPILED")


def test_compiled_artifact_paths_are_content_addressed_and_private_storage_is_flat():
    digest = "a" * 64
    package_path = preview_artifact_path(COMPILED, digest)

    assert package_path == f"LATEXSTRUCT-ARTIFACTS/compiled-{digest}.pdf"
    assert preview_storage_filename(COMPILED, digest) == (
        f".latexstruct-preview-compiled-{digest}.pdf"
    )


@pytest.mark.parametrize("digest", ["", "0" * 63, "g" * 64])
def test_compiled_artifact_path_rejects_invalid_digests(digest):
    with pytest.raises(ValueError, match="valid SHA-256"):
        preview_artifact_path(COMPILED, digest)
