import hashlib
import importlib.util
from pathlib import Path

import pytest

from latexstruct.core.provenance import (
    PROVENANCE_SCHEMA_VERSION,
    VERIFIED_SCOPE,
    make_provenance_record,
    parse_tex_provenance,
    sha256_lf_normalized_text,
    stamp_tex_provenance,
    strip_tex_provenance,
)


def _record(body: bytes, *, verified: bool = True):
    return make_provenance_record(
        body=body,
        verified=verified,
        verification_scope=VERIFIED_SCOPE,
        artifact_kind="test-tex",
        app_version="1.2.3",
        build_id="unknown",
        commit="unknown",
        prompt_version="3.6",
        source_sha256="a" * 64,
        raw_sha256="b" * 64,
        result_sha256=hashlib.sha256(body).hexdigest(),
    )


def test_stamp_is_idempotent_and_hashes_only_unstamped_body():
    body = b"\\documentclass{article}\n\\begin{document}\nBody\n\\end{document}\n"
    record = _record(body)

    stamped = stamp_tex_provenance(body, record)

    assert stamp_tex_provenance(stamped, record) == stamped
    assert strip_tex_provenance(stamped) == body
    assert parse_tex_provenance(stamped) == record
    assert record["schema_version"] == PROVENANCE_SCHEMA_VERSION
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize(
    ("encoding", "bom", "newline"),
    [
        ("latin-1", b"", "\r\n"),
        ("utf-16-le", b"\xff\xfe", "\n"),
    ],
)
def test_stamp_preserves_legacy_encoding_bom_newlines_and_body(encoding, bom, newline):
    text = newline.join(("\\documentclass{article}", "Caf\xe9.", ""))
    body = bom + text.encode(encoding)
    record = _record(body, verified=False)

    stamped = stamp_tex_provenance(body, record)

    assert stamped.startswith(bom)
    assert strip_tex_provenance(stamped) == body
    assert parse_tex_provenance(stamped)["verification_status"] == "UNVERIFIED"


def test_stamp_rejects_record_for_a_different_body():
    record = _record(b"first")
    with pytest.raises(ValueError, match="body_sha256"):
        stamp_tex_provenance(b"second", record)


@pytest.mark.parametrize(
    "magic",
    [b"%&xelatex\n", b"% !TeX program = xelatex\n% !TeX encoding = UTF-8\n"],
)
def test_stamp_keeps_tex_magic_directives_before_provenance(magic):
    body = magic + b"\\documentclass{article}\n"
    record = _record(body)

    stamped = stamp_tex_provenance(body, record)

    assert stamped.startswith(magic + b"% LaTeXStruct-Provenance-Begin\n")
    assert strip_tex_provenance(stamped) == body
    assert parse_tex_provenance(stamped) == record


def test_explicit_producer_and_exporter_identity_remain_distinct():
    body = b"\\documentclass{article}\n"
    raw = b"line one\r\nline two\r\n"
    producer = {
        "app_version": "1.2.4",
        "build_id": "1001",
        "commit": "a" * 40,
        "prompt_version": "3.6",
    }
    exporter = {
        "app_version": "1.2.5",
        "build_id": "1002",
        "commit": "b" * 40,
        "prompt_version": "not-used",
    }

    record = make_provenance_record(
        body=body,
        verified=True,
        verification_scope=VERIFIED_SCOPE,
        artifact_kind="test-tex",
        app_version="must-not-win",
        producer_identity=producer,
        exporter_identity=exporter,
        raw_sha256="0" * 64,
        raw_bytes_sha256=hashlib.sha256(raw).hexdigest(),
        raw_normalized_text_sha256=sha256_lf_normalized_text(raw),
        raw_artifact_role="analysis-input-tex",
        raw_artifact_path="LATEXSTRUCT-RAW-SOURCE.tex",
        raw_normalization_pipeline="decode-tex/newline-LF/encode-utf8",
    )

    # Legacy aliases remain available and now always describe the producer.
    assert record["app_version"] == producer["app_version"]
    assert record["build_id"] == producer["build_id"]
    assert record["commit"] == producer["commit"]
    assert record["prompt_version"] == producer["prompt_version"]
    assert record["producer_commit"] == producer["commit"]
    assert record["exporter_commit"] == exporter["commit"]
    assert record["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert record["raw_bytes_sha256"] == hashlib.sha256(raw).hexdigest()
    assert record["raw_normalized_text_sha256"] == hashlib.sha256(
        b"line one\nline two\n"
    ).hexdigest()


def test_lf_normalized_hash_is_reproducible_across_newline_encodings():
    assert sha256_lf_normalized_text(b"a\r\nb\r\n") == sha256_lf_normalized_text(
        b"a\nb\n"
    )
    assert hashlib.sha256(b"a\r\nb\r\n").hexdigest() != hashlib.sha256(
        b"a\nb\n"
    ).hexdigest()


def test_build_identity_renderer_requires_exact_ci_values():
    path = Path(__file__).resolve().parents[1] / "packaging" / "sync_build_identity.py"
    spec = importlib.util.spec_from_file_location("sync_build_identity_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    rendered = module.render_build_identity("A" * 40, "123456")
    assert 'BUILD_COMMIT = "' + "a" * 40 + '"' in rendered
    assert 'BUILD_ID = "123456"' in rendered
    with pytest.raises(ValueError, match="40-character"):
        module.render_build_identity("abc", "123456")
    with pytest.raises(ValueError, match="positive decimal"):
        module.render_build_identity("a" * 40, "run-1")
