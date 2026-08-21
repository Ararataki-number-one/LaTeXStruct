import hashlib

import pytest

from latexstruct.core.provenance import (
    PROVENANCE_SCHEMA_VERSION,
    VERIFIED_SCOPE,
    make_provenance_record,
    parse_tex_provenance,
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
