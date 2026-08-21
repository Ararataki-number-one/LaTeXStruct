from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest

from latexstruct.core.ai import LLMError
from latexstruct.ocr import (
    _page_request,
    pdf_page_equation_tag_regions,
    transcribe_page_result,
)


def _region(label: str = "15") -> dict:
    return {
        "evidence_id": "p14-equation-tag-1",
        "label_hint": label,
        "bbox_normalized": [0.848, 0.20, 0.883, 0.22],
        "source": "isolated_right_margin_pdf_word_geometry",
    }


class _StaticVisionClient:
    last_usage = {}

    def __init__(self, output: str):
        self.output = output
        self.users: list[str] = []

    def chat_vision_bytes(self, _system: str, user: str, _image: bytes) -> str:
        self.users.append(user)
        return self.output


def test_equation_tag_evidence_is_in_request_and_requires_one_active_tag():
    request = _page_request(
        14,
        None,
        "",
        reference_equation_tag_regions=[_region()],
    )
    payload = json.loads(request[request.index("{"):])
    assert payload["publisher_equation_tag_evidence"][0]["label_hint"] == "15"
    assert "图像" in payload["equation_tag_policy"]
    assert r"\tag{15}" in payload["equation_tag_policy"]
    assert r"\tag{(15)}" in payload["equation_tag_policy"]

    client = _StaticVisionClient(
        r"\begin{equation} x=1 \tag{15} \end{equation}"
    )
    result = transcribe_page_result(
        client,
        b"\x89PNG\r\n\x1a\npixels",
        14,
        reference_equation_tag_regions=[_region()],
    )
    assert r"\tag{15}" in result.tex
    assert result.quality_flags == [{
        "type": "equation_tag_integrity_evidence",
        "status": "source_geometry_and_active_match",
        "needs_review": False,
        "evidence_id": "p14-equation-tag-1",
        "label": "15",
        "bbox_normalized": [0.848, 0.20, 0.883, 0.22],
        "source": "isolated_right_margin_pdf_word_geometry",
        "verifier": "pdf_geometry_plus_full_page_visual_and_active_latex",
    }]


def test_parenthesized_printed_source_accepts_unparenthesized_active_tag():
    result = transcribe_page_result(
        _StaticVisionClient(
            r"\begin{equation} x=1 \tag{15} \end{equation}"
        ),
        b"\x89PNG\r\n\x1a\npixels",
        14,
        reference_equation_tag_regions=[_region("(15)")],
    )

    assert r"\tag{15}" in result.tex
    assert result.quality_flags[0]["label"] == "15"


@pytest.mark.parametrize(
    "output",
    [
        r"\begin{equation} x=1 \end{equation}",
        r"\begin{equation} x=1 \tag{16} \end{equation}",
        r"\begin{equation} x=1 \tag{15} \tag{15} \end{equation}",
        "% \\tag{15}\n" + r"\begin{equation} x=1 \end{equation}",
        r"ordinary text \tag{15}",
        r"escaped command \\tag{15}",
        r"\begin{equation} x=1 \tag{(15)} \end{equation}",
    ],
)
def test_missing_wrong_duplicate_or_commented_equation_tag_fails_closed(output):
    with pytest.raises(LLMError, match="公式编号.*不一致") as caught:
        transcribe_page_result(
            _StaticVisionClient(output),
            b"\x89PNG\r\n\x1a\npixels",
            14,
            reference_equation_tag_regions=[_region()],
        )
    assert "不会依据文字层自动补写" in caught.value.retry_instruction


def test_equation_tags_in_swapped_source_order_fail_closed():
    second_region = {
        **_region("16"),
        "evidence_id": "p14-equation-tag-2",
        "bbox_normalized": [0.848, 0.30, 0.883, 0.32],
    }

    with pytest.raises(LLMError, match="公式编号.*不一致"):
        transcribe_page_result(
            _StaticVisionClient(
                r"\begin{align} x&=1 \tag{16} \\ y&=2 \tag{15} \end{align}"
            ),
            b"\x89PNG\r\n\x1a\npixels",
            14,
            reference_equation_tag_regions=[_region("15"), second_region],
        )


def test_equation_tags_in_source_order_are_accepted():
    second_region = {
        **_region("16"),
        "evidence_id": "p14-equation-tag-2",
        "bbox_normalized": [0.848, 0.30, 0.883, 0.32],
    }

    result = transcribe_page_result(
        _StaticVisionClient(
            r"\begin{align} x&=1 \tag{15} \\ y&=2 \tag{16} \end{align}"
        ),
        b"\x89PNG\r\n\x1a\npixels",
        14,
        reference_equation_tag_regions=[_region("15"), second_region],
    )

    assert [flag["label"] for flag in result.quality_flags] == ["15", "16"]


def test_illegal_bracket_display_tag_is_normalized_before_integrity_check():
    result = transcribe_page_result(
        _StaticVisionClient(r"\[x=1 \tag{15}\]"),
        b"\x89PNG\r\n\x1a\npixels",
        14,
        reference_equation_tag_regions=[_region()],
    )

    assert result.tex == "% Page 14\n" + r"\begin{equation}x=1 \tag{15}\end{equation}"
    assert result.quality_flags[0]["status"] == "source_geometry_and_active_match"


def test_tag_inside_align_is_accepted_as_an_ams_display_tag():
    result = transcribe_page_result(
        _StaticVisionClient(
            r"\begin{align} x&=1 \tag{15} \\ y&=2 \end{align}"
        ),
        b"\x89PNG\r\n\x1a\npixels",
        14,
        reference_equation_tag_regions=[_region()],
    )

    assert r"\tag{15}" in result.tex
    assert result.quality_flags[0]["status"] == "source_geometry_and_active_match"


def test_pdf_equation_tag_geometry_accepts_only_isolated_body_right_margin_words():
    class _Rect:
        x0 = 0.0
        y0 = 0.0
        x1 = 600.0
        y1 = 800.0
        width = 600.0
        height = 800.0

    class _Page:
        rect = _Rect()

        def get_text(self, _kind, sort=True):
            assert sort is True
            return [
                (510.0, 200.0, 530.0, 212.0, "(15)", 1, 0, 0),
                # Far right, but not isolated on its PDF line.
                (450.0, 300.0, 490.0, 312.0, "value", 2, 0, 0),
                (510.0, 300.0, 530.0, 312.0, "(16)", 2, 0, 1),
                # Isolated but not in the right-margin tag column.
                (300.0, 400.0, 320.0, 412.0, "(17)", 3, 0, 0),
                # Running-header height is outside the body gate.
                (510.0, 10.0, 530.0, 22.0, "(18)", 4, 0, 0),
            ]

    class _Document:
        page_count = 1
        closed = False

        def __getitem__(self, index):
            assert index == 0
            return _Page()

        def close(self):
            self.closed = True

    document = _Document()

    class _Fitz:
        @staticmethod
        def open(_path):
            return document

    with patch.dict(sys.modules, {"fitz": _Fitz}):
        regions = pdf_page_equation_tag_regions("book.pdf", 1)

    assert document.closed is True
    assert regions == [{
        "evidence_id": "p1-equation-tag-1",
        "label_hint": "15",
        "bbox_points": [510.0, 200.0, 530.0, 212.0],
        "bbox_normalized": [0.85, 0.25, 0.883333, 0.265],
        "source": "isolated_right_margin_pdf_word_geometry",
    }]


def test_pdf_equation_tag_geometry_failure_is_not_silently_an_empty_inventory():
    class _Page:
        def get_text(self, *_args, **_kwargs):
            raise OSError("broken text layer")

    class _Document:
        page_count = 1
        closed = False

        def __getitem__(self, _index):
            return _Page()

        def close(self):
            self.closed = True

    document = _Document()

    class _Fitz:
        @staticmethod
        def open(_path):
            return document

    with patch.dict(sys.modules, {"fitz": _Fitz}):
        with pytest.raises(RuntimeError, match="公式编号文字几何提取失败"):
            pdf_page_equation_tag_regions("book.pdf", 1)

    assert document.closed is True
