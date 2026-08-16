# -*- coding: utf-8 -*-
"""OCR 转写模块测试（Fake 视觉客户端，不依赖网络与 PDF 渲染库）。"""

import io
import json
import os
import re
import shutil
import sys
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.ai import LLMClient, LLMError, RoleConfig  # noqa: E402
from latexstruct.ocr import (  # noqa: E402
    OcrConfig,
    _clean_page_output,
    encode_image,
    image_mime_type,
    merge_book,
    ocr_page_needs_retry,
    parse_page_range,
    pdf_document_info_bytes,
    pdf_page_count_bytes,
    select_page_interval,
    transcribe_images,
)


class FakeVisionClient:
    def __init__(self, pages=None, fail_page=None):
        self.pages = pages or {}
        self.fail_page = fail_page
        self.calls = []
        self.last_usage = {"total_tokens": 10}

    def chat_vision(self, system, user, data_uri):
        self.calls.append((system, user, data_uri[:30]))
        hit = re.search(r"第\s*(\d+)\s*页", user)
        page = int(hit.group(1)) if hit else len(self.calls)
        if self.fail_page == page:
            raise LLMError("模拟失败")
        if page in self.pages:
            return self.pages[page]
        return f"```latex\nTheorem 1. Statement on page {page}.\n```"


def test_parse_page_range():
    assert parse_page_range("", 10) == list(range(1, 11))
    assert parse_page_range("1-3,7", 10) == [1, 2, 3, 7]
    for bad in ("5-2", "abc", "99", "5-99", "1,,2", "0-2"):
        try:
            parse_page_range(bad, 10)
        except ValueError as exc:
            assert "页码" in str(exc)
        else:
            raise AssertionError(f"应拒绝页码范围：{bad}")


def test_page_interval_defaults_validates_bounds_and_caps_work():
    assert select_page_interval(8) == list(range(1, 9))
    assert select_page_interval(100, 88, 90, 10) == [88, 89, 90]
    for args in ((10, 0, 2, 10), (10, 3, 2, 10), (10, 2, 11, 10), (20, 1, 11, 10)):
        try:
            select_page_interval(*args)
        except ValueError as exc:
            assert "页" in str(exc)
        else:
            raise AssertionError(f"应拒绝页码范围：{args}")


def test_parse_page_range_rejects_oversized_interval_before_expansion():
    try:
        parse_page_range("1-999999999999999999999", 20, max_pages=10)
    except ValueError as exc:
        assert "1-20" in str(exc) or "最多" in str(exc)
    else:
        raise AssertionError("应拒绝巨大越界范围")


def test_pdf_page_count_bytes_reads_real_pdf_and_rejects_damage():
    class FakeDocument:
        needs_pass = False
        page_count = 2

        def __init__(self):
            self.closed = False

        def get_toc(self, simple=True):
            assert simple is True
            return [[1, "Introduction", 1], [2, "First result", 2]]

        def close(self):
            self.closed = True

    document = FakeDocument()

    class FakeFitz:
        @staticmethod
        def open(*, stream, filetype):
            assert filetype == "pdf"
            if stream.endswith(b"broken"):
                raise RuntimeError("damaged")
            return document

    with patch.dict(sys.modules, {"fitz": FakeFitz}):
        info = pdf_document_info_bytes(b"%PDF-1.7\nvalid")
        assert info == {
            "pages": 2,
            "outline": [
                {"level": 0, "title": "Introduction", "page": 1},
                {"level": 1, "title": "First result", "page": 2},
            ],
        }
        assert pdf_page_count_bytes(b"%PDF-1.7\nvalid") == 2
        try:
            pdf_page_count_bytes(b"%PDF-1.7\nbroken")
        except ValueError as exc:
            assert "损坏" in str(exc) or "无法读取" in str(exc)
        else:
            raise AssertionError("应拒绝损坏 PDF")
    assert document.closed is True


def test_clean_page_output():
    assert _clean_page_output("```latex\nTheorem 1. X.\n```") == "Theorem 1. X."
    assert _clean_page_output("Theorem 1. X.") == "Theorem 1. X."


def test_clean_page_output_normalizes_single_line_tagged_display():
    source = r"\[x+y=z\tag{5.6}\]"
    assert _clean_page_output(source) == (
        r"\begin{equation}x+y=z\tag{5.6}\end{equation}"
    )


def test_clean_page_output_moves_aligned_tag_after_environment():
    source = r"""\[
\begin{aligned}
a &= b \\
c &= d \tag{5.4}
\end{aligned}
\]"""
    expected = (
        "\\begin{equation}\n"
        "\\begin{aligned}\n"
        "a &= b \\\\\n"
        "c &= d " + "\n"
        "\\end{aligned}\n"
        "\\tag{5.4}\n"
        "\\end{equation}"
    )
    cleaned = _clean_page_output(source)
    assert cleaned == expected
    assert cleaned.index(r"\end{aligned}") < cleaned.index(r"\tag{5.4}")


def test_clean_page_output_leaves_ambiguous_or_untagged_math_unchanged():
    unchanged = (
        r"\[x+y=z\]",
        r"\[x\tag{1}+y\tag{2}\]",
        r"\[x+y\tag{1}",
        r"\begin{equation}x+y\tag{5.6}\end{equation}",
        "\\[\nx=y % \\tag{ignored-comment}\n\\]",
    )
    for source in unchanged:
        assert _clean_page_output(source) == source


def test_ocr_page_needs_retry_for_broken_or_illegal_bracket_displays():
    missing_first_close = r"""\[
\begin{aligned}
a &= b + c \tag{5.4}
\end{aligned}
The following display starts before the first one was closed.
\[
d &= e
\]"""
    assert ocr_page_needs_retry(missing_first_close)
    assert ocr_page_needs_retry(r"\[x=y")
    assert ocr_page_needs_retry(r"x=y\]")

    multiple_tags = _clean_page_output(r"\[x\tag{1}+y\tag{2}\]")
    assert multiple_tags == r"\[x\tag{1}+y\tag{2}\]"
    assert ocr_page_needs_retry(multiple_tags)


def test_ocr_page_retry_check_ignores_valid_math_and_comments():
    normalized = _clean_page_output(r"\[x=y\tag{1}\]")
    safe = (
        r"\[x=y\]",
        normalized,
        r"\begin{equation}x=y\tag{1}\end{equation}",
        r"\begin{align}x&=y\tag{1}\end{align}",
        "% inactive examples: \\[x=y\\tag{1)\n"
        r"\begin{equation}a=b\end{equation}",
    )
    for source in safe:
        assert not ocr_page_needs_retry(source)


def test_image_data_uri_uses_real_mime_type():
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 8
    jpeg = b"\xff\xd8\xff\xe0" + b"0" * 8
    assert image_mime_type(png) == "image/png"
    assert image_mime_type(jpeg) == "image/jpeg"
    assert encode_image(jpeg).startswith("data:image/jpeg;base64,")


def test_qwen_vision_openai_compatible_payload():
    """离线锁定 Qwen 官方的 image_url + Base64 Data URL 请求格式。"""
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "choices": [{"message": {"content": "```latex\nX\n```"}}],
                "usage": {"total_tokens": 7},
            }).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    role = RoleConfig(
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        model="qwen3-vl-flash",
        api_key="not-a-real-key",
        timeout=12,
    )
    image = encode_image(b"\x89PNG\r\n\x1a\n" + b"0" * 8)
    with patch("latexstruct.core.ai._open_no_redirect", fake_urlopen):
        client = LLMClient(role)
        assert "X" in client.chat_vision("system", "transcribe", image)

    assert captured["url"].endswith("/compatible-mode/v1/chat/completions")
    assert captured["authorization"] == "Bearer not-a-real-key"
    assert captured["timeout"] == 12
    payload = captured["payload"]
    assert payload["model"] == "qwen3-vl-flash"
    assert payload["enable_thinking"] is False
    assert "thinking" not in payload
    content = payload["messages"][1]["content"]
    assert content[0]["type"] == "image_url"
    assert content[0]["image_url"]["url"].startswith("data:image/png;base64,")
    assert content[1] == {"type": "text", "text": "transcribe"}


def test_provider_error_redacts_api_key():
    key = "not-a-real-runtime-secret"

    def unauthorized(request, timeout):
        body = json.dumps({"error": {"message": f"invalid credential {key}"}}).encode("utf-8")
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(body))

    role = RoleConfig(
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        model="qwen3-vl-flash",
        api_key=key,
    )
    try:
        with patch("latexstruct.core.ai._open_no_redirect", unauthorized):
            LLMClient(role).chat_vision("system", "user", "data:image/png;base64,AA==")
    except LLMError as exc:
        message = str(exc)
        assert "HTTP 401" in message
        assert key not in message
        assert "[已隐藏]" in message
    else:
        raise AssertionError("401 应抛出 LLMError")


def test_merge_book():
    tex = merge_book(["% Page 1\nTheorem 1. X.", "% Page 2\nProof. Y."])
    assert tex.startswith("\\documentclass[11pt]{article}")
    assert "% LaTeXStruct-OCR-Metadata:" in tex
    assert "% Page 1" in tex and "% Page 2" in tex
    assert tex.rstrip().endswith("\\end{document}")
    assert "%=== PAGE BREAK ===" in tex
    assert "\\clearpage" in tex


def test_merge_book_keeps_only_outline_nodes_from_selected_pages():
    from latexstruct.core.ocrstruct import parse_ocr_metadata

    tex = merge_book(
        ["% Page 88\n\\textbf{Selected method}"],
        outline=[
            {"level": 0, "title": "Introduction", "page": 1},
            {"level": 1, "title": "Selected method", "page": 88},
            {"level": 1, "title": "Later method", "page": 90},
        ],
    )
    metadata = parse_ocr_metadata(tex)
    assert metadata["pages"] == [88]
    assert metadata["outline"] == [
        {"level": 1, "title": "Selected method", "page": 88}
    ]


def _write_dummy_images(paths):
    import tempfile

    d = tempfile.mkdtemp(prefix="ls-ocr-", dir=os.path.dirname(os.path.abspath(__file__)))
    out = []
    for i, p in enumerate(paths):
        f = os.path.join(d, f"p{i}.png")
        with open(f, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + b"0" * 16)
        out.append(f)
    return out, d


def test_transcribe_images_and_errors():
    paths, d = _write_dummy_images(["a", "b"])
    try:
        client = FakeVisionClient(pages={1: "```latex\nPage one text.\n```"}, fail_page=2)
        result = transcribe_images(paths, client, OcrConfig())
        assert "Page one text" in result.tex
        assert len(result.errors) == 1 and result.errors[0]["page"] == 2
        assert len(client.calls) == 3  # 第 2 页自动重试 1 次
        # 视觉调用携带 system 规则
        assert "OCR" in client.calls[0][0] and "data:image/png;base64" in client.calls[0][2]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_transcribe_images_all_fail():
    paths, d = _write_dummy_images(["a"])
    try:
        client = FakeVisionClient(fail_page=1)
        result = transcribe_images(paths, client, OcrConfig())
        assert len(result.errors) == 1
        assert result.tex  # 空书稿骨架仍可输出
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_transcribe_all_fail_with_friendly_hint():
    # 不支持图片的模型（400）应得到友好提示
    class BadVision(FakeVisionClient):
        def chat_vision(self, system, user, data_uri):
            raise LLMError("视觉模型调用失败: HTTP Error 400: Bad Request")

    paths, d = _write_dummy_images(["a"])
    try:
        result = transcribe_images(paths, BadVision(), OcrConfig())
        assert len(result.errors) == 1
        assert "不支持图片输入" in result.errors[0]["reason"]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_stage_a_prompt_has_no_structure_demands():
    # 两阶段解耦：Stage A 提示词不得要求视觉模型做结构判断
    from latexstruct.ocr import OCR_SYSTEM_PROMPT

    assert "使用对应环境" not in OCR_SYSTEM_PROMPT
    assert "\\begin{theorem}" not in OCR_SYSTEM_PROMPT
    assert "\\begin{proof}" not in OCR_SYSTEM_PROMPT
    assert "不做任何结构判断" in OCR_SYSTEM_PROMPT


def test_ocr_pipeline_two_stages():
    paths, d = _write_dummy_images(["a"])
    try:
        client = FakeVisionClient(pages={1: "```latex\nTheorem 1. X.\n\nProof. Y.\n```"})
        from latexstruct.ocr import OcrConfig, transcribe_images

        ocr = transcribe_images(paths, client, OcrConfig())
        assert "\\begin{theorem}" not in ocr.tex  # Stage A 不加环境
        from latexstruct.core.pipeline import run_pipeline

        pr = run_pipeline(ocr.tex, mode="rule")
        assert pr.ok
        # 中性 article + 自动生成的无编号环境可安全保存源编号，且不会双编号。
        assert "\\begin{theorem}[1]" in pr.result
        assert "Theorem 1. X." not in pr.result
        assert "\\begin{proof}" in pr.result
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    import traceback

    tests = [
        (k, v)
        for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
