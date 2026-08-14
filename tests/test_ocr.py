# -*- coding: utf-8 -*-
"""OCR 转写模块测试（Fake 视觉客户端，不依赖网络与 PDF 渲染库）。"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.ai import LLMError  # noqa: E402
from latexstruct.ocr import (  # noqa: E402
    OcrConfig,
    _clean_page_output,
    merge_book,
    parse_page_range,
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
        page = len(self.calls)
        if self.fail_page == page:
            raise LLMError("模拟失败")
        if page in self.pages:
            return self.pages[page]
        return f"```latex\nTheorem 1. Statement on page {page}.\n```"


def test_parse_page_range():
    assert parse_page_range("", 10) == list(range(1, 11))
    assert parse_page_range("1-3,7", 10) == [1, 2, 3, 7]
    assert parse_page_range("5-99", 10) == [5, 6, 7, 8, 9, 10]


def test_clean_page_output():
    assert _clean_page_output("```latex\nTheorem 1. X.\n```") == "Theorem 1. X."
    assert _clean_page_output("Theorem 1. X.") == "Theorem 1. X."


def test_merge_book():
    tex = merge_book(["% Page 1\nTheorem 1. X.", "% Page 2\nProof. Y."])
    assert tex.startswith("\\documentclass[11pt]{elegantbook}")
    assert "% Page 1" in tex and "% Page 2" in tex
    assert tex.rstrip().endswith("\\end{document}")
    assert "%=== PAGE BREAK ===" in tex


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
        assert len(client.calls) == 2
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
        assert "\\begin{theorem}[1]" in pr.result  # Stage B 结构化
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
