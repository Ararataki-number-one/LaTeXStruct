# -*- coding: utf-8 -*-
"""OCR 真实实测：本机配置的视觉模型转写一页 PDF。

用法：python tools/e2e_ocr.py <pdf路径> [页码]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.config import load_config  # noqa: E402
from latexstruct.core.ai import LLMClient, LLMError  # noqa: E402
from latexstruct.ocr import OcrConfig, transcribe_pdf  # noqa: E402


def main():
    pdf = sys.argv[1] if len(sys.argv) > 1 else "tests/tmp_pdf/ocr_page.pdf"
    pages = sys.argv[2] if len(sys.argv) > 2 else ""
    cfg = load_config()
    ocfg = cfg.to_ocr_config()
    print(f"OCR 模型: {ocfg.role.model} · base_url: {ocfg.role.base_url}", flush=True)
    if not ocfg.role.api_key:
        print("未配置任何 API Key")
        return 1
    if pages:
        ocfg.pages = pages
    client = LLMClient(ocfg.role)
    try:
        result = transcribe_pdf(pdf, client, ocfg)
    except LLMError as e:
        print(f"转写失败: {e}")
        return 1
    print(f"页面: {result.pages} · 错误: {len(result.errors)} · usage: {result.usage}", flush=True)
    for err in result.errors[:3]:
        print(f"  页 {err.get('page')}: {err.get('reason')}", flush=True)
    print("--- 转写结果（前 1500 字符）---", flush=True)
    print(result.tex[:1500])
    return 0 if not result.errors else 1


if __name__ == "__main__":
    sys.exit(main())
