# -*- coding: utf-8 -*-
"""Qwen 视觉 OCR 在线冒烟测试（密钥只从环境变量/本机凭据读取）。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.config import load_config
from latexstruct.core.ai import LLMClient, LLMError
from latexstruct.ocr import transcribe_page


def main() -> int:
    parser = argparse.ArgumentParser(description="调用当前 OCR 视觉模型转写一张 PNG/JPG")
    parser.add_argument("image", help="PNG/JPG 图片路径")
    args = parser.parse_args()

    path = Path(args.image)
    if not path.is_file():
        parser.error(f"图片不存在: {path}")

    role = load_config().to_ocr_config().role
    if not role.api_key:
        parser.error("未配置 OCR Key；请设置 DASHSCOPE_API_KEY 或 LATEXSTRUCT_OCR_KEY")

    try:
        result = transcribe_page(LLMClient(role), path.read_bytes(), 1)
    except LLMError as exc:
        print(f"FAIL: {exc}")
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
