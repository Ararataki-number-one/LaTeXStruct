# -*- coding: utf-8 -*-
"""OCR 转写模块（M2）：PDF/图片 → 视觉模型逐页转写 LaTeX → 合并为 ElegantBook 书稿。

流程（对应设计文档 §12）：
  渲染页面 → 逐页视觉转写（模型可选，OpenAI 兼容视觉端点）→ 逐页校验/重试 →
  合并（统一 ElegantBook 导言区 + % Page N 标记）→ 输出 .tex，可继续送入结构化流水线。
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .core.ai import LLMClient, LLMError, RoleConfig

OCR_SYSTEM_PROMPT = """你是「数学文档 OCR→LaTeX 转写专家」。把给定书页图像完整、忠实地转写为 LaTeX 正文片段。

硬性要求：
1. 只输出 LaTeX 正文片段（不含 \\documentclass/\\begin{document}/导言区），用 ```latex 代码块包裹；
2. 完整保留页面所有内容与顺序：标题层级（\\chapter*{...}/\\section*{...} 等）、定理类内容
   使用对应环境（theorem/lemma/proposition/corollary/definition/example/remark，标题自带编号时
   保留编号文本并置于环境可选参数，如 \\begin{theorem}[1.7.2]）、证明用 \\begin{proof}...\\end{proof}；
3. 公式：行内用 \\(...\\)，展示用 \\[...\\] 或 equation/align；交换图用 tikz-cd；
   算法用 algorithm+algpseudocode；
4. 不增不减：不要臆造内容；无法辨认的符号用 \\textcolor{red}{[?]} 占位并加行内注释 % unsure；
5. 正确转义特殊字符 # $ % & _ { } ~ ^ \\；中英混排保持数学符号规范
   （\\mathbb{R}、\\mathcal{B}、\\operatorname{conv} 等；常见 OCR 误识修正：
   1R→\\mathbb{R}，S^n→\\mathbb{S}^n，cos v→\\operatorname{conv} X，<x,y>→\\langle x,y\\rangle）；
6. 页面中的插图：用 \\includegraphics[width=0.6\\linewidth]{images/page_<页码>_<序号>} 占位
   并加注释 % figure: <图中内容简述>；
7. 片段首行写 % Page <页码> 注释；长内容自然分段，段落之间空一行。"""

ELEGANTBOOK_PREAMBLE = """\\documentclass[11pt]{elegantbook}

\\usepackage{amsmath}
\\usepackage{amssymb}
\\usepackage{amsfonts}
\\usepackage{esint}
\\usepackage{stmaryrd}
\\usepackage{tcolorbox}
\\usepackage{booktabs}
\\usepackage{multirow}
\\usepackage{graphicx}
\\usepackage{tikz}
\\usetikzlibrary{cd}
\\usepackage{algorithm}
\\usepackage{algpseudocode}
\\usepackage{hyperref}
\\hypersetup{colorlinks=true, linkcolor=blue, urlcolor=cyan}
\\graphicspath{ {./images/} }

\\begin{document}
"""


@dataclass
class OcrConfig:
    role: RoleConfig = field(default_factory=RoleConfig)
    pages: str = ""  # 如 "1-5" 或 "1,3,7"；空 = 全部
    dpi: int = 150
    concurrency: int = 1
    retries: int = 1


@dataclass
class OcrResult:
    tex: str
    pages: List[int]
    errors: List[dict]
    usage: Dict


def parse_page_range(spec: str, total: int) -> List[int]:
    if not spec.strip():
        return list(range(1, total + 1))
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(set(p for p in out if 1 <= p <= total))


def render_pdf_pages(pdf_path: str, pages: List[int], dpi: int = 150):
    """返回 [(page_no, png_bytes)]。依赖 PyMuPDF（未安装时报错）。"""
    import fitz  # PyMuPDF

    doc = fitz.open(pdf_path)
    out = []
    try:
        for p in pages:
            page = doc[p - 1]
            pix = page.get_pixmap(dpi=dpi)
            out.append((p, pix.tobytes("png")))
    finally:
        doc.close()
    return out


def encode_image(png_bytes: bytes) -> str:
    b64 = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _clean_page_output(raw: str) -> str:
    text = raw.strip()
    m = re.search(r"```(?:latex)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    return text


def transcribe_page(client: LLMClient, png_bytes: bytes, page_no: int) -> str:
    user = f"请转写第 {page_no} 页。只输出 LaTeX 代码块。"
    raw = client.chat_vision(OCR_SYSTEM_PROMPT, user, encode_image(png_bytes))
    text = _clean_page_output(raw)
    if not text:
        raise LLMError(f"第 {page_no} 页转写为空")
    return f"% Page {page_no}\n{text}"


def transcribe_pdf(
    pdf_path: str,
    client: LLMClient,
    cfg: OcrConfig = None,
    progress=None,
) -> OcrResult:
    cfg = cfg or OcrConfig()
    pages = parse_page_range(cfg.pages, _pdf_page_count(pdf_path))
    rendered = render_pdf_pages(pdf_path, pages, cfg.dpi)
    chunks: List[str] = []
    errors: List[dict] = []
    usage: Dict = {}
    for i, (page_no, png) in enumerate(rendered):
        if progress:
            progress(i, len(rendered), page_no)
        last_err = None
        ok = False
        for _ in range(cfg.retries + 1):
            try:
                chunks.append(transcribe_page(client, png, page_no))
                ok = True
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
        if not ok:
            errors.append({"page": page_no, "reason": str(last_err)})
        for k, v in (client.last_usage or {}).items():
            if isinstance(v, (int, float)):
                usage[k] = usage.get(k, 0) + v
    if progress:
        progress(len(rendered), len(rendered), None)
    tex = merge_book(chunks)
    return OcrResult(tex=tex, pages=[p for p, _ in rendered], errors=errors, usage=usage)


def transcribe_images(image_paths: List[str], client: LLMClient, cfg: OcrConfig = None) -> OcrResult:
    cfg = cfg or OcrConfig()
    chunks = []
    errors = []
    usage: Dict = {}
    for i, path in enumerate(image_paths):
        png = open(path, "rb").read()
        try:
            chunks.append(transcribe_page(client, png, i + 1))
        except Exception as e:  # noqa: BLE001
            errors.append({"page": i + 1, "path": path, "reason": str(e)})
        for k, v in (client.last_usage or {}).items():
            if isinstance(v, (int, float)):
                usage[k] = usage.get(k, 0) + v
    return OcrResult(tex=merge_book(chunks), pages=list(range(1, len(image_paths) + 1)), errors=errors, usage=usage)


def merge_book(chunks: List[str]) -> str:
    parts = [ELEGANTBOOK_PREAMBLE.rstrip()]
    for i, c in enumerate(chunks):
        parts.append("")
        if i > 0:
            parts.append(f"%=== PAGE BREAK === 第 {i + 1} 段")
        parts.append(c.strip())
    parts.append("")
    parts.append("\\end{document}")
    return "\n".join(parts)


def _pdf_page_count(pdf_path: str) -> int:
    try:
        import fitz

        with fitz.open(pdf_path) as doc:
            return doc.page_count
    except ImportError:
        return 10**6
