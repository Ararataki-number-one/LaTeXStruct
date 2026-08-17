# -*- coding: utf-8 -*-
"""OCR 转写模块（M2，两阶段解耦）：PDF/图片 → 视觉模型逐页**忠实转写** LaTeX
（Stage A，不做任何结构判断）→ 合并为中性 article/book 书稿 → 交给结构化流水线
（Stage B：扫描→决策→补丁→校验，与"AI 只决策、Patch 负责改"核心理念统一）。

流程（对应设计文档 §12）：
  渲染页面 → 逐页视觉转写（模型可选，OpenAI 兼容视觉端点）→ 逐页校验/重试 →
  合并（中性导言区 + % Page N 标记）→ 输出原始 .tex → 用户选择固定排版模板 → run_pipeline。
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, List

from .core.ai import LLMClient, LLMError, RoleConfig
from .core.ocrstruct import encode_ocr_metadata, infer_document_kind
from .core.parser import mask_comments

OCR_SYSTEM_PROMPT = """你是「数学文档页面转写专家」。把给定书页图像**忠实**转写为 LaTeX 正文片段——
你的唯一任务是"看清楚"，**不做任何结构判断**（结构整理由后续引擎完成）。

硬性要求：
1. 只输出 LaTeX 正文片段（不含 \\documentclass、\\begin{document}、\\end{document} 或导言区），用 ```latex 代码块包裹；
2. 完整保留页面内容与顺序；标题行（如 "Theorem 2.7. ..."、"Proof. ..."、"1.1 Graphs"）
   按原样作为独立文本行转写——**不要**添加 theorem/lemma/proof/definition 环境，也不要使用
   \\chapter/\\section/\\subsection/\\subsubsection、\\tableofcontents、\\dotfill 等结构命令；
   不要把标题与正文合并改写（章节树与环境由后续引擎统一生成）；
3. 数学公式：行内用 \\(...\\)，展示用 \\[...\\] 或 $$...$$（仅转写公式本身，不改变其内容）；
4. 不增不减：不要臆造内容；无法辨认的符号用 \\textcolor{red}{[?]} 占位并加行内注释 % unsure；
5. 正确转义特殊字符 # $ % & _ { } ~ ^ \\；中英混排保持数学符号规范
   （\\mathbb{R}、\\mathcal{B}、\\operatorname{conv} 等；常见 OCR 误识修正：
   1R→\\mathbb{R}，S^n→\\mathbb{S}^n，cos v→\\operatorname{conv} X，<x,y>→\\langle x,y\\rangle）；
6. 页面中的插图：用 \\includegraphics[width=0.6\\linewidth]{images/page_<页码>_<序号>} 占位
   并加注释 % figure: <图中内容简述>；
7. 不要输出 % Page 页码注释（程序会在校验后唯一写入权威页码标记）；
   长内容自然分段，段落之间空一行。"""

OCR_PREAMBLE = """\\documentclass[11pt]{__DOCUMENT_CLASS__}

\\usepackage{amsmath}
\\usepackage{amssymb}
\\usepackage{amsfonts}
\\usepackage{bbm}
\\usepackage{esint}
\\usepackage{stmaryrd}
\\usepackage{tcolorbox}
\\usepackage{booktabs}
\\usepackage{multirow}
\\usepackage{graphicx}
\\usepackage{caption}
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


def select_page_interval(
    total: int,
    start_page: int | None = None,
    end_page: int | None = None,
    max_pages: int | None = None,
) -> List[int]:
    """校验并返回 1-based 连续 PDF 页码。

    页码必须完整落在源 PDF 内；不再静默截断越界输入，避免用户以为处理了
    请求范围之外的页面。``max_pages`` 用于服务端限制单次 OCR 的意外费用。
    """
    if not isinstance(total, int) or isinstance(total, bool) or total < 1:
        raise ValueError("PDF 没有可处理的页面")
    start = 1 if start_page is None else start_page
    end = total if end_page is None else end_page
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (start, end)):
        raise ValueError("起始页和结束页必须是整数")
    if start < 1:
        raise ValueError("起始页必须从 1 开始")
    if end > total:
        raise ValueError(f"结束页不能超过 PDF 总页数 {total}")
    if start > end:
        raise ValueError("起始页不能大于结束页")
    count = end - start + 1
    if max_pages is not None and count > max_pages:
        raise ValueError(f"单次最多处理 {max_pages} 页，请缩小页码范围")
    return list(range(start, end + 1))


def parse_page_range(spec: str, total: int, max_pages: int | None = None) -> List[int]:
    """解析旧版逗号/横线页码格式，并严格拒绝越界或超大范围。"""
    if not isinstance(spec, str) or len(spec) > 200:
        raise ValueError("页码范围输入过长")
    if not spec.strip():
        return select_page_interval(total, max_pages=max_pages)
    if not isinstance(total, int) or isinstance(total, bool) or total < 1:
        raise ValueError("PDF 没有可处理的页面")

    selected = set()
    parts = spec.split(",")
    if any(not part.strip() for part in parts):
        raise ValueError("页码范围格式无效，请使用 1-5 或 1,3,7")
    for raw_part in parts:
        part = raw_part.strip()
        match = re.fullmatch(r"(\d+)\s*(?:-\s*(\d+))?", part)
        if match is None:
            raise ValueError("页码范围格式无效，请使用 1-5 或 1,3,7")
        try:
            start = int(match.group(1))
            end = int(match.group(2) or match.group(1))
        except ValueError:
            raise ValueError("页码范围格式无效，请使用 1-5 或 1,3,7") from None
        if start < 1 or end > total:
            raise ValueError(f"页码范围必须完整位于 1-{total} 页内")
        if start > end:
            raise ValueError("页码范围起始页不能大于结束页")
        interval_count = end - start + 1
        if max_pages is not None and interval_count > max_pages:
            raise ValueError(f"单次最多处理 {max_pages} 页，请缩小页码范围")
        selected.update(range(start, end + 1))
        if max_pages is not None and len(selected) > max_pages:
            raise ValueError(f"单次最多处理 {max_pages} 页，请缩小页码范围")

    if not selected:
        raise ValueError(f"页码范围不在文档 1-{total} 页内")
    return sorted(selected)


def render_pdf_pages(pdf_path: str, pages: List[int], dpi: int = 150):
    """返回 [(page_no, png_bytes)]。依赖 PyMuPDF（未安装时报错）。"""
    return list(iter_pdf_pages(pdf_path, pages, dpi))


def iter_pdf_pages(pdf_path: str, pages: List[int], dpi: int = 150):
    """逐页渲染，避免大 PDF 一次把所有 PNG 堆进内存。"""
    import fitz  # PyMuPDF

    doc = fitz.open(pdf_path)
    try:
        for p in pages:
            page = doc[p - 1]
            pix = page.get_pixmap(dpi=dpi)
            yield p, pix.tobytes("png")
    finally:
        doc.close()


def pdf_document_info_bytes(pdf_bytes: bytes) -> dict:
    """读取页数与 PDF 书签；书签只作为结构元数据，不执行其中任何文本。"""
    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise LLMError("缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试") from None
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception:
        raise ValueError("PDF 文件损坏或无法读取，请重新导出后再试") from None
    try:
        if doc.needs_pass:
            raise ValueError("暂不支持加密 PDF，请先移除打开密码")
        total = doc.page_count
        if total < 1:
            raise ValueError("PDF 没有可处理的页面")
        outline = []
        try:
            for level, title, page, *_rest in doc.get_toc(simple=True):
                title = str(title or "").strip()
                if title and int(page) > 0:
                    outline.append({
                        "level": max(0, int(level) - 1),
                        "title": title[:300],
                        "page": int(page),
                    })
        except (AttributeError, TypeError, ValueError):
            # 没有书签不影响 OCR；后续仅少一层确定性结构依据。
            outline = []
        return {"pages": total, "outline": outline[:500]}
    finally:
        doc.close()


def pdf_page_count_bytes(pdf_bytes: bytes) -> int:
    """从已上传的 PDF 字节安全读取总页数，不渲染页面。"""
    return int(pdf_document_info_bytes(pdf_bytes)["pages"])


def image_mime_type(image_bytes: bytes) -> str:
    """根据文件签名判断 MIME，避免把 JPG 错标成 image/png。"""
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    raise LLMError("仅支持 PNG 或 JPEG 图片")


def encode_image(image_bytes: bytes) -> str:
    b64 = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{image_mime_type(image_bytes)};base64,{b64}"


_DISPLAY_MATH_RE = re.compile(r"(?<!\\)\\\[(.*?)(?<!\\)\\\]", re.S)
_TAG_MARKER_RE = re.compile(r"(?<!\\)\\tag(?![A-Za-z@])")
_TAG_RE = re.compile(r"(?<!\\)\\tag\s*\{(?P<label>[^{}\r\n]+)\}")
_DISPLAY_SAFETY_TOKEN_RE = re.compile(
    r"(?<!\\)\\(?P<delimiter>[\[\]])|(?<!\\)\\(?P<tag>tag)(?![A-Za-z@])"
)
_PAGE_MARKER_RE = re.compile(r"(?im)^\s*%\s*Page\s+\d+\s*(?:\r?\n|$)")
_FORBIDDEN_STAGE_A_STRUCTURE_RE = re.compile(
    r"\\documentclass(?:\s*\[[^\]\r\n]*\])?\s*\{"
    r"|\\(?:part|chapter|section|subsection|subsubsection|paragraph|subparagraph)\*?"
    r"\s*(?:\[[^\]\r\n]*\]\s*)?\{"
    r"|\\(?:tableofcontents|addcontentsline|frontmatter|mainmatter|backmatter)\b"
    r"|\\(?:begin|end)\s*\{\s*(?:"
    r"theorem\*?|lemma\*?|proposition\*?|corollary\*?|definition\*?|"
    r"remark\*?|example\*?|exercise\*?|proof\*?|claim\*?|conjecture\*?|"
    r"axiom\*?|problem\*?|solution\*?|notation\*?|observation\*?|fact\*?|document"
    r")\s*\}",
    re.I,
)


def _normalize_tagged_display_math(text: str) -> str:
    r"""把唯一明确带 tag 的 ``\[...\]`` 保守改写为合法 equation。"""

    def replace(match: re.Match) -> str:
        body = match.group(1)
        # 嵌套 display 起点说明边界有歧义；任何额外/畸形 tag 记号也都不处理。
        if re.search(r"(?<!\\)\\\[", body):
            return match.group(0)
        # 注释中的示例命令不是活动 tag。mask_comments 保留长度，后续仍可用
        # 匹配位置从原始正文提取/移除命令，避免把注释 tag 意外激活。
        active_body = mask_comments(body)
        markers = list(_TAG_MARKER_RE.finditer(active_body))
        tags = list(_TAG_RE.finditer(active_body))
        if (
            len(markers) != 1
            or len(tags) != 1
            or markers[0].start() != tags[0].start()
            or not tags[0].group("label").strip()
        ):
            return match.group(0)
        tag = tags[0].group(0)
        body_without_tag = body[: tags[0].start()] + body[tags[0].end() :]
        closing_separator = "\n" if "\n" in body else ""
        # tag 统一置于整个 body 之后；若有 aligned，自然落在 \end{aligned} 之后。
        return (
            "\\begin{equation}"
            + body_without_tag
            + tag
            + closing_separator
            + "\\end{equation}"
        )

    return _DISPLAY_MATH_RE.sub(replace, text)


def _clean_page_output(raw: str) -> str:
    text = raw.strip()
    m = re.search(r"```(?:latex)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    # 页码只能由 transcribe_page 在校验后写一次。视觉模型即使
    # 忽略提示词自行输出 marker，也不得覆盖/制造假页码。
    text = _PAGE_MARKER_RE.sub("", text).strip()
    return _normalize_tagged_display_math(text)


def _has_forbidden_stage_a_structure(text: str) -> bool:
    """Stage A 只允许转录；标记模型擅自生成的结构命令。

    非空转写不能因为模型没有完全遵守 Stage A 格式而被整页丢弃。
    调用方应将这种页面标为需审阅，同时保留模型返回的全部文本。
    """
    return bool(_FORBIDDEN_STAGE_A_STRUCTURE_RE.search(mask_comments(text)))


def ocr_page_needs_review(text: str) -> bool:
    """检测页面是否需要人工确认，但不丢弃已识别文本。"""
    return _has_forbidden_stage_a_structure(text)


def ocr_page_needs_retry(text: str) -> bool:
    r"""检测明确的 OCR display 语法错误，供逐页重试提示使用。

    这里只处理可确定的 ``\[``/``\]`` 顺序与闭合错误，以及后处理后仍
    位于 bracket display 内的活动 ``\tag``。注释被等长屏蔽；普通 AMS
    equation/align 环境不参与该窄检查。
    """
    active = mask_comments(text)
    in_display = False
    for token in _DISPLAY_SAFETY_TOKEN_RE.finditer(active):
        delimiter = token.group("delimiter")
        if delimiter == "[":
            if in_display:  # display 尚未闭合又遇到下一个起点
                return True
            in_display = True
        elif delimiter == "]":
            if not in_display:  # 无对应起点的 display 终点
                return True
            in_display = False
        elif in_display:  # \tag 在 \[...\] 中始终非法
            return True
    return in_display


def transcribe_page(client: LLMClient, png_bytes: bytes, page_no: int) -> str:
    user = f"请转写第 {page_no} 页。只输出 LaTeX 代码块。"
    try:
        raw = client.chat_vision(OCR_SYSTEM_PROMPT, user, encode_image(png_bytes))
    except LLMError as e:
        msg = str(e)
        lower = msg.lower()
        if any(token in lower for token in ("http 401", "http error 401", "http 403", "http error 403")):
            raise LLMError(
                f"{msg}｜请确认 API Key 与 Base URL 来自同一地域/工作空间，且该 Key 有视觉模型权限"
            ) from None
        if "http 429" in lower or "http error 429" in lower:
            raise LLMError(f"{msg}｜已触发限流或额度不足，请稍后重试或检查账户额度") from None
        if any(token in lower for token in (
            "http 400", "http error 400", "http 404", "http error 404", "image", "multimodal",
        )):
            raise LLMError(
                f"{msg}｜当前模型可能不支持图片输入；Qwen 视觉 Flash 的正式标识是 "
                "qwen3.7-flash（推荐）或 qwen3-vl-flash"
            ) from None
        raise
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
    with open(pdf_path, "rb") as pdf_file:
        info = pdf_document_info_bytes(pdf_file.read())
    tex = merge_book(chunks, outline=info.get("outline"))
    return OcrResult(tex=tex, pages=[p for p, _ in rendered], errors=errors, usage=usage)


def transcribe_images(
    image_paths: List[str], client: LLMClient, cfg: OcrConfig = None, progress=None
) -> OcrResult:
    cfg = cfg or OcrConfig()
    chunks = []
    errors = []
    usage: Dict = {}
    for i, path in enumerate(image_paths):
        if progress:
            progress(i, len(image_paths), i + 1)
        with open(path, "rb") as f:
            png = f.read()
        last_err = None
        for _ in range(cfg.retries + 1):
            try:
                chunks.append(transcribe_page(client, png, i + 1))
                last_err = None
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
        if last_err is not None:
            errors.append({"page": i + 1, "path": path, "reason": str(last_err)})
        for k, v in (client.last_usage or {}).items():
            if isinstance(v, (int, float)):
                usage[k] = usage.get(k, 0) + v
    if progress:
        progress(len(image_paths), len(image_paths), None)
    return OcrResult(tex=merge_book(chunks), pages=list(range(1, len(image_paths) + 1)), errors=errors, usage=usage)


def _chunk_pages(chunks: List[str]) -> List[int]:
    pages = []
    for chunk in chunks:
        match = re.search(r"(?m)^\s*%\s*Page\s+(\d+)\s*$", chunk)
        if match:
            pages.append(int(match.group(1)))
    return pages


def _chunks_have_toc(chunks: List[str]) -> bool:
    text = "\n".join(chunks)
    return bool(
        re.search(
            r"(?im)^\s*(?:\\(?:section|chapter)\*?\s*\{\s*)?contents\s*\}?\s*$",
            text,
        )
        or len(re.findall(r"\\dotfill\b", text)) >= 3
    )


def merge_book(chunks: List[str], outline: List[dict] = None) -> str:
    """合并逐页片段，并携带不可执行的 PDF 大纲元数据。

    文档类仅由书签与明确 Chapter 标题决定；不再无条件套用 elegantbook，
    避免没有 chapter 时出现 0.1 以及内置定理计数冲突。
    """
    document_kind = infer_document_kind(outline, chunks)
    selected_pages = _chunk_pages(chunks)
    selected_page_set = set(selected_pages)
    selected_outline = []
    for item in list(outline or []):
        try:
            page = int(item.get("page", 0))
        except (AttributeError, TypeError, ValueError):
            continue
        if not selected_page_set or page in selected_page_set:
            selected_outline.append(item)
    preamble = OCR_PREAMBLE.replace("__DOCUMENT_CLASS__", document_kind)
    metadata = encode_ocr_metadata(
        selected_outline,
        document_kind,
        selected_pages,
        _chunks_have_toc(chunks),
    )
    parts = [preamble.rstrip(), metadata]
    for i, c in enumerate(chunks):
        parts.append("")
        if i > 0:
            parts.append("\\clearpage")
            parts.append(f"%=== PAGE BREAK === 第 {i + 1} 段")
        parts.append(c.strip())
    parts.append("")
    parts.append("\\end{document}")
    return "\n".join(parts)


def ocr_pipeline(pdf_path: str, client: LLMClient, cfg: OcrConfig = None,
                 mode: str = "ai", pipeline_kwargs=None) -> Dict:
    """两阶段：A 视觉忠实转写（不做结构判断）→ B 结构化流水线（扫描→决策→补丁→校验）。

    返回 {"ocr": OcrResult, "pipeline": PipelineResult}。
    """
    from .core.pipeline import run_pipeline

    ocr = transcribe_pdf(pdf_path, client, cfg)
    pr = run_pipeline(ocr.tex, mode=mode, **(pipeline_kwargs or {}))
    return {"ocr": ocr, "pipeline": pr}


def _pdf_page_count(pdf_path: str) -> int:
    try:
        import fitz

        with fitz.open(pdf_path) as doc:
            return doc.page_count
    except ImportError:
        raise LLMError("缺少 PDF 渲染组件 PyMuPDF，请重新安装完整版本后重试") from None
