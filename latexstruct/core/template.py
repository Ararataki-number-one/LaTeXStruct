# -*- coding: utf-8 -*-
"""可审阅、可撤销的排版模板。

已经结构化的普通 TeX 默认保持原排版；OCR 重建或用户明确选择时才转换为
ElegantBook。模型只判断正文结构，模板转换始终是独立、可审阅的确定性补丁。
``professional-handout`` 仅保留给既有项目读取。
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from .faithfulbook import (
    FAITHFULBOOK_STYLE_MARKER,
    render_faithfulbook_style,
    resolve_faithfulbook_layout,
)
from .parser import mask_comments, parse_latex
from .patch import PendingOp
from .scanner import BOX_ENVS

DOC_CLASS_LINE_RE = re.compile(r"^\s*\\documentclass(?:\[[^\]]*\])?\s*\{[^{}]*\}\s*$")
DOC_CLASS_CAPTURE_RE = re.compile(
    r"^\s*\\documentclass(?:\[[^\]]*\])?\s*\{\s*([^{}]+?)\s*\}\s*$"
)
BEGIN_DOCUMENT_RE = re.compile(r"^\s*\\begin\s*\{document\}\s*$")
TABLEOFCONTENTS_RE = re.compile(r"^\s*\\tableofcontents\s*$")
PAGE_BREAK_COMMAND_RE = re.compile(r"^\s*\\(?:clearpage|newpage)\s*$")
FRONTMATTER_RE = re.compile(r"^\s*\\frontmatter\s*$")
MAINMATTER_RE = re.compile(r"^\s*\\mainmatter\s*$")
USEPACKAGE_RE = re.compile(r"\\usepackage(?:\[[^\]]*\])?\s*\{([^{}]+)\}")
GEOMETRY_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{geometry\}\s*$")
CTEX_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{ctex\}\s*$")
# elegantbook 自带 tcolorbox[many]/geometry/ctex/\circled；书稿再次定义会冲突
TCOLORBOX_LINE_RE = re.compile(r"^\s*\\usepackage(?:\[[^\]]*\])?\{tcolorbox\}\s*$")
CIRCLED_LINE_RE = re.compile(r"^\s*\\newcommand\*?\\circled\b.*$")
CHAPTER_RE = re.compile(r"^\d+\s+\S")
TOC_ENTRY_SUFFIX_RE = re.compile(r"\s+\d+\s*$")
CONTENTS_TITLE_RE = re.compile(r"^contents$", re.I)
LOCAL_CONTENTS_MARKER_RE = re.compile(
    r"^\s*%\s*LaTeXStruct-Local-Contents\s*$", re.I,
)
PRINTED_PAGE_MARKER_PREFIX_RE = re.compile(
    r"^\s*%\s*LaTeXStruct-Printed-Page\s*:", re.I,
)
PRINTED_PAGE_MARKER_RE = re.compile(
    r"^\s*%\s*LaTeXStruct-Printed-Page\s*:\s*(?P<page>\d+)\s*$", re.I,
)
MAX_PRINTED_PAGE = 999_999
SECTION_COMMAND_LINE_RE = re.compile(
    r"^(?P<indent>\s*)\\(?P<cmd>section|subsection|subsubsection)"
    r"(?P<rest>\*?\s*\{)"
)
ELEGANT_NEW_THEOREM_RE = re.compile(r"\\elegantnewtheorem\s*\{([^{}]+)\}")

PROFESSIONAL_HANDOUT = "professional-handout"
ELEGANTBOOK = "elegantbook"
FAITHFULBOOK = "faithfulbook"
PRESERVE_SOURCE = ""
PROFESSIONAL_MARKER = "% LaTeXStruct template: professional-handout begin"
ELEGANTBOOK_MARKER = "% LaTeXStruct template: elegantbook v4.7"
ELEGANTBOOK_TITLE_MARKER = "% LaTeXStruct: clean ElegantBook title page"
SUPPORTED_HANDOUT_CLASSES = {
    "article", "report", "book", "ctexart", "ctexrep", "ctexbook",
}
ELEGANTBOOK_SOURCE_CLASSES = frozenset({*SUPPORTED_HANDOUT_CLASSES, ELEGANTBOOK})
ARTICLE_CLASSES = {"article", "ctexart"}
ELEGANTBOOK_BUILTIN_ENVS = frozenset({
    "theorem", "definition", "postulate", "axiom", "corollary", "lemma",
    "proposition",
})
ELEGANTBOOK_EXTRA_ENVS = {
    "conjecture": ("Conjecture", "猜想", "thmstyle", "conj"),
    "claim": ("Claim", "断言", "thmstyle", "clm"),
    "fact": ("Fact", "事实", "thmstyle", "fact"),
    "remark": ("Remark", "注", "thmstyle", "rem"),
    "observation": ("Observation", "观察", "thmstyle", "obs"),
    "note": ("Note", "注记", "thmstyle", "note"),
    "example": ("Example", "例", "defstyle", "ex"),
    "problem": ("Problem", "问题", "defstyle", "prob"),
    "question": ("Question", "问题", "defstyle", "ques"),
    "exercise": ("Exercise", "练习", "defstyle", "exer"),
}

TEMPLATE_PRESETS = (
    {
        "id": PRESERVE_SOURCE,
        "label": "保持原排版（推荐）",
        "description": "保留原 documentclass、宏包、章节层级和自定义环境，只整理明确的正文结构。",
        "recommended_for": "tex",
    },
    {
        "id": FAITHFULBOOK,
        "label": "原书近似 · 出版书籍",
        "description": "OCR 书稿专用双面书籍版式；保持源页分页，生成结构化页眉和章内目录。",
        "recommended_for": "ocr",
    },
    {
        "id": ELEGANTBOOK,
        "label": "ElegantBook 专业讲义",
        "description": "明确需要统一书籍版式时使用；会适配文档类、章节层级、目录与定理色块。",
        "recommended_for": "ocr",
    },
)
_TEMPLATE_LABELS = {
    PRESERVE_SOURCE: "保持原排版",
    PROFESSIONAL_HANDOUT: "专业讲义（旧项目）",
    **{item["id"]: item["label"] for item in TEMPLATE_PRESETS},
}


def list_template_presets() -> List[dict]:
    """返回不含用户数据的公开模板选项。"""
    return [dict(item) for item in TEMPLATE_PRESETS]


def normalize_template_id(template: str | None) -> str:
    value = str(template or "").strip()
    if value not in _TEMPLATE_LABELS:
        raise ValueError("未知排版模板；请选择保持原排版、faithfulbook 或 ElegantBook")
    return value


def template_label(template: str | None) -> str:
    return _TEMPLATE_LABELS.get(str(template or "").strip(), "固定模板")


def _loaded_packages(text: str) -> set[str]:
    active = mask_comments(text)
    packages: set[str] = set()
    for match in USEPACKAGE_RE.finditer(active):
        packages.update(part.strip().lower() for part in match.group(1).split(",") if part.strip())
    return packages


def _escape_latex_text(value: str) -> str:
    mapping = {
        "\\": r"\textbackslash{}",
        "{": r"\{",
        "}": r"\}",
        "#": r"\#",
        "$": r"\$",
        "%": r"\%",
        "&": r"\&",
        "_": r"\_",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    cleaned = "".join(char for char in str(value or "") if char >= " " and char != "\x7f")
    return "".join(mapping.get(char, char) for char in cleaned.strip()[:160])


def _has_custom_environment(text: str, env: str) -> bool:
    active = mask_comments(text)
    escaped = re.escape(env)
    return bool(re.search(
        rf"\\(?:newtheorem|newtcbtheorem|newenvironment|renewenvironment|declaretheorem|newmdtheoremenv)\*?"
        rf"(?:\[[^\]]*\])?\s*\{{{escaped}\}}",
        active,
    ) or re.search(rf"\\(?:tcolorboxenvironment|elegantnewtheorem)\s*\{{{escaped}\}}", active))


def uses_elegantbook_class(text: str) -> bool:
    """只识别活动的、独立的 ElegantBook 文档类声明。"""
    active = mask_comments(text)
    return any(
        (match := DOC_CLASS_CAPTURE_RE.match(line)) is not None
        and match.group(1).strip().lower() == ELEGANTBOOK
        for line in active.split("\n")
    )


def uses_faithfulbook_style(text: str) -> bool:
    """Return true only for the deterministic inline faithfulbook style layer."""
    return FAITHFULBOOK_STYLE_MARKER in text


def _handout_title_block() -> List[str]:
    return [
        r"\makeatletter",
        r"\renewcommand{\maketitle}{%",
        r"  \begin{titlepage}",
        r"  \thispagestyle{empty}",
        r"  \centering",
        r"  \vspace*{0.13\textheight}",
        r"  {\color{LSBlue}\rule{\linewidth}{1.6pt}\par}",
        r"  \vspace{1.8cm}",
        r"  {\Huge\sffamily\bfseries\color{LSNavy}\@title\par}",
        r"  \vspace{0.9cm}",
        r"  \ifx\@author\@empty\else{\Large\sffamily\color{LSMuted}\@author\par}\fi",
        r"  \vfill",
        r"  \ifx\@date\@empty\else{\large\sffamily\color{LSMuted}\@date\par}\fi",
        r"  \vspace{1.2cm}",
        r"  {\color{LSBlue}\rule{0.34\linewidth}{0.7pt}\par}",
        r"  \vspace{0.5cm}",
        r"  {\small\sffamily\color{LSMuted}LaTeXStruct · Structured Edition\par}",
        r"  \end{titlepage}%",
        r"}",
        r"\makeatother",
    ]


def _direct_cover_lines(title: str, chinese: bool) -> List[str]:
    subtitle = "专业讲义" if chinese else "Professional Lecture Notes"
    return [
        r"\begin{titlepage}",
        r"\thispagestyle{empty}",
        r"\centering",
        r"\vspace*{0.13\textheight}",
        r"{\color{LSBlue}\rule{\linewidth}{1.6pt}\par}",
        r"\vspace{1.8cm}",
        rf"{{\Huge\sffamily\bfseries\color{{LSNavy}} {title}\par}}",
        r"\vspace{0.9cm}",
        rf"{{\Large\sffamily\color{{LSMuted}} {subtitle}\par}}",
        r"\vfill",
        r"{\color{LSBlue}\rule{0.34\linewidth}{0.7pt}\par}",
        r"\vspace{0.5cm}",
        r"{\small\sffamily\color{LSMuted}LaTeXStruct · Structured Edition\par}",
        r"\end{titlepage}",
    ]


def _elegantbook_clean_title_block() -> List[str]:
    """Replace ElegantBook's example-image fallback with a self-contained title page."""
    return [
        ELEGANTBOOK_TITLE_MARKER,
        r"\makeatletter",
        r"\renewcommand{\maketitle}{%",
        r"  \hypersetup{pageanchor=false}%",
        r"  \begin{titlepage}",
        r"  \thispagestyle{empty}",
        r"  \centering",
        r"  \vspace*{0.16\textheight}",
        r"  {\color{structurecolor}\rule{\textwidth}{1.4pt}\par}",
        r"  \vspace{2.2cm}",
        r"  {\Huge\sffamily\bfseries\color{structurecolor}\@title\par}",
        r"  \ifcsname @subtitle\endcsname",
        r"    \vspace{0.9cm}{\Large\sffamily\color{darkgray}\@subtitle\par}",
        r"  \fi",
        r"  \vfill",
        r"  \ifx\@author\@empty\else{\large\sffamily\@author\par}\vspace{0.5cm}\fi",
        r"  \ifx\@date\@empty\else{\color{gray}\@date\par}\fi",
        r"  \vspace{1.2cm}",
        r"  {\color{structurecolor}\rule{0.28\textwidth}{0.8pt}\par}",
        r"  \end{titlepage}%",
        r"  \hypersetup{pageanchor=true}%",
        r"}",
        r"\makeatother",
    ]


def _build_professional_handout_ops(
    text: str,
    context: Dict[str, str] | None = None,
) -> Tuple[List[PendingOp], List[dict]]:
    """插入固定专业讲义样式；所有插入仍通过 PendingOp 参与可逆校验。"""
    if PROFESSIONAL_MARKER in text:
        return [], [{"line": 1, "reason": "专业讲义模板已存在，未重复插入"}]

    lines = text.split("\n")
    class_match = next((DOC_CLASS_CAPTURE_RE.match(line) for line in lines if DOC_CLASS_CAPTURE_RE.match(line)), None)
    if class_match is None:
        return [], [{"line": 1, "reason": "未找到独立的 \\documentclass 行，已保留原排版"}]
    document_class = class_match.group(1).strip().lower()
    if document_class not in SUPPORTED_HANDOUT_CLASSES:
        return [], [{
            "line": 1,
            "reason": f"文档类 {document_class} 不在专业讲义安全名单中，已保留原排版",
        }]
    begin_index = next((index for index, line in enumerate(lines) if BEGIN_DOCUMENT_RE.match(line)), None)
    if begin_index is None:
        return [], [{"line": 1, "reason": "未找到独立的 \\begin{document} 行，已保留原排版"}]

    packages = _loaded_packages(text)
    preamble = [PROFESSIONAL_MARKER]
    if "geometry" in packages:
        preamble.append(r"\geometry{a4paper,top=22mm,bottom=24mm,left=24mm,right=24mm,headheight=18pt}")
    else:
        preamble.append(
            r"\usepackage[a4paper,top=22mm,bottom=24mm,left=24mm,right=24mm,headheight=18pt]{geometry}"
        )
    if "xcolor" not in packages:
        preamble.append(r"\usepackage{xcolor}")
    if "tcolorbox" not in packages:
        preamble.append(r"\usepackage[most]{tcolorbox}")
    else:
        preamble.append(r"\tcbuselibrary{breakable,skins}")

    standard_class = document_class in {"article", "report", "book"}
    heading_style_safe = standard_class and "sectsty" not in packages
    if heading_style_safe and "titlesec" not in packages:
        preamble.append(r"\usepackage{titlesec}")

    preamble.extend([
        r"\definecolor{LSNavy}{HTML}{17324D}",
        r"\definecolor{LSBlue}{HTML}{2166C2}",
        r"\definecolor{LSTeal}{HTML}{168C8C}",
        r"\definecolor{LSAmber}{HTML}{C47A15}",
        r"\definecolor{LSMuted}{HTML}{5B677A}",
        r"\definecolor{LSPaper}{HTML}{F7FAFC}",
        r"\setlength{\parindent}{2em}",
        r"\setlength{\parskip}{0.22em plus 0.08em}",
        r"\setlength{\emergencystretch}{2em}",
        r"\setlength{\headheight}{18pt}",
    ])

    if heading_style_safe:
        if document_class in {"report", "book"}:
            preamble.extend([
                r"\titleformat{\chapter}[display]",
                r"  {\normalfont\huge\bfseries\color{LSNavy}}",
                r"  {\filleft\Large\color{LSBlue}\chaptername\ \thechapter}",
                r"  {0.5ex}{\titlerule\vspace{1ex}\filright}",
                r"  [\vspace{0.5ex}\titlerule]",
                r"\titlespacing*{\chapter}{0pt}{-12pt}{28pt}",
            ])
        preamble.extend([
            r"\titleformat{\section}",
            r"  {\Large\sffamily\bfseries\color{LSNavy}}",
            r"  {\colorbox{LSBlue}{\color{white}\strut\thesection}}{0.75em}{}",
            r"\titleformat{\subsection}",
            r"  {\large\sffamily\bfseries\color{LSBlue}}{\thesubsection}{0.65em}{}",
            r"\titlespacing*{\section}{0pt}{2.3ex plus 0.6ex}{1.1ex}",
            r"\titlespacing*{\subsection}{0pt}{1.8ex plus 0.4ex}{0.8ex}",
        ])

    preamble.extend([
        r"\makeatletter",
        r"\def\ps@latexstructhandout{%",
        r"  \def\@oddhead{\vbox{\hbox to\textwidth{\small\sffamily\color{LSMuted}\rightmark\hfil\color{LSBlue}\thepage}\vskip3pt\hrule height0.4pt}}%",
        r"  \def\@evenhead{\vbox{\hbox to\textwidth{\small\sffamily\color{LSBlue}\thepage\hfil\color{LSMuted}\leftmark}\vskip3pt\hrule height0.4pt}}%",
        r"  \def\@oddfoot{}\def\@evenfoot{}%",
        r"}",
        r"\makeatother",
        r"\pagestyle{latexstructhandout}",
    ])

    style_groups = {
        "LSBlue": ("theorem", "lemma", "proposition", "corollary", "conjecture", "claim", "fact"),
        "LSTeal": ("definition", "example", "observation"),
        "LSAmber": ("problem", "question", "exercise"),
        "LSMuted": ("remark", "note"),
    }
    custom_theorem_stack = bool(packages & {"mdframed", "ntheorem", "theorem", "thmtools"})
    safe_box_envs = [] if custom_theorem_stack else [
        (env, color)
        for color, envs in style_groups.items()
        for env in envs
        if not _has_custom_environment(text, env)
    ]
    if safe_box_envs:
        preamble.extend([
            r"\newcommand{\LSHandoutStyleEnv}[2]{%",
            r"  \ifcsname #1\endcsname",
            r"    \tcolorboxenvironment{#1}{enhanced,breakable,colback=#2!4!white,colframe=#2!72!black,boxrule=0.7pt,arc=1.6mm,left=2.4mm,right=2.4mm,top=1.6mm,bottom=1.6mm,before skip=8pt,after skip=8pt}%",
            r"  \fi",
            r"}",
            r"\AtBeginDocument{%",
        ])
        preamble.extend(rf"  \LSHandoutStyleEnv{{{env}}}{{{color}}}" for env, color in safe_box_envs)
        preamble.append(r"}")

    has_title = bool(re.search(r"\\title\s*\{", mask_comments(text)))
    has_maketitle = bool(re.search(r"\\maketitle\b", mask_comments(text)))
    if has_maketitle or has_title:
        preamble.extend(_handout_title_block())
    preamble.append("% LaTeXStruct template: professional-handout end")

    ops = [PendingOp("insert_line", begin_index, new=line) for line in preamble]
    notes = [{
        "line": begin_index + 1,
        "reason": "已应用固定 A4 讲义版式、标题层级与页眉页码",
    }]
    if safe_box_envs:
        notes.append({
            "line": begin_index + 1,
            "reason": f"已为 {len(safe_box_envs)} 类标准定理/定义/例题环境启用一致色块",
        })
    elif custom_theorem_stack:
        notes.append({
            "line": begin_index + 1,
            "reason": "检测到自定义定理排版体系，已保留其原有视觉样式",
        })
    if standard_class and not heading_style_safe:
        notes.append({
            "line": begin_index + 1,
            "reason": "检测到既有章节样式包，已保留其标题格式以避免冲突",
        })

    if has_title and not has_maketitle:
        ops.append(PendingOp("insert_line", begin_index + 1, new=r"\maketitle"))
        notes.append({"line": begin_index + 1, "reason": "已使用原文标题生成专业标题页"})
    elif has_maketitle:
        notes.append({"line": begin_index + 1, "reason": "已将原有标题页换为专业讲义样式"})
    else:
        raw_title = str((context or {}).get("title") or "").strip()
        if raw_title and raw_title != "未命名项目":
            escaped_title = _escape_latex_text(raw_title)
            chinese = bool(re.search(r"[\u3400-\u9fff]", raw_title + text[:4000]))
            cover = _direct_cover_lines(escaped_title, chinese)
            ops.extend(PendingOp("insert_line", begin_index + 1, new=line) for line in cover)
            notes.append({"line": begin_index + 1, "reason": "已使用项目名称生成专业标题页"})
        else:
            notes.append({"line": begin_index + 1, "reason": "项目没有可用标题，未臆造标题页"})

    toc_index = next((index for index, line in enumerate(lines) if TABLEOFCONTENTS_RE.match(line)), None)
    if toc_index is not None:
        following = next((line for line in lines[toc_index + 1:] if line.strip()), "")
        if not PAGE_BREAK_COMMAND_RE.match(following):
            ops.append(PendingOp("insert_line", toc_index + 1, new=r"\clearpage"))
            notes.append({"line": toc_index + 1, "reason": "目录后已分页，避免目录与正文标题挤在一起"})
    return ops, notes


def _non_box_sections(doc):
    out = []
    box_ivs = [(r[1], r[3]) for r in doc.env_ranges if r[0] in BOX_ENVS]
    for s in doc.sections:
        off = s.span.start_off
        if any(bs <= off <= es for bs, es in box_ivs):
            continue
        out.append(s)
    return out


def _build_elegantbook_ops(
    text: str,
    context: Dict[str, str] | None = None,
) -> Tuple[List[PendingOp], List[dict]]:
    """把已确认的结构适配为固定 ElegantBook，而不猜测标题或目录边界。"""
    ops: List[PendingOp] = []
    notes: List[dict] = []
    doc = parse_latex(text)
    lines = text.split("\n")
    class_item = next(
        ((i, match) for i, line in enumerate(lines)
         if (match := DOC_CLASS_CAPTURE_RE.match(line)) is not None),
        None,
    )
    if class_item is None:
        return [], [{
            "line": 1,
            "status": "rejected",
            "reason": "未找到独立的 \\documentclass 行，已阻止模板转换",
        }]

    dc_idx, class_match = class_item
    original_class = class_match.group(1).strip().lower()
    if original_class not in ELEGANTBOOK_SOURCE_CLASSES:
        return [], [{
            "line": dc_idx + 1,
            "status": "rejected",
            "reason": (
                f"文档类 {original_class} 不在 ElegantBook 安全转换名单中，"
                "已阻止模板转换"
            ),
        }]
    active = mask_comments(text)
    chinese = bool(re.search(r"[\u3400-\u9fff]", active))
    has_title = bool(re.search(r"\\title\s*\{", active))
    has_maketitle = bool(re.search(r"\\maketitle\b", active))
    raw_title = str((context or {}).get("title") or "").strip()
    will_have_title = has_title or bool(raw_title and raw_title != "未命名项目")
    has_cover = bool(re.search(r"\\cover\s*\{", active))
    has_custom_maketitle = bool(re.search(
        r"\\(?:re)?newcommand\*?\s*\{?\\maketitle\}?",
        active,
    ))
    options = "lang=cn,scheme=chinese,11pt" if chinese else "lang=en,11pt"
    class_line = rf"\documentclass[{options}]{{elegantbook}}"
    if lines[dc_idx] != class_line:
        ops.append(PendingOp("replace_line", dc_idx + 1, old=lines[dc_idx], new=class_line))
    notes.append({
        "line": dc_idx + 1,
        "reason": "正式成品已固定为 ElegantBook v4.7；正文与公式不由模板改写",
    })

    # ElegantBook 已统一加载这些排版组件；重复加载常造成选项冲突。
    for i, line in enumerate(lines):
        if (
            GEOMETRY_LINE_RE.match(line)
            or CTEX_LINE_RE.match(line)
            or TCOLORBOX_LINE_RE.match(line)
            or CIRCLED_LINE_RE.match(line)
        ):
            ops.append(PendingOp("delete_line", i + 1, old=line))

    begin_index = next(
        (index for index, line in enumerate(lines) if BEGIN_DOCUMENT_RE.match(line)),
        None,
    )
    if begin_index is None:
        return [], [{
            "line": 1,
            "status": "rejected",
            "reason": "未找到独立的 \\begin{document} 行，已阻止模板转换",
        }]

    # article -> book 是文档类语义适配，不是标题猜测。所有已解析层级整体上移，
    # 因而不会出现 book 类中只有 section 时的 0.1 编号。
    shifted = 0
    sections = _non_box_sections(doc)
    if original_class in ARTICLE_CLASSES and not any(section.cmd == "chapter" for section in sections):
        command_map = {
            "section": "chapter",
            "subsection": "section",
            "subsubsection": "subsection",
        }
        for section in sections:
            target = command_map.get(section.cmd)
            if not target:
                continue
            line_no = section.span.start_line
            old = lines[line_no - 1]
            match = SECTION_COMMAND_LINE_RE.match(old)
            if match is None or match.group("cmd") != section.cmd:
                continue
            new = (
                match.group("indent") + "\\" + target + match.group("rest")
                + old[match.end():]
            )
            ops.append(PendingOp("replace_line", line_no, old=old, new=new))
            shifted += 1
        if shifted:
            notes.append({
                "line": 1,
                "reason": f"文章型标题层级已整体上移 {shifted} 处，避免 ElegantBook 出现 0.1 章节",
            })

    # 补齐 ElegantBook 未内置、但 LaTeXStruct 会识别的常用定理环境。输出实际
    # 使用其无编号星号环境，把原书编号作为标题参数保留下来，杜绝双编号。
    preamble_lines: List[str] = []
    if ELEGANTBOOK_MARKER not in text:
        preamble_lines.append(ELEGANTBOOK_MARKER)
    for env, (english, chinese_name, style, prefix) in ELEGANTBOOK_EXTRA_ENVS.items():
        if _has_custom_environment(text, env):
            continue
        title = chinese_name if chinese else english
        declaration = rf"\elegantnewtheorem{{{env}}}{{{title}}}{{{style}}}{{{prefix}}}"
        if declaration not in text:
            preamble_lines.append(declaration)
    if (
        will_have_title
        and not has_cover
        and not has_custom_maketitle
        and ELEGANTBOOK_TITLE_MARKER not in text
    ):
        preamble_lines.extend(_elegantbook_clean_title_block())
    ops.extend(PendingOp("insert_line", begin_index, new=line) for line in preamble_lines)
    if preamble_lines:
        notes.append({
            "line": begin_index + 1,
            "reason": "已补齐固定的 ElegantBook 定理色块定义；原书编号仍按原文显示",
        })

    if not has_title and raw_title and raw_title != "未命名项目":
        ops.append(PendingOp(
            "insert_line", begin_index,
            new=rf"\title{{{_escape_latex_text(raw_title)}}}",
        ))
        has_title = True
        notes.append({"line": begin_index + 1, "reason": "已使用项目名称生成 ElegantBook 标题页"})
    if has_title and not has_maketitle:
        ops.append(PendingOp("insert_line", begin_index + 1, new=r"\maketitle"))

    toc_index = next(
        (index for index, line in enumerate(lines) if TABLEOFCONTENTS_RE.match(line)),
        None,
    )
    if toc_index is not None:
        active_lines = active.split("\n")
        has_frontmatter = any(FRONTMATTER_RE.match(line) for line in active_lines[:toc_index])
        has_mainmatter = any(MAINMATTER_RE.match(line) for line in active_lines[toc_index + 1:])
        if not has_frontmatter:
            ops.append(PendingOp("insert_line", toc_index, new=r"\frontmatter"))
        following_item = next(
            ((index, line) for index, line in enumerate(lines[toc_index + 1:], toc_index + 1)
             if line.strip()),
            None,
        )
        if following_item is None or not PAGE_BREAK_COMMAND_RE.match(following_item[1]):
            ops.append(PendingOp("insert_line", toc_index + 1, new=r"\clearpage"))
            mainmatter_anchor = toc_index + 1
        else:
            mainmatter_anchor = following_item[0] + 1
        if not has_mainmatter:
            ops.append(PendingOp("insert_line", mainmatter_anchor, new=r"\mainmatter"))
        notes.append({
            "line": toc_index + 1,
            "reason": "真实目录使用前置页码，正文从第 1 页重新编号；目录条目由 LaTeX 二次编译生成",
        })
    else:
        notes.append({
            "line": 1,
            "reason": "未凭数字标题臆造目录；只有 OCR 大纲或原文件明确目录时才使用 \\tableofcontents",
        })
    return ops, notes


def _build_faithfulbook_ops(
    text: str,
    context: Dict[str, str] | None = None,
) -> Tuple[List[PendingOp], List[dict]]:
    """Apply a compact, two-sided OCR book style without rewriting source text.

    The source-page ``\\clearpage`` commands and ``% Page`` markers are not
    edited.  Running heads are generated from chapter/section marks, never by
    copying OCR body lines into the preamble.
    """
    if uses_faithfulbook_style(text):
        return [], [{"line": 1, "reason": "faithfulbook 模板已存在，未重复插入"}]

    try:
        layout = resolve_faithfulbook_layout(context)
        style_lines = render_faithfulbook_style(layout).split("\n")
    except (RuntimeError, ValueError) as exc:
        return [], [{
            "line": 1,
            "status": "rejected",
            "reason": f"faithfulbook 布局无效，已保留原排版：{exc}",
        }]

    doc = parse_latex(text)
    lines = text.split("\n")
    class_item = next(
        ((index, match) for index, line in enumerate(lines)
         if (match := DOC_CLASS_CAPTURE_RE.match(line)) is not None),
        None,
    )
    if class_item is None:
        return [], [{
            "line": 1,
            "status": "rejected",
            "reason": "未找到独立的 \\documentclass 行，已阻止 faithfulbook 转换",
        }]
    dc_idx, class_match = class_item
    original_class = class_match.group(1).strip().lower()
    if original_class not in SUPPORTED_HANDOUT_CLASSES:
        return [], [{
            "line": dc_idx + 1,
            "status": "rejected",
            "reason": (
                f"文档类 {original_class} 不在 faithfulbook 安全转换名单中，"
                "已保留原排版"
            ),
        }]
    begin_index = next(
        (index for index, line in enumerate(lines) if BEGIN_DOCUMENT_RE.match(line)),
        None,
    )
    if begin_index is None:
        return [], [{
            "line": 1,
            "status": "rejected",
            "reason": "未找到独立的 \\begin{document} 行，已阻止 faithfulbook 转换",
        }]

    target_class = "ctexbook" if original_class.startswith("ctex") else "book"
    class_options = f"{layout.body_font_pt}pt,twoside,openany"
    if target_class == "ctexbook":
        class_options = "UTF8," + class_options
    class_line = rf"\documentclass[{class_options}]{{{target_class}}}"
    ops: List[PendingOp] = []
    notes: List[dict] = []
    if lines[dc_idx] != class_line:
        ops.append(PendingOp("replace_line", dc_idx + 1, old=lines[dc_idx], new=class_line))

    # Insert the reviewed asset inline so a single-TEX export remains complete.
    ops.extend(PendingOp("insert_line", begin_index, new=line) for line in style_lines)
    local_contents_markers = [
        line_no for line_no, line in enumerate(lines, start=1)
        if LOCAL_CONTENTS_MARKER_RE.match(line)
    ]
    for line_no in local_contents_markers:
        ops.append(PendingOp(
            "replace_line", line_no, old=lines[line_no - 1],
            new=r"\LSChapterContents",
        ))

    # The OCR structure pass may provide a chapter-start printed-page marker
    # only when outline and global-contents evidence agree.  Consume the
    # numeric-only marker deterministically; malformed or implausible values
    # remain inert comments and can never become executable TeX.
    printed_page_markers: List[Tuple[int, int]] = []
    invalid_printed_page_markers: List[int] = []
    for line_no, line in enumerate(lines, start=1):
        if not PRINTED_PAGE_MARKER_PREFIX_RE.match(line):
            continue
        match = PRINTED_PAGE_MARKER_RE.match(line)
        if match is None:
            invalid_printed_page_markers.append(line_no)
            continue
        printed_page = int(match.group("page"))
        if not 1 <= printed_page <= MAX_PRINTED_PAGE:
            invalid_printed_page_markers.append(line_no)
            continue
        printed_page_markers.append((line_no, printed_page))
        ops.append(PendingOp(
            "replace_line", line_no, old=line,
            new=rf"\setcounter{{page}}{{{printed_page}}}",
        ))

    sections = _non_box_sections(doc)
    article_source = original_class in ARTICLE_CLASSES
    shifted = 0
    chapter_nodes = []
    if article_source and not any(section.cmd == "chapter" for section in sections):
        command_map = {
            "section": "chapter",
            "subsection": "section",
            "subsubsection": "subsection",
        }
        for section in sections:
            target = command_map.get(section.cmd)
            if not target:
                continue
            line_no = section.span.start_line
            old = lines[line_no - 1]
            match = SECTION_COMMAND_LINE_RE.match(old)
            if match is None or match.group("cmd") != section.cmd:
                continue
            new = (
                match.group("indent") + "\\" + target + match.group("rest")
                + old[match.end():]
            )
            ops.append(PendingOp("replace_line", line_no, old=old, new=new))
            shifted += 1
            if target == "chapter" and not section.starred:
                chapter_nodes.append(section)
    else:
        chapter_nodes.extend(
            section for section in sections
            if section.cmd == "chapter" and not section.starred
        )

    # Book semantics, not OCR page text, own the displayed pagination: front
    # matter uses roman numerals and the first numbered chapter restarts at 1.
    # ``openany`` makes these transitions clear the current page without
    # inventing an empty recto page, so source-page boundaries stay intact.
    pagination_added = False
    first_front_page_emptied = False
    if chapter_nodes:
        active_lines = mask_comments(text).split("\n")
        first_chapter_line = min(node.span.start_line for node in chapter_nodes)
        if not any(FRONTMATTER_RE.match(line) for line in active_lines):
            ops.append(PendingOp("insert_line", begin_index + 1, new=r"\frontmatter"))
            pagination_added = True
        # Do not strip the first numbered chapter's page style when the book
        # starts directly with chapter 1.  If genuine source material (or an
        # explicit physical-page break) precedes that chapter, arm the
        # template's one-shot first-shipout empty style instead.  Comments and
        # pagination-state commands alone are not treated as a title page.
        front_page_ignored_re = re.compile(
            r"^\s*\\(?:frontmatter|mainmatter|LSMainMatter|"
            r"pagestyle\s*\{[^{}]*\}|thispagestyle\s*\{[^{}]*\})\s*$"
        )
        source_before_first_chapter = active_lines[
            begin_index + 1:first_chapter_line - 1
        ]
        if any(
            line.strip() and not front_page_ignored_re.match(line)
            for line in source_before_first_chapter
        ):
            ops.append(PendingOp(
                "insert_line", begin_index + 1, new=r"\LSFirstPageEmpty",
            ))
            first_front_page_emptied = True
        if not any(MAINMATTER_RE.match(line) for line in active_lines):
            mainmatter_anchor = first_chapter_line - 1
            markers_before_first_chapter = [
                line_no for line_no, _ in printed_page_markers
                if begin_index + 1 < line_no < first_chapter_line
            ]
            if markers_before_first_chapter:
                # Switch to arabic book semantics before applying the source's
                # first authoritative printed-page counter.
                mainmatter_anchor = max(markers_before_first_chapter) - 1
            ops.append(PendingOp(
                "insert_line", mainmatter_anchor, new=r"\LSMainMatter",
            ))
            pagination_added = True

    # A chapter-local TOC is useful only when the parsed chapter has section
    # descendants.  This avoids empty decorative blocks on chapter-only OCR.
    chapter_tocs = len(local_contents_markers)
    ordered_chapters = sorted(chapter_nodes, key=lambda item: item.span.start_line)
    for chapter_index, chapter in enumerate(ordered_chapters):
        next_chapter_line = (
            ordered_chapters[chapter_index + 1].span.start_line
            if chapter_index + 1 < len(ordered_chapters)
            else len(lines) + 1
        )
        has_local_marker = any(
            chapter.span.start_line < line_no < next_chapter_line
            for line_no in local_contents_markers
        )
        try:
            start = sections.index(chapter)
        except ValueError:
            continue
        has_descendant = False
        for following in sections[start + 1:]:
            if following.level <= chapter.level:
                break
            if following.cmd in {"section", "subsection", "subsubsection"}:
                has_descendant = True
                break
        if has_descendant and not has_local_marker:
            ops.append(PendingOp(
                "insert_line",
                chapter.span.end_line,
                new=r"\LSChapterContents",
            ))
            chapter_tocs += 1

    source_clearpages = sum(
        1 for line in mask_comments(text).split("\n")
        if line.strip() == r"\clearpage"
    )
    notes.extend([
        {
            "line": dc_idx + 1,
            "reason": (
                "已应用 faithfulbook 双面书籍版式："
                f"{layout.paper_width_mm:g}×{layout.paper_height_mm:g}mm、"
                f"{layout.body_font_pt}pt 正文、约 15mm 书页边距"
            ),
        },
        {
            "line": begin_index + 1,
            "reason": (
                "奇偶页眉仅取自结构化章/节标题和新页码；"
                "不会把 OCR 页眉或印刷页码复制到页眉"
            ),
        },
        {
            "line": begin_index + 1,
            "reason": f"完整保留 {source_clearpages} 个源页 \\clearpage 分界",
        },
    ])
    if shifted:
        notes.append({
            "line": 1,
            "reason": f"文章型标题层级已整体上移 {shifted} 处以适配 book 章结构",
        })
    if pagination_added:
        notes.append({
            "line": 1,
            "reason": "前置页使用罗马页码；首个编号章从正文第 1 页开始且不增加空白页",
        })
    if first_front_page_emptied:
        notes.append({
            "line": begin_index + 2,
            "reason": "首个前置物理页使用 empty 页式；后续前置页和首章页不受影响",
        })
    if chapter_tocs:
        notes.append({
            "line": 1,
            "reason": f"已为 {chapter_tocs} 个章加入二次编译章内目录",
        })
    if printed_page_markers:
        notes.append({
            "line": printed_page_markers[0][0],
            "reason": (
                f"已应用 {len(printed_page_markers)} 个可信印刷页码锚点；"
                "只校正页码计数，不增加物理空白页"
            ),
        })
    if invalid_printed_page_markers:
        notes.append({
            "line": invalid_printed_page_markers[0],
            "reason": (
                f"已忽略 {len(invalid_printed_page_markers)} 个非法印刷页码 marker；"
                f"仅接受 1–{MAX_PRINTED_PAGE} 的十进制整数"
            ),
        })
    return ops, notes


def build_template_ops(
    text: str,
    template: str | None = ELEGANTBOOK,
    context: Dict[str, str] | None = None,
) -> Tuple[List[PendingOp], List[dict]]:
    """按模板 ID 返回可逆编辑计划；默认值保持旧调用兼容。"""
    template_id = normalize_template_id(template)
    if not template_id:
        return [], []
    if template_id == PROFESSIONAL_HANDOUT:
        return _build_professional_handout_ops(text, context=context)
    if template_id == FAITHFULBOOK:
        return _build_faithfulbook_ops(text, context=context)
    return _build_elegantbook_ops(text, context=context)
