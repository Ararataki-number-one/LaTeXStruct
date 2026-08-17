# -*- coding: utf-8 -*-
"""机器校验：环境配平 / 花括号配平（内容不变校验在 patch.py）。"""

from __future__ import annotations

import re
from typing import Dict, List

from .parser import (
    ENV_RE,
    PROTECTED_ENVS,
    find_env_ranges,
    mask_comments,
    mask_inline_verb,
    mask_protected,
)


DISPLAY_SAFETY_TOKEN_RE = re.compile(
    r"(?<!\\)\\(?P<delimiter>[\[\]])|(?<!\\)\\(?P<tag>tag)(?![A-Za-z@])"
)
DISPLAY_OUTER_TEXT_ENVS = {
    "theorem", "theorem*", "lemma", "lemma*", "proposition", "proposition*",
    "corollary", "corollary*", "definition", "definition*", "remark", "remark*",
    "example", "example*", "exercise", "exercise*", "proof",
}


def _masked(text: str) -> str:
    t1 = mask_comments(text)
    ranges, _, _ = find_env_ranges(t1)
    return mask_inline_verb(mask_protected(t1, ranges))


def check_env_balance(text: str) -> Dict:
    masked = mask_comments(text)
    _, ub, ue = find_env_ranges(masked)
    stack = []
    issues = []
    for match in ENV_RE.finditer(masked):
        kind, name = match.group(1), match.group(2)
        line = masked.count("\n", 0, match.start()) + 1
        if stack and stack[-1][0] in PROTECTED_ENVS:
            if kind == "end" and name == stack[-1][0]:
                stack.pop()
            continue
        if kind == "begin":
            stack.append((name, line))
        elif stack and stack[-1][0] == name:
            stack.pop()
        else:
            issues.append({
                "line": line,
                "env": name,
                "reason": (
                    f"\\end{{{name}}} 的位置错误；"
                    + (
                        f"此处仍在 {stack[-1][0]} 环境内"
                        if stack else "此前没有对应的开始环境"
                    )
                ),
            })
    issues.extend(
        {
            "line": line,
            "env": name,
            "reason": f"\\begin{{{name}}} 缺少对应的 \\end{{{name}}}",
        }
        for name, line in stack
    )
    return {
        "ok": not ub and not ue,
        "unbalanced_begins": ub,
        "unbalanced_ends": ue,
        "issues": issues[:50],
    }


def compare_env_balance(before: str, after: str) -> Dict:
    """基线对比：整理不得**新增**环境不平衡（原文自身的不平衡保持原样）。

    适用于整书切片等"原文就截断"的输入：前后不平衡集合一致即通过。
    """
    b = check_env_balance(before)
    a = check_env_balance(after)
    no_new = (
        sorted(b["unbalanced_begins"]) == sorted(a["unbalanced_begins"])
        and sorted(b["unbalanced_ends"]) == sorted(a["unbalanced_ends"])
    )
    return {
        "ok": a["ok"] or no_new,
        "no_new": no_new,
        "before_unbalanced": b["unbalanced_begins"] + b["unbalanced_ends"],
        "after_unbalanced": a["unbalanced_begins"] + a["unbalanced_ends"],
        "before_issues": b.get("issues", []),
        "after_issues": a.get("issues", []),
        # 失败清单直接使用 after 的具体行号与环境名；只在比较失败时暴露，
        # 原文已有且未恶化的问题仍由 no_new 兼容逻辑处理。
        "issues": [] if (a["ok"] or no_new) else a.get("issues", []),
    }


def check_braces(text: str) -> Dict:
    """花括号配平（跳过转义花括号）；结果仅作参考（advisory）。"""
    masked = _masked(text)
    depth = 0
    prev = ""
    for ch in masked:
        if ch == "{" and prev != "\\":
            depth += 1
        elif ch == "}" and prev != "\\":
            depth -= 1
            if depth < 0:
                return {"ok": False, "depth": depth, "note": "多余右花括号"}
        prev = ch
    return {"ok": depth == 0, "depth": depth}


def compare_braces(before: str, after: str) -> Dict:
    """整理不得新增花括号不平衡；原文已有且保持不变时允许继续审阅。"""
    b = check_braces(before)
    a = check_braces(after)
    no_new = b == a
    return {
        "ok": bool(a["ok"] or no_new),
        "no_new": no_new,
        "before": b,
        "after": a,
        "depth": a.get("depth", 0),
    }


def check_display_tag_safety(text: str) -> Dict:
    r"""检查活动 ``\[``/``\]`` 配对及其中的非法 ``\tag``。

    名称为兼容既有 verification 字段保留；检查范围只覆盖 bracket display，
    equation/align 等 AMS 数学环境中的合法 ``\tag`` 不受影响。
    """
    masked = _masked(text)
    issues = []
    open_offset = None
    outer_env_stack = []
    combined = re.compile(
        DISPLAY_SAFETY_TOKEN_RE.pattern
        + r"|\\(?P<env_kind>begin|end)\s*\{(?P<env_name>[^{}\s]+)\}"
    )
    for token in combined.finditer(masked):
        delimiter = token.group("delimiter")
        if delimiter == "[":
            if open_offset is not None:
                issues.append({
                    "line": masked.count("\n", 0, token.start()) + 1,
                    "reason": "展示公式尚未闭合又出现新的 \\[，请检查公式分隔符",
                })
            else:
                open_offset = token.start()
        elif delimiter == "]":
            if open_offset is None:
                issues.append({
                    "line": masked.count("\n", 0, token.start()) + 1,
                    "reason": "发现没有对应 \\[ 的 \\]，请检查公式分隔符",
                })
            else:
                open_offset = None
        elif token.group("tag") and open_offset is not None:
            issues.append({
                "line": masked.count("\n", 0, token.start()) + 1,
                "reason": (
                    "\\tag 不能直接用于 \\[...\\] 显示公式；"
                    "请改用 equation/align 等 AMS 数学环境，或移除多余 tag"
                ),
            })
        elif token.group("env_kind"):
            kind, name = token.group("env_kind"), token.group("env_name")
            if name not in DISPLAY_OUTER_TEXT_ENVS:
                continue
            if kind == "begin":
                outer_env_stack.append(name)
            elif outer_env_stack and outer_env_stack[-1] == name:
                if open_offset is not None:
                    issues.append({
                        "line": masked.count("\n", 0, token.start()) + 1,
                        "reason": (
                            f"\\end{{{name}}} 位于尚未闭合的 \\[...\\] 内；"
                            "请先闭合公式，再结束外层环境"
                        ),
                    })
                outer_env_stack.pop()
    if open_offset is not None:
        issues.append({
            "line": masked.count("\n", 0, open_offset) + 1,
            "reason": "展示公式的 \\[ 缺少对应 \\]，请补全或移除未闭合分隔符",
        })
    return {
        "ok": not issues,
        "count": len(issues),
        "issues": issues[:20],
    }


KNOWN_ISSUE_PATTERNS = [
    # 原文既有问题，仅报告不修改
    (r"\\left\s*\(\s*\\begin\{matrix\}",
     "\\left( 内嵌 matrix 环境：TeX Live 2026 内核 bug，编译时内存溢出（原文既有，未修改）"),
]


def known_issues(text: str) -> List[Dict]:
    masked = _masked(text)
    out = []
    for pat, desc in KNOWN_ISSUE_PATTERNS:
        for m in re.finditer(pat, masked):
            line = masked.count("\n", 0, m.start()) + 1
            out.append({"line": line, "reason": desc})
    return out


_FAILURE_ACTIONS = {
    "content": "重新运行结构化整理；若仍失败，请保留原文并查看失败草稿中的最后一项修改",
    "environments": "按提示行号检查 begin/end 顺序，或重新运行让 OCR 结构修复器处理",
    "braces": "按提示深度检查未闭合或多余的花括号",
    "math": "数学内容发生变化，已禁止保存；请检查失败草稿中的公式差异",
    "labels": "label 集合发生变化，已禁止保存；请检查失败草稿中的引用标签",
    "refs": "引用集合发生变化，已禁止保存；请检查失败草稿中的 ref/cite",
    "images": "图片引用发生变化，已禁止保存；请检查 includegraphics 路径",
    "display-math": "按提示行号修正展示公式边界或改用 equation/align 环境",
    "outline": "重新运行 AI 结构化；目录必须由 \\tableofcontents 生成，章节使用标准 LaTeX 命令",
    "resources": "重新从原 PDF 导入以提取图片；仍缺失时请把列出的图片加入项目 images 目录",
    "compile": "根据首条编译错误及行号修正后重试；原项目和上一次安全结果均未覆盖",
    "project": "补齐缺失的 input/include 文件并解除循环引用后重试",
}


_LOCAL_TEX_PATH_RE = re.compile(
    r"(?i)(?:[A-Z]:[\\/]|/)(?:[^\r\n:]*?[\\/])*[^\r\n:]*?"
    r"\.(?:tex|sty|cls|log|aux|out|toc|pdf)(?=:\d+|[\s:)]|$)"
)


def _safe_failure_text(value: object) -> str:
    """保留 LaTeX 命令/行号，同时移除编译器可能回显的本机绝对路径。"""
    return _LOCAL_TEX_PATH_RE.sub("<local-file>", str(value))[:1000]


def verification_failures(verification: Dict) -> List[Dict]:
    """把机器校验结果变成稳定、可行动且不泄露本机路径的失败清单。"""
    if not isinstance(verification, dict):
        return [{
            "id": "verification",
            "label": "安全检查",
            "summary": "安全检查结果缺失",
            "details": [],
            "action": "重新运行结构化整理；若仍失败，请查看问题汇报",
        }]
    failed = [
        item for item in verification.get("checks", [])
        if isinstance(item, dict) and item.get("ok") is False
    ]
    result = []
    for check in failed:
        check_id = str(check.get("id") or "verification")
        label = str(check.get("label") or check_id)
        details: List[Dict] = []
        summary = f"{label}未通过"
        if check_id == "environments":
            details = list((verification.get("env_balance") or {}).get("issues") or [])
        elif check_id == "braces":
            brace = verification.get("braces") or {}
            after = brace.get("after") or brace
            summary = str(after.get("note") or f"花括号深度为 {after.get('depth', 0)}")
        elif check_id in {"math", "labels", "refs", "images"}:
            key = {"math": "math", "labels": "labels", "refs": "refs", "images": "images"}[check_id]
            invariant = ((verification.get("invariants") or {}).get(key) or {})
            missing = [str(item) for item in invariant.get("missing", [])]
            extra = [str(item) for item in invariant.get("extra", [])]
            details = ([{"reason": f"缺少：{item}"} for item in missing]
                       + [{"reason": f"新增：{item}"} for item in extra])[:20]
            if details:
                summary = "；".join(item["reason"] for item in details[:3])
        elif check_id == "display-math":
            details = list((verification.get("display_tags") or {}).get("issues") or [])
        elif check_id == "outline":
            details = list((verification.get("ocr_structure") or {}).get("issues") or [])
        elif check_id == "resources":
            resources = verification.get("resources") or {}
            missing = [str(item) for item in resources.get("missing", [])]
            unsafe = [str(item) for item in resources.get("unsafe", [])]
            details = ([{"reason": f"缺少图片：{item}"} for item in missing]
                       + [{"reason": f"不安全路径：{item}"} for item in unsafe])[:50]
            if missing:
                summary = "缺少图片：" + "、".join(missing[:5])
            elif unsafe:
                summary = "图片路径不安全：" + "、".join(unsafe[:5])
        elif check_id == "compile":
            errors = [
                _safe_failure_text(item)
                for item in (verification.get("compile_after") or {}).get("errors", [])
            ]
            details = [{"reason": item} for item in errors[:10]]
            if errors:
                summary = errors[0]
        elif check_id == "project":
            project = verification.get("project") or {}
            details = ([{"reason": f"缺失依赖：{item}"} for item in project.get("missing_includes", [])]
                       + [{"reason": f"循环引用：{item}"} for item in project.get("cycles", [])])[:50]
            if project.get("error"):
                details.insert(0, {"reason": str(project["error"])[:300]})
        if details and summary == f"{label}未通过":
            summary = str(details[0].get("reason") or summary)
        result.append({
            "id": check_id,
            "label": label,
            "summary": summary[:500],
            "details": details[:50],
            "action": _FAILURE_ACTIONS.get(
                check_id,
                "保留原项目，查看失败草稿和问题汇报后重试",
            ),
        })
    return result
