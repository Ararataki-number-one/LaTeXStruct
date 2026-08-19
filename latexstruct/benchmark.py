# -*- coding: utf-8 -*-
"""Benchmark 金标评测（评审 P1）。

- 检测指标：按类型（theorem-like 各环境 / proof / exercise-section）计算
  Precision / Recall / F1，以"标题行 + 类型"为匹配键；
- 内容指标：内容不变校验、多层不变量、环境配平、可选 xelatex 编译；
- 金标数据格式（benchmark/golden/*.json）：
  {"sample": "相对路径", "pack": "bilingual", "mode": "rule",
   "labels": [{"needle": "Theorem 2.3.4", "kind": "theorem"}, ...]}
  needle 用于定位标题行（文本搜索，避免脆弱的行号）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .core.parser import parse_latex
from .core.pipeline import run_pipeline
from .core.scanner import scan

MEASURED_KINDS = ("theorem-like", "proof", "exercise-section")
BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmark"
GOLDEN_DIR = BENCHMARK_DIR / "golden"
HOLDOUT_DIR = BENCHMARK_DIR / "golden-holdout"


def locate_line(tex: str, needle: str) -> Optional[int]:
    for i, line in enumerate(tex.split("\n"), 1):
        if needle in line:
            return i
    return None


def load_golden(path) -> Dict:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    sample = (p.parent / data["sample"]).resolve()
    data["_sample_path"] = sample
    data["_tex"] = sample.read_text(encoding="utf-8")
    return data


def _metrics(tp: int, fp: int, fn: int) -> Dict:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def evaluate_golden(golden_path, compile_check: bool = False) -> Dict:
    data = load_golden(golden_path)
    tex = data["_tex"]
    pack = data.get("pack") or "bilingual"
    # 编译对比只对"声明可编译"的金标生效（最小依赖集），--compile 开启该机制
    do_compile = bool(data.get("compile", False)) and compile_check
    doc = parse_latex(tex)
    res = scan(doc, pack=pack)

    # 候选键集合
    cand_keys = set()
    for c in res.candidates:
        if c.kind == "theorem-like":
            cand_keys.add(("theorem-like:" + c.env_hint, c.span.start_line))
        elif c.kind in ("proof", "exercise-section"):
            cand_keys.add((c.kind, c.span.start_line))

    # 金标键集合（行号锚定优先；无行号时用 needle 定位）
    gold_keys = set()
    label_errors = []
    for lb in data.get("labels", []):
        if lb.get("line"):
            line = int(lb["line"])
            if lb.get("needle") and lb["needle"] not in tex.split("\n")[line - 1]:
                label_errors.append(f"行号 {line} 与 needle 不符: {lb['needle'][:40]}")
        else:
            line = locate_line(tex, lb["needle"])
            if line is None:
                label_errors.append(f"needle 未定位: {lb['needle']}")
                continue
        kind = lb["kind"]
        if kind == "theorem-like":
            gold_keys.add(("theorem-like:" + lb["env"], line))
        else:
            gold_keys.add((kind, line))

    # 分类型统计（键前缀聚合）
    by_kind: Dict[str, Dict] = {}
    for prefix in sorted({k[0].split(":")[0] for k in gold_keys | cand_keys}):
        if prefix not in MEASURED_KINDS:
            continue
        g = {k for k in gold_keys if k[0].split(":")[0] == prefix}
        c = {k for k in cand_keys if k[0].split(":")[0] == prefix}
        by_kind[prefix] = _metrics(len(g & c), len(c - g), len(g - c))
    # 按环境细分（theorem-like）
    by_env: Dict[str, Dict] = {}
    for env in sorted({k[0] for k in gold_keys | cand_keys if k[0].startswith("theorem-like:")}):
        g = {k for k in gold_keys if k[0] == env}
        c = {k for k in cand_keys if k[0] == env}
        by_env[env.split(":")[1]] = _metrics(len(g & c), len(c - g), len(g - c))

    total_tp = sum(v["tp"] for v in by_kind.values())
    total_fp = sum(v["fp"] for v in by_kind.values())
    total_fn = sum(v["fn"] for v in by_kind.values())
    macro = _metrics(total_tp, total_fp, total_fn)

    # 内容指标（规则模式全流水线）
    pr = run_pipeline(
        tex,
        mode=data.get("mode", "rule"),
        pack=pack,
        compile_check=do_compile,
    )
    content = {
        "content_invariant": pr.verification["content_invariant"],
        "invariants_ok": pr.verification["invariants"]["ok"],
        "env_balance": pr.verification["env_balance"]["ok"],
    }
    if do_compile:
        content["compile_before"] = pr.verification["compile_before"]
        content["compile"] = pr.verification["compile_after"]
        content["compile_gate"] = bool(
            pr.verification["compile"]["checked"]
            and pr.verification["compile"]["ok"]
        )

    return {
        "name": data.get("name", Path(golden_path).stem),
        "labels_total": len(data.get("labels", [])),
        "label_errors": label_errors,
        "by_kind": by_kind,
        "by_env": by_env,
        "macro": macro,
        "content": content,
        "ok": (not label_errors)
             and all(v["fn"] == 0 and v["fp"] == 0 for v in by_kind.values())
             and content["content_invariant"] and content["invariants_ok"] and content["env_balance"]
             and (not do_compile or content["compile_gate"]),
    }


def run_all(compile_check: bool = False, include_holdout: bool = False) -> List[Dict]:
    reports = [evaluate_golden(p, compile_check=compile_check) for p in sorted(GOLDEN_DIR.glob("*.json"))]
    if include_holdout:
        reports += [evaluate_golden(p, compile_check=compile_check)
                    for p in sorted(HOLDOUT_DIR.glob("*.json"))]
    return reports


def render_markdown(reports: List[Dict]) -> str:
    L = ["# LaTeXStruct Benchmark", ""]
    # 汇总指标（用户评审要求：不止一个 Accuracy）
    total_labels = sum(r["labels_total"] for r in reports)
    total_tp = sum(r["macro"]["tp"] for r in reports)
    total_fp = sum(r["macro"]["fp"] for r in reports)
    total_fn = sum(r["macro"]["fn"] for r in reports)
    m = _metrics(total_tp, total_fp, total_fn)
    zero_change = sum(1 for r in reports if r["content"]["content_invariant"]) / max(1, len(reports))
    ref_keep = sum(1 for r in reports if r["content"]["invariants_ok"]) / max(1, len(reports))
    compiled = [r for r in reports if r["content"].get("compile")]
    compile_ok = sum(1 for r in compiled if r["content"]["compile"].get("ok")) / max(1, len(compiled)) if compiled else None
    L.append(f"- 金标集数：{len(reports)} · 标签总数：{total_labels} · TP {total_tp} / FP {total_fp} / FN {total_fn}")
    L.append(f"- 总 Precision {m['precision']:.2%} · Recall {m['recall']:.2%} · F1 {m['f1']:.2%}")
    L.append(f"- 正文零改动率：{zero_change:.0%} · 引用保持率：{ref_keep:.0%} · "
             f"编译成功率：{compile_ok:.0%}（{len(compiled)} 组参与编译）" if compile_ok is not None else
             f"- 正文零改动率：{zero_change:.0%} · 引用保持率：{ref_keep:.0%} · 编译成功率：—")
    L.append("")
    L.append("| 金标集 | 类型 | TP | FP | FN | Precision | Recall | F1 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in reports:
        for kind in sorted(r["by_kind"]):
            m = r["by_kind"][kind]
            L.append(
                f"| {r['name']} | {kind} | {m['tp']} | {m['fp']} | {m['fn']} | "
                f"{m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} |"
            )
        if r["by_env"]:
            for env in sorted(r["by_env"]):
                m = r["by_env"][env]
                L.append(
                    f"| {r['name']} | theorem-like:{env} | {m['tp']} | {m['fp']} | {m['fn']} | "
                    f"{m['precision']:.2%} | {m['recall']:.2%} | {m['f1']:.2%} |"
                )
    L.append("")
    L.append("## 内容指标")
    L.append("")
    L.append("| 金标集 | 内容不变 | 多层不变量 | 环境配平 | 编译 |")
    L.append("|---|---|---|---|---|")
    for r in reports:
        c = r["content"]
        comp = c.get("compile")
        comp_s = ("成功 " + str(comp["pages"]) + " 页") if comp and comp.get("ok") else ("失败" if comp else "—")
        L.append(
            f"| {r['name']} | {'OK' if c['content_invariant'] else 'FAIL'} | "
            f"{'OK' if c['invariants_ok'] else 'FAIL'} | {'OK' if c['env_balance'] else 'FAIL'} | {comp_s} |"
        )
    compile_failures = [
        r for r in reports
        if r["content"].get("compile") and not r["content"]["compile"].get("ok")
    ]
    if compile_failures:
        L.append("")
        L.append("## 编译诊断")
        L.append("")
        for r in compile_failures:
            c = r["content"]
            for phase, label in (("compile_before", "修改前"), ("compile", "修改后")):
                result = c.get(phase) or {}
                if not result.get("available"):
                    details = "编译器不可用"
                elif result.get("ok"):
                    details = f"成功 {result.get('pages', 0)} 页"
                else:
                    errors = result.get("errors") or ["编译失败，但日志中未提取到 TeX 错误"]
                    details = "; ".join(str(error).replace("|", "\\|") for error in errors)
                L.append(f"- `{r['name']}` {label}：{details}")
    if any(r["label_errors"] for r in reports):
        L.append("")
        L.append("## 金标数据问题")
        for r in reports:
            for e in r["label_errors"]:
                L.append(f"- {r['name']}: {e}")
    return "\n".join(L)
