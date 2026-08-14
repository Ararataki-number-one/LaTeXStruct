# -*- coding: utf-8 -*-
"""多文件 LaTeX 项目处理 CLI。

用法：
  python tools/process_project.py <项目文件夹> [输出文件夹] [--mode rule|ai] [--template elegantbook]

流程：发现 main.tex → \input/\include 依赖图（缺失/循环报告）→ 带标记展开 →
单文件流水线（解析/扫描/决策/补丁/多层校验）→ 拆分回各文件 → 导出到副本目录。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from latexstruct.core.project import export_project, process_project  # noqa: E402


def main():
    args = sys.argv[1:]
    mode, template = "rule", None
    if "--mode" in args:
        i = args.index("--mode")
        mode = args[i + 1]
        args = args[:i] + args[i + 2 :]
    if "--template" in args:
        i = args.index("--template")
        template = args[i + 1]
        args = args[:i] + args[i + 2 :]
    if not args:
        print("用法: python tools/process_project.py <项目文件夹> [输出文件夹] [--mode ai] [--template elegantbook]")
        return 1
    root = Path(args[0])
    outdir = Path(args[1]) if len(args) > 1 else root.parent / (root.name + "-structured")
    if not root.is_dir():
        print(f"目录不存在: {root}")
        return 1

    res = process_project(root, mode=mode, template=template)
    g, pr = res.graph, res.pipeline
    print(f"主文件: {g.main_rel} · 依赖文件: {len(g.files)} 个 · 缺失引用: {len(g.missing)} · 循环: {len(g.cycles)}")
    for m in g.missing:
        print(f"  [缺失] {m}")
    for c in g.cycles:
        print(f"  [循环] {' -> '.join(c)}")
    print(f"流水线: ok={pr.ok} applied={len(pr.applied)} rejected={len(pr.rejected)} "
          f"ambiguous={len(pr.ambiguous)}")
    v = pr.verification
    print(f"校验: invariant={v.get('content_invariant')} balance={v.get('env_balance', {}).get('ok')} "
          f"多层不变量={v.get('invariants', {}).get('ok')}")
    export_project(root, outdir, g.main_rel, res.per_file, g)
    print(f"已导出到: {outdir}")
    (outdir / "LATEXSTRUCT-REPORT.md").write_text(pr.report_md, encoding="utf-8")
    return 0 if pr.ok else 1


if __name__ == "__main__":
    sys.exit(main())
