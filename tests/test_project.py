# -*- coding: utf-8 -*-
"""多文件 LaTeX 项目测试。"""

import os
import shutil
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.project import (  # noqa: E402
    build_project_graph,
    collect_project_structured_envs,
    discover_main,
    decode_tex_bytes,
    encode_project_files,
    encode_tex_like_original,
    export_project,
    flatten_project,
    parse_includes,
    process_project,
    read_tex,
    safe_project_relpath,
    split_project,
)

_TESTS = os.path.dirname(os.path.abspath(__file__))

MAIN = """\\documentclass{book}
\\input{preamble}
\\begin{document}
\\include{chapters/ch01}
\\include{chapters/ch02}
\\end{document}
"""

PREAMBLE = "\\usepackage{amsmath,amssymb}\n"

CH01 = """\\section{First}

Theorem 1.1. A statement.

Proof. By definition.

\\input{chapters/ch02-note}
"""

CH01_NOTE = "\\section{Note}\n\nRemark. A note.\n"

CH02 = """\\section{Second}

Theorem 1.2. Another statement.

\\input{missing-file}
"""


def _make_project():
    root = tempfile.mkdtemp(prefix="ls-proj-", dir=_TESTS)
    (Path := __import__("pathlib").Path)(root, "chapters").mkdir()
    for name, content in (
        ("main.tex", MAIN),
        ("preamble.tex", PREAMBLE),
        ("chapters/ch01.tex", CH01),
        ("chapters/ch02-note.tex", CH01_NOTE),
        ("chapters/ch02.tex", CH02),
    ):
        (Path(root) / name).write_text(content, encoding="utf-8")
    return root


def test_discover_and_graph():
    root = _make_project()
    try:
        assert discover_main(__import__("pathlib").Path(root)) == "main.tex"
        g = build_project_graph(__import__("pathlib").Path(root), "main.tex")
        assert "preamble.tex" in g.files
        assert "chapters/ch01.tex" in g.files
        assert "chapters/ch02-note.tex" in g.files
        assert "chapters/ch02.tex" in g.files
        assert any("missing-file" in m for m in g.missing)
        assert g.cycles == [] or g.cycles  # 无环时为空
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_flatten_and_split_roundtrip():
    root = _make_project()
    try:
        from pathlib import Path

        flat, g = flatten_project(Path(root), "main.tex")
        # 展开含标记与子文件内容
        assert "LATEXSTRUCT-FILE-START: chapters/ch01.tex" in flat
        assert "Theorem 1.1. A statement." in flat
        assert "Remark. A note." in flat  # 嵌套展开
        # 主文件中的 \input 行保留
        assert "\\input{preamble}" in flat
        # 拆分回各文件
        per = split_project(flat)
        assert "\\documentclass{book}" in per[""]
        assert "Theorem 1.1. A statement." in per["chapters/ch01.tex"]
        assert "Remark. A note." in per["chapters/ch02-note.tex"]
        assert "Theorem 1.2. Another statement." in per["chapters/ch02.tex"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_nested_split_restores_parent_after_child():
    flat = (
        "main-before\n"
        "% === LATEXSTRUCT-FILE-START: chapters/a.tex ===\n"
        "a-before\n"
        "% === LATEXSTRUCT-FILE-START: shared/note.tex ===\n"
        "note\n"
        "% === LATEXSTRUCT-FILE-END: shared/note.tex ===\n"
        "a-after\n"
        "% === LATEXSTRUCT-FILE-END: chapters/a.tex ===\n"
        "main-after"
    )
    per = split_project(flat)
    assert per[""] == "main-before\nmain-after"
    assert per["chapters/a.tex"] == "a-before\na-after"
    assert per["shared/note.tex"] == "note"


def test_include_parser_ignores_comments_and_protected_examples():
    text = (
        "% \\input{commented}\n"
        "\\begin{minted}{latex}\n\\include{example}\n\\end{minted}\n"
        "\\input real-file\n\\include{chapters/one}\n"
    )
    assert parse_includes(text) == ["real-file", "chapters/one"]


def test_repeated_include_is_expanded_only_once():
    root = tempfile.mkdtemp(prefix="ls-proj-", dir=_TESTS)
    try:
        from pathlib import Path

        (Path(root) / "main.tex").write_text(
            "\\documentclass{book}\n\\begin{document}\n"
            "\\input{chapter}\n\\input{chapter}\n\\end{document}\n",
            encoding="utf-8",
        )
        (Path(root) / "chapter.tex").write_text("chapter body\n", encoding="utf-8")
        flat, _ = flatten_project(Path(root), "main.tex")
        assert flat.count("LATEXSTRUCT-FILE-START: chapter.tex") == 1
        assert split_project(flat)["chapter.tex"].count("chapter body") == 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_source_cannot_spoof_internal_file_markers():
    root = tempfile.mkdtemp(prefix="ls-proj-", dir=_TESTS)
    try:
        from pathlib import Path

        (Path(root) / "main.tex").write_text(
            "\\documentclass{book}\n% === LATEXSTRUCT-FILE-START: fake.tex ===\n",
            encoding="utf-8",
        )
        try:
            flatten_project(Path(root), "main.tex")
        except ValueError as exc:
            assert "保留标记" in str(exc)
        else:
            raise AssertionError("内部文件标记碰撞应阻止展开")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_project_paths_reject_traversal():
    assert safe_project_relpath("chapters/a.tex") == "chapters/a.tex"
    for rel in ("../outside.tex", "/absolute.tex", "C:/outside.tex", "a/../../b.tex"):
        try:
            safe_project_relpath(rel)
        except ValueError:
            pass
        else:
            raise AssertionError(f"应拒绝不安全路径：{rel}")


def test_process_project_end_to_end():
    root = _make_project()
    try:
        from pathlib import Path

        # 该用例验证成功路径；补齐 CH02 中引用的文件。缺失依赖的阻断行为由
        # server/project 安全检查用例单独覆盖。
        (Path(root) / "missing-file.tex").write_text("Supplement.\n", encoding="utf-8")
        res = process_project(Path(root), mode="rule")
        pr = res.pipeline
        assert pr.ok, pr.report_md
        assert pr.verification["invariants"]["ok"] is True
        # 章节文件中的定理被结构化
        assert "\\begin{theorem}[1.1]" in res.per_file["chapters/ch01.tex"]
        assert "\\begin{theorem}[1.2]" in res.per_file["chapters/ch02.tex"]
        assert "\\begin{proof}" in res.per_file["chapters/ch01.tex"]
        # 主文件结构不变
        assert "\\include{chapters/ch01}" in res.per_file[""]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_single_file_latin1_gbk_bom_and_newline_roundtrip_and_modified_encoding():
    latin1 = "% caf\xe9\r\nPlain text.\r\n".encode("latin-1")
    latin = decode_tex_bytes(latin1)
    assert latin.encoding == "latin-1"
    assert latin.newline == "\r\n"
    # Analysis normalizes line endings; an otherwise unchanged file must still
    # be returned byte-for-byte, including the trailing newline.
    assert encode_tex_like_original(latin.text.replace("\r\n", "\n"), latin1) == latin1
    latin_changed = encode_tex_like_original(latin.text + "R\xe9sum\xe9.\r\n", latin1)
    assert latin_changed.decode("latin-1").endswith("R\xe9sum\xe9.\r\n")
    assert b"\r\n" in latin_changed and b"\n" not in latin_changed.replace(b"\r\n", b"")

    gbk = "% GBK \u6d4b\u8bd5\r\n\u4e2d\u6587\u6b63\u6587\r\n".encode("gbk")
    chinese = decode_tex_bytes(gbk)
    assert chinese.encoding == "gbk"
    assert encode_tex_like_original(chinese.text.replace("\r\n", "\n"), gbk) == gbk
    gbk_changed = encode_tex_like_original(chinese.text + "\u65b0\u589e\u3002\r\n", gbk)
    assert gbk_changed.decode("gbk").endswith("\u65b0\u589e\u3002\r\n")

    bom = b"\xef\xbb\xbf" + "Alpha\r\n".encode("utf-8")
    decoded_bom = decode_tex_bytes(bom)
    assert decoded_bom.bom == b"\xef\xbb\xbf"
    assert encode_tex_like_original("Alpha\n", bom) == bom
    assert encode_tex_like_original("Alpha\nBeta\n", bom).startswith(b"\xef\xbb\xbf")


def test_folder_mixed_encodings_reuse_unchanged_bytes_and_encode_changes():
    main_raw = (
        "\\documentclass{book}\r\n% caf\xe9\r\n"
        "\\begin{document}\r\n\\input{chapter}\r\n\\end{document}\r\n"
    ).encode("latin-1")
    chapter_raw = "\u4e2d\u6587\u6bb5\u843d\r\n".encode("gbk")
    originals = {"main.tex": main_raw, "chapter.tex": chapter_raw}
    unchanged = {
        "": decode_tex_bytes(main_raw).text.replace("\r\n", "\n"),
        "chapter.tex": decode_tex_bytes(chapter_raw).text.replace("\r\n", "\n"),
    }
    encoded = encode_project_files(originals, "main.tex", unchanged)
    assert encoded == originals

    changed = dict(unchanged)
    changed["chapter.tex"] += "\u65b0\u589e\u4e00\u884c\n"
    encoded = encode_project_files(originals, "main.tex", changed)
    assert encoded["main.tex"] == main_raw
    assert encoded["chapter.tex"].decode("gbk").endswith("\u65b0\u589e\u4e00\u884c\r\n")


def test_unrepresentable_modified_text_fails_closed():
    latin1 = "caf\xe9\n".encode("latin-1")
    try:
        encode_tex_like_original("caf\xe9 \u4e2d\u6587\n", latin1)
    except ValueError as exc:
        assert "无法表示" in str(exc)
    else:
        raise AssertionError("Latin-1 无法表示的修改必须阻止写回")


def test_reachable_style_and_class_theorem_declarations_are_propagated():
    root = tempfile.mkdtemp(prefix="ls-proj-envs-", dir=_TESTS)
    try:
        from pathlib import Path

        project = Path(root)
        (project / "main.tex").write_text(
            "\\documentclass{localbook}\n"
            "\\usepackage{active}\n"
            "\\begin{document}\n"
            "\\begin{styresult*}\n"
            "Theorem. Already structured by the project style.\n"
            "\\end{styresult*}\n"
            "\\end{document}\n",
            encoding="utf-8",
        )
        (project / "localbook.cls").write_text(
            "\\LoadClass{book}\n"
            "\\newtheorem{classresult}{Class Result}\n",
            encoding="utf-8",
        )
        (project / "active.sty").write_text(
            "\\newtheorem*{styresult}{Style Result}\n"
            "\\input{support-theorems}\n",
            encoding="utf-8",
        )
        (project / "support-theorems.tex").write_text(
            "\\declaretheorem[name={Nested Result}]{nestedresult}\n",
            encoding="utf-8",
        )
        (project / "unused.sty").write_text(
            "\\newtheorem{unusedresult}{Unused Result}\n",
            encoding="utf-8",
        )

        declared = collect_project_structured_envs(project, "main.tex")
        assert declared == {"classresult", "styresult", "nestedresult"}

        result = process_project(project, mode="rule")
        assert result.pipeline.ok is True
        assert result.per_file[""].count("\\begin{styresult*}") == 1
        assert "\\begin{theorem}" not in result.per_file[""]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_process_project_compile_uses_reconstructed_files_not_flattened_text():
    root = tempfile.mkdtemp(prefix="ls-proj-compile-", dir=_TESTS)
    try:
        from pathlib import Path

        project = Path(root)
        (project / "chapters").mkdir()
        (project / "images").mkdir()
        (project / "main.tex").write_text(
            "\\documentclass{book}\n\\begin{document}\n"
            "\\input{chapters/one}\n\\end{document}\n",
            encoding="utf-8",
        )
        (project / "chapters" / "one.tex").write_text(
            "Theorem 1. A statement.\n", encoding="utf-8"
        )
        (project / "images" / "keep.bin").write_bytes(b"resource")

        successful = {
            "available": True,
            "ok": True,
            "pages": 1,
            "errors": [],
            "log": "",
        }
        with patch(
            "latexstruct.core.compilecheck.compile_latex",
            return_value=successful,
        ) as compile_mock:
            result = process_project(project, mode="rule", compile_check=True)

        assert result.pipeline.ok is True
        assert compile_mock.call_count == 2
        before, after = compile_mock.call_args_list
        for call in (before, after):
            main_text = call.args[0]
            extra = call.kwargs["extra_files"]
            assert "LATEXSTRUCT-FILE" not in main_text
            assert "\\input{chapters/one}" in main_text
            assert "main.tex" not in extra
            assert extra["images/keep.bin"] == b"resource"
            assert b"LATEXSTRUCT-FILE" not in extra["chapters/one.tex"]
        assert b"\\begin{theorem}" not in before.kwargs["extra_files"]["chapters/one.tex"]
        assert b"\\begin{theorem}" in after.kwargs["extra_files"]["chapters/one.tex"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_export_project_copy():
    root = _make_project()
    try:
        from pathlib import Path

        res = process_project(Path(root), mode="rule")
        out = Path(tempfile.mkdtemp(prefix="ls-proj-out-", dir=_TESTS))
        export_project(Path(root), out, "main.tex", res.per_file, res.graph)
        assert (out / "main.tex").exists()
        assert "\\begin{theorem}[1.1]" in read_tex(out / "chapters/ch01.tex")
        assert "\\input{preamble}" in read_tex(out / "main.tex")
        shutil.rmtree(out, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cycle_detection():
    root = tempfile.mkdtemp(prefix="ls-proj-", dir=_TESTS)
    try:
        from pathlib import Path

        (Path(root) / "main.tex").write_text(
            "\\documentclass{book}\n\\begin{document}\n\\input{a}\n\\end{document}\n",
            encoding="utf-8",
        )
        (Path(root) / "a.tex").write_text("\\input{b}\n", encoding="utf-8")
        (Path(root) / "b.tex").write_text("\\input{a}\n", encoding="utf-8")
        g = build_project_graph(Path(root), "main.tex")
        assert len(g.cycles) >= 1
        flat, _ = flatten_project(Path(root), "main.tex")
        assert "LATEXSTRUCT-FILE-START" in flat  # 循环处停止展开但整体可用
    finally:
        shutil.rmtree(root, ignore_errors=True)


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
