# -*- coding: utf-8 -*-
"""多层不变量与编译校验测试。"""

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.compilecheck import compile_latex  # noqa: E402
from latexstruct.core.invariants import (  # noqa: E402
    check_image_resources,
    check_invariants,
    cites,
    image_paths,
    labels,
    math_tokens,
    refs,
)
from latexstruct.core.pipeline import run_pipeline  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


SIMPLE = (
    "\\documentclass{book}\n\\usepackage{amsmath}\n\\usepackage{graphicx}\n\\begin{document}\n\n"
    "\\section{Intro}\\label{sec:intro}\n\n"
    "Inline math \\(a+b\\) and $c^2$ and display \\[\\int_0^1 x\\,dx\\]\n\n"
    "\\begin{equation}\\label{eq:main}\nE = mc^2\n\\end{equation}\n\n"
    "See \\ref{sec:intro} and \\eqref{eq:main} and \\cite{knuth84}.\n\n"
    "\\includegraphics[width=.5\\linewidth]{figures/plot.png}\n\n"
    "\\end{document}\n"
)


def _tiny_png() -> bytes:
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"\x00" + b"\x00\x00\x00\x00" * 4  # 1x1 RGBA（filter + 4 字节）
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_math_tokens_extraction():
    toks = math_tokens(SIMPLE)
    assert any("a+b" in t for t in toks)
    assert any("c^2" in t for t in toks)
    assert any("int_0^1" in t for t in toks)
    assert any("E = mc^2" in t for t in toks)


def test_label_ref_cite_image_collections():
    assert labels(SIMPLE) == ["eq:main", "sec:intro"]
    assert refs(SIMPLE) == ["eq:main", "sec:intro"]
    assert cites(SIMPLE) == ["knuth84"]
    assert image_paths(SIMPLE) == ["figures/plot.png"]
    spaced = (
        r"\label {sec:spaced}\autoref {sec:spaced}"
        r"\citep[see][p. 2]{key}\includegraphics* [width=1cm] {figures/a b.png}"
    )
    assert labels(spaced) == ["sec:spaced"]
    assert refs(spaced) == ["sec:spaced"]
    assert cites(spaced) == ["key"]
    assert image_paths(spaced) == ["figures/a b.png"]


def test_image_resources_follow_safe_graphicspath_and_reject_escape():
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ls-image-", dir=os.path.dirname(__file__)) as root:
        image_dir = os.path.join(root, "images")
        os.makedirs(image_dir)
        with open(os.path.join(image_dir, "plot.png"), "wb") as stream:
            stream.write(_tiny_png())
        text = r"\graphicspath{{./images/}}\includegraphics{plot}"
        check = check_image_resources(text, root)
        assert check["ok"] is True and check["count"] == 1

        escaped = check_image_resources(
            r"\graphicspath{{../outside/}}\includegraphics{plot}", root
        )
        assert escaped["ok"] is False
        assert "graphicspath:../outside/" in escaped["unsafe"]

        missing = check_image_resources(r"\includegraphics{not-there}", root)
        assert missing["ok"] is False and missing["missing"] == ["not-there"]


def test_invariants_equal_on_same_text():
    out = check_invariants(SIMPLE, SIMPLE)
    assert out["ok"] is True
    for key in ("math", "labels", "refs", "cites", "images"):
        assert out[key]["equal"] is True


def test_invariants_detect_content_change():
    changed = SIMPLE.replace("E = mc^2", "E = mc^3")
    out = check_invariants(SIMPLE, changed)
    assert out["math"]["equal"] is False
    # label 新增也应检出
    out2 = check_invariants(SIMPLE, SIMPLE.replace("\\section{Intro}", "\\section{Intro}\\label{sec:x}"))
    assert out2["labels"]["equal"] is False


def test_invariants_preserve_duplicate_reference_counts():
    before = SIMPLE.replace(
        "See \\ref{sec:intro}",
        "See \\ref{sec:intro} and again \\ref{sec:intro}",
    )
    out = check_invariants(before, SIMPLE)
    assert out["refs"]["equal"] is False
    assert out["refs"]["before_count"] == out["refs"]["after_count"] + 1


def test_pipeline_invariants_pass():
    res = run_pipeline(read_sample("basic_book.tex"), mode="rule")
    assert res.ok
    inv = res.verification["invariants"]
    assert inv["ok"] is True
    assert "多层不变量校验" in res.report_md
    assert "数学公式 token" in res.report_md
    assert res.verification["safe_to_export"] is True
    assert res.verification["rolled_back"] is False
    assert all(c["ok"] for c in res.verification["checks"])


def test_compile_latex_ok_and_broken():
    c = compile_latex(SIMPLE, timeout=120, extra_files={"figures/plot.png": _tiny_png()})
    if not c["available"]:
        print("xelatex not available, skip compile test")
        return
    assert c["ok"] is True and c["pages"] == 1, c
    broken = SIMPLE.replace("\\end{document}", "\\begin{broken}")
    c2 = compile_latex(broken, timeout=120)
    assert c2["ok"] is False or c2["errors"], c2


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
