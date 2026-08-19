# -*- coding: utf-8 -*-
"""Real OCR/AI structure regressions distilled from ``OCR-OCR-P1-24``.

The original failed draft was a 24-page set of Ramsey theory lecture notes.
These fixtures intentionally keep only the structural boundaries that failed;
they do not need a model, a network connection, or the user's local project.
"""

from __future__ import annotations

import re
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.invariants import check_image_resources, check_invariants
from latexstruct.core.legalize import legalize_decisions
from latexstruct.core.ocrstruct import (
    build_ocr_structure_ops,
    check_ocr_structure,
    encode_ocr_metadata,
)
from latexstruct.core.parser import parse_latex
from latexstruct.core.patch import (
    Decision,
    PatchContext,
    apply_patches,
    build_ops,
)
from latexstruct.core.scanner import scan
from latexstruct.core.verify import check_display_tag_safety, check_env_balance


def _apply_ocr_structure(text: str) -> tuple[str, list[dict]]:
    ops, notes = build_ocr_structure_ops(text)
    decision = Decision(candidate_id="real-ocr-structure", action="none")
    out, applied, rejected = apply_patches(text.split("\n"), [(decision, ops)])
    assert rejected == []
    assert applied, "the real OCR fixture must produce at least one safe edit"
    return "\n".join(out), notes


def _line_number(lines: list[str], exact: str) -> int:
    return lines.index(exact) + 1


def test_real_manual_contents_is_replaced_by_one_generated_toc() -> None:
    """The printed page-number list must never become the finished TOC."""
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "Ramsey numbers", "page": 4},
            {"level": 1, "title": "History", "page": 4},
        ],
        "book",
        [3, 4],
        True,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 3",
            r"\section*{Contents}",
            r"Introduction \dotfill i",
            r"1 \textbf{Ramsey numbers} \dotfill 1",
            r"\quad 1.1 \quad History \dotfill 1",
            r"\vfill",
            # This exact wrapper ended the real printed TOC and previously made
            # the conservative recognizer reject the whole replacement.
            r"\hbox{ii}",
            r"\clearpage",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 4",
            r"\section*{Chapter 1}",
            r"\section*{Ramsey numbers}",
            r"\subsection*{1.1 History}",
            "Body.",
            r"\end{document}",
        ]
    )

    result, _notes = _apply_ocr_structure(source)

    assert len(re.findall(r"(?m)^\\tableofcontents\s*$", result)) == 1
    assert r"\section*{Contents}" not in result
    assert r"\dotfill" not in result
    assert r"\hbox{ii}" not in result
    assert r"\chapter{Ramsey numbers}" in result
    assert r"\section{History}" in result
    assert check_ocr_structure(result)["ok"] is True


def test_commented_toc_cannot_satisfy_outline_gate() -> None:
    metadata = encode_ocr_metadata(
        [{"level": 0, "title": "Contents", "page": 1}],
        "book",
        [1],
        True,
    )
    source = "\n".join([
        r"\documentclass{book}",
        r"\begin{document}",
        metadata,
        r"% Page 1",
        r"% \tableofcontents",
        r"\end{document}",
    ])
    structure = check_ocr_structure(source)
    assert structure["ok"] is False
    assert any("没有 \\tableofcontents" in item["reason"] for item in structure["issues"])


def test_real_outline_uses_unstarred_commands_at_pdf_bookmark_levels() -> None:
    """Lock the four headings that were missing or one level too deep."""
    metadata = encode_ocr_metadata(
        [
            {
                "level": 0,
                "title": "Hermitian unitals and the lower bound for r(4,t)",
                "page": 10,
            },
            {"level": 1, "title": "The Zarankiewicz viewpoint", "page": 16},
            {"level": 0, "title": "Bradač's recent result", "page": 17},
            {"level": 1, "title": "From a digraph to a graph", "page": 18},
            {"level": 1, "title": "From antiflags to flags", "page": 21},
            {"level": 2, "title": "Big bites and small bites", "page": 21},
        ],
        "book",
        [10, 16, 17, 18, 21],
        False,
    )
    source = "\n".join(
        [
            r"\documentclass[11pt]{book}",
            r"\begin{document}",
            metadata,
            r"% Page 10",
            r"\section*{Chapter 3}",
            r"\section*{Hermitian unitals and the lower bound for $r(4,t)$}",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 16",
            r"\subsection*{3.9 The Zarankiewicz viewpoint}",
            r"%=== PAGE BREAK === 第 3 段",
            r"% Page 17",
            r"\section*{Chapter 4}",
            r"\section*{Bradač's recent result}",
            r"%=== PAGE BREAK === 第 4 段",
            r"% Page 18",
            r"\subsection*{4.3 \quad From a digraph to a graph}",
            r"%=== PAGE BREAK === 第 5 段",
            r"% Page 21",
            r"\subsection*{4.5 From antiflags to flags}",
            r"\subsubsection*{4.5.1 Big bites and small bites}",
            r"\end{document}",
        ]
    )

    result, _notes = _apply_ocr_structure(source)

    expected = (
        r"\chapter{Hermitian unitals and the lower bound for $r(4,t)$}",
        r"\section{The Zarankiewicz viewpoint}",
        r"\chapter{Bradač's recent result}",
        r"\section{From a digraph to a graph}",
        r"\section{From antiflags to flags}",
        r"\subsection{Big bites and small bites}",
    )
    for command in expected:
        assert command in result, result
    assert not re.search(
        r"\\(?:chapter|section|subsection|subsubsection)\*\s*\{(?:3\.|4\.|Chapter)",
        result,
    )
    assert not re.search(
        r"\\(?:chapter|section|subsection|subsubsection)\s*\{\\quad\b",
        result,
    )
    structure = check_ocr_structure(result)
    assert structure["ok"] is True, structure["issues"]
    assert structure["matched"] == len(expected)


def test_real_ai_spans_snap_after_display_equation_tag_and_matrix() -> None:
    """AI line spans may be imprecise, but closers may never split math."""
    source = "\n".join(
        [
            r"\documentclass{book}",
            r"\usepackage{amsmath}",
            r"\begin{document}",
            "",
            r"\textbf{Theorem 3.1}. There is a constant $c>0$ such that",
            r"\[",
            r"r(4,t) \ge c\frac{t^3}{(\log t)^4}",
            r"\]",
            r"\textit{for all $t\ge3$.}",
            "",
            r"\textbf{Theorem 4.1}. For every fixed $s\ge3$ one has",
            r"\begin{equation}",
            r"r(s,t) \ge c_s\frac{t^{s-1}}{(\log t)^{2s-4}}.",
            r"\tag{4.1}",
            r"\end{equation}",
            "",
            "Proof. Therefore",
            r"\[",
            r"AB=\begin{pmatrix}0&a&b\\-a&0&c\\-b&-c&0\end{pmatrix}",
            r"\]",
            r"is singular, a contradiction. \hfill $\square$",
            "",
            r"\end{document}",
        ]
    )
    lines = source.split("\n")
    doc = parse_latex(source)
    candidates = scan(doc).candidates
    theorem_candidates = [item for item in candidates if item.kind == "theorem-like"]
    proof_candidate = next(item for item in candidates if item.kind == "proof")
    assert len(theorem_candidates) == 2

    first_display_open = _line_number(lines, r"\[")
    equation_formula = _line_number(
        lines, r"r(s,t) \ge c_s\frac{t^{s-1}}{(\log t)^{2s-4}}."
    )
    matrix_formula = _line_number(
        lines,
        r"AB=\begin{pmatrix}0&a&b\\-a&0&c\\-b&-c&0\end{pmatrix}",
    )
    decisions = [
        Decision(
            candidate_id=theorem_candidates[0].id,
            action="wrap",
            env="theorem*",
            source="ai",
            body_span=(theorem_candidates[0].span.start_line, first_display_open),
        ),
        Decision(
            candidate_id=theorem_candidates[1].id,
            action="wrap",
            env="theorem*",
            source="ai",
            body_span=(theorem_candidates[1].span.start_line, equation_formula),
        ),
        Decision(
            candidate_id=proof_candidate.id,
            action="wrap",
            env="proof",
            source="ai",
            body_span=(proof_candidate.span.start_line, matrix_formula),
        ),
    ]
    by_id = {item.id: item for item in candidates}

    legalize_decisions(doc, decisions, by_id)

    equation_close = _line_number(lines, r"\end{equation}")
    matrix_display_close = max(
        index for index, line in enumerate(lines, start=1) if line == r"\]"
    )
    # The first model range omits the qualifier between the display and the
    # next theorem.  Snapping only to ``\]`` would create a balanced but
    # semantically truncated theorem, so the new boundary gate rejects it.
    assert "漏段" in getattr(decisions[0], "_legalize_error", "")
    assert decisions[1].body_span[1] >= equation_close, [d.body_span for d in decisions]
    assert decisions[2].body_span[1] >= matrix_display_close

    context = PatchContext(preamble_anchor=3)
    planned = []
    for decision in decisions[1:]:
        ops, error = build_ops(decision, lines, context)
        assert error == ""
        planned.append((decision, ops))
    out, _applied, rejected = apply_patches(lines, planned)
    assert rejected == []
    result = "\n".join(out)

    assert check_env_balance(result)["ok"] is True
    assert check_display_tag_safety(result)["ok"] is True
    invariants = check_invariants(source, result)
    assert invariants["math"]["equal"] is True, invariants["math"]


def test_real_broken_draft_cannot_pass_math_or_environment_guards() -> None:
    """The exact two premature-closer shapes from the failed draft stay blocked."""
    broken = "\n".join(
        [
            r"\begin{theorem*}[3.1]",
            r"\[",
            r"\end{theorem*}",
            r"r(4,t) \ge c\frac{t^3}{(\log t)^4}",
            r"\]",
            r"\begin{theorem*}[4.1]",
            r"\begin{equation}",
            r"r(s,t) \ge c_s\frac{t^{s-1}}{(\log t)^{2s-4}}.",
            r"\end{theorem*}",
            r"\tag{4.1}",
            r"\end{equation}",
        ]
    )

    display = check_display_tag_safety(broken)
    environments = check_env_balance(broken)
    assert display["ok"] is False
    assert any(r"\end{theorem*}" in item["reason"] for item in display["issues"])
    assert environments["ok"] is False
    assert any(item.get("env") in {"theorem*", "equation"} for item in environments["issues"])


def test_real_page_furniture_is_never_silently_accepted() -> None:
    """Repeated running heads and printed folios must be removed or block export."""
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First result", "page": 11},
            {"level": 0, "title": "Second result", "page": 12},
        ],
        "book",
        [11, 12],
        False,
    )
    source = "\n".join(
        [
            r"\documentclass{book}",
            r"\begin{document}",
            metadata,
            r"% Page 11",
            "Off-diagonal Ramsey numbers",
            r"\chapter{First result}",
            "First page body.",
            r"\hrule",
            r"\begin{center}",
            "8",
            r"\end{center}",
            r"\clearpage",
            r"%=== PAGE BREAK === 第 2 段",
            r"% Page 12",
            r"\noindent Off-diagonal Ramsey numbers",
            r"\chapter{Second result}",
            "Second page body.",
            r"\centerline{12}",
            r"\end{document}",
        ]
    )

    result, _notes = _apply_ocr_structure(source)
    header_remains = bool(
        re.search(
            r"(?mi)^\s*(?:\\noindent\s*)?Off-diagonal Ramsey numbers\s*$",
            result,
        )
    )
    footer_remains = bool(
        re.search(r"(?m)^\s*\\centerline\{\d+\}\s*$", result)
        or re.search(
            r"(?ms)^\s*\\hrule\s*\n\\begin\{center\}\s*\n\d+\s*\n\\end\{center\}\s*$",
            result,
        )
    )
    structure = check_ocr_structure(result)

    # Automatic removal is preferred; conservative rejection is also safe.
    assert not ((header_remains or footer_remains) and structure["ok"]), (
        "OCR page furniture remained active but the outline safety gate accepted it"
    )


def test_real_hfill_numeric_folios_are_removed_or_block_export() -> None:
    metadata = encode_ocr_metadata(
        [
            {"level": 0, "title": "First result", "page": 11},
            {"level": 0, "title": "Second result", "page": 12},
        ],
        "book",
        [11, 12],
        False,
    )
    source = "\n".join([
        r"\documentclass{book}",
        r"\begin{document}",
        metadata,
        r"% Page 11",
        r"\chapter{First result}",
        "First page body.",
        r"\hfill 8",
        r"\clearpage",
        r"%=== PAGE BREAK === 第 2 段",
        r"% Page 12",
        r"\chapter{Second result}",
        "Second page body.",
        r"\hfill 12",
        r"\end{document}",
    ])
    result, _notes = _apply_ocr_structure(source)
    remains = bool(re.search(r"(?mi)^\s*\\hfill\s*(?:8|12)\s*$", result))
    structure = check_ocr_structure(result)
    assert not (remains and structure["ok"]), (
        "numeric \\hfill folios remained active but the OCR safety gate accepted them"
    )


def test_real_missing_ocr_images_are_exactly_reported_and_then_resolve() -> None:
    """The five paths from the failed run cannot be treated as decorative text."""
    paths = [
        "images/page_08_01",
        "images/page_9_1",
        "images/page_15_0",
        "images/page_15_1",
        "images/page_15_2",
    ]
    text = "\n".join(
        rf"\includegraphics[width=.6\linewidth]{{{path}}}" for path in paths
    )

    with tempfile.TemporaryDirectory(prefix="ls-real-ocr-") as directory:
        root = Path(directory)
        missing = check_image_resources(text, str(root))
        assert missing["ok"] is False
        assert missing["unsafe"] == []
        assert set(missing["missing"]) == set(paths)

        image_dir = root / "images"
        image_dir.mkdir()
        for path in paths:
            (root / f"{path}.png").write_bytes(b"real-embedded-image")
        resolved = check_image_resources(text, str(root))
        assert resolved["ok"] is True
        assert resolved["count"] == len(paths)


def main() -> None:
    import traceback

    tests = [
        (name, function)
        for name, function in sorted(globals().items())
        if name.startswith("test_") and callable(function)
    ]
    failed = 0
    for name, function in tests:
        try:
            function()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
