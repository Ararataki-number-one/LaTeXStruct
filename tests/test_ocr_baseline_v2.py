# -*- coding: utf-8 -*-

import hashlib

import pytest

from latexstruct.core import compilecheck, ocr_baseline
from latexstruct.core.ocr_baseline import (
    OcrBaselineResult,
    OcrCompileInvocationEvidence,
    compile_ocr_baseline,
)
from latexstruct.core.ocr_runtime import OcrPreviewStatus


def _artifact(
    *,
    ok,
    pdf=b"",
    code=1,
    errors=(),
    log="real compiler log",
    engine="xelatex.exe",
    passes_completed=None,
    fatal_line=None,
):
    return {
        "engine": engine,
        "ok": ok,
        "exit_code": code,
        "passes_completed": (
            1 if ok else 0
        ) if passes_completed is None else passes_completed,
        "pdf_bytes": pdf,
        "errors": list(errors),
        "fatal_line": fatal_line,
        "log": log,
    }


def test_baseline_requires_two_real_successful_compiles(monkeypatch):
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        return _artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0)

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline("\\begin{document}x\\end{document}")
    assert len(calls) == 2
    assert result.preview_status == OcrPreviewStatus.COMPILED
    assert result.successful_passes == 2
    assert [item.sequence for item in result.compile_invocations] == [1, 2]
    assert all(item.exit_code == 0 and item.ok is True for item in result.compile_invocations)
    expected_sha = hashlib.sha256(calls[0].encode()).hexdigest()
    assert {item.input_tex_sha256 for item in result.compile_invocations} == {expected_sha}


def test_baseline_only_applies_host_syntax_repairs(monkeypatch):
    source = "\\begin{document}\n\\begin{equation}\n\n x=1\n\\end{equation}\n\\end{document}"
    seen = []

    def compile_once(text, **_kwargs):
        seen.append(text)
        if len(seen) == 1:
            return _artifact(ok=False, errors=("blank paragraph",))
        return _artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0)

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(source)
    assert len(seen) == 3
    assert "\\begin{equation}\n\n" not in result.tex
    assert "x=1" in result.tex
    assert result.preview_status == OcrPreviewStatus.COMPILED
    assert len(result.compile_invocations) == 3
    assert result.compile_invocations[0].input_tex_sha256 != result.compile_invocations[1].input_tex_sha256
    assert (
        result.compile_invocations[1].input_tex_sha256
        == result.compile_invocations[2].input_tex_sha256
        == hashlib.sha256(result.tex.encode()).hexdigest()
    )


def test_baseline_repairs_only_each_compiler_confirmed_bare_formula(monkeypatch):
    first_formula = r"2^{k/2} \le R(k) \le 4^k \qquad (1)"
    second_formula = r"R(k) \le (4-\varepsilon)^k"
    source = "\n".join((
        r"\documentclass{article}",
        r"\begin{document}",
        "The bounds",
        "",
        first_formula,
        "",
        "There exists a constant such that",
        "",
        second_formula,
        "",
        "for all sufficiently large values.",
        r"\end{document}",
    ))
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        for formula in (first_formula, second_formula):
            if f"\\[\n{formula}\n\\]" not in text:
                fatal_line = text.split("\n").index(formula) + 1
                return _artifact(
                    ok=False,
                    errors=(f"Missing $ inserted. @l.{fatal_line}",),
                    fatal_line=fatal_line,
                )
        return _artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0)

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(source)

    assert len(calls) == 4
    assert result.preview_status == OcrPreviewStatus.COMPILED
    assert result.successful_passes == 2
    assert result.tex.count("\\[") == result.tex.count("\\]") == 2
    assert first_formula in result.tex and second_formula in result.tex
    assert source.split("\n")[4] == first_formula
    assert [note["status"] for note in result.syntax_repairs] == [
        "repaired-missing-math-delimiters",
        "repaired-missing-math-delimiters",
    ]


@pytest.mark.parametrize(
    "line",
    [
        "1. Introduction",
        "Use x^2 in examples.",
        "Version 2.0 = stable candidate",
        r"\section{Growth of x^2}",
        r"\includegraphics[width=0.5\linewidth]{figures/a_b.png}",
        r"Text already contains $x_y$ inline.",
    ],
)
def test_missing_math_diagnostic_does_not_wrap_prose_or_structural_lines(
    monkeypatch,
    line,
):
    source = "\n".join((
        r"\begin{document}",
        "",
        line,
        "",
        r"\end{document}",
    ))
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        return _artifact(
            ok=False,
            errors=("Missing $ inserted. @l.3",),
            fatal_line=3,
        )

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(source)

    assert calls == [source]
    assert result.tex == source
    assert result.syntax_repairs == ()
    assert result.preview_status == OcrPreviewStatus.SOURCE_PREVIEW


def test_bare_formula_is_not_repaired_without_matching_compiler_diagnostic(monkeypatch):
    source = "\n".join((
        r"\begin{document}",
        r"R(k) \le (4-\varepsilon)^k",
        r"\end{document}",
    ))
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        return _artifact(
            ok=False,
            errors=("Undefined control sequence. @l.2",),
            fatal_line=2,
        )

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(source)

    assert calls == [source]
    assert result.tex == source
    assert result.syntax_repairs == ()


def test_baseline_never_guesses_or_removes_forbidden_control_characters(monkeypatch):
    source = "\n".join((
        r"\begin{document}",
        "",
        "Visible \x18locally-sparse\x19 prose.",
        "",
        r"\end{document}",
    ))
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        return _artifact(
            ok=False,
            errors=("Text line contains an invalid character. @l.3",),
            fatal_line=3,
        )

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(source)

    assert calls == [source]
    assert result.tex == source
    assert "\x18" in result.tex and "\x19" in result.tex
    assert result.syntax_repairs == ()
    assert result.preview_status == OcrPreviewStatus.SOURCE_PREVIEW


def test_missing_math_repair_refuses_formula_already_inside_display_math():
    formula = r"R(k) \le (4-\varepsilon)^k"
    lines = [
        r"\begin{document}",
        r"\[",
        "",
        formula,
        "",
        r"\]",
        r"\end{document}",
    ]

    operations, notes = ocr_baseline._missing_math_repair_ops(
        lines,
        {
            "errors": ["Missing $ inserted. @l.4"],
            "fatal_line": 4,
        },
    )

    assert operations == []
    assert notes == []


def test_missing_math_repair_requires_an_isolated_paragraph_line():
    formula = r"R(k) \le (4-\varepsilon)^k"
    lines = [
        r"\begin{document}",
        "There exists a constant such that",
        formula,
        "",
        r"\end{document}",
    ]

    operations, notes = ocr_baseline._missing_math_repair_ops(
        lines,
        {
            "errors": ["Missing $ inserted. @l.3"],
            "fatal_line": 3,
        },
    )

    assert operations == []
    assert notes == []


def test_missing_math_diagnostic_must_bind_the_same_fatal_line():
    formula = r"R(k) \le (4-\varepsilon)^k"
    lines = [
        r"\begin{document}",
        "",
        formula,
        "",
        "More text",
        "",
        r"x^2 \le y^2",
        "",
        r"\end{document}",
    ]

    operations, notes = ocr_baseline._missing_math_repair_ops(
        lines,
        {
            "errors": [
                "Undefined control sequence. @l.3",
                "Missing $ inserted. @l.7",
            ],
            "fatal_line": 3,
        },
    )

    assert operations == []
    assert notes == []


def test_real_ramsey_bare_formula_repair_compiles_when_xelatex_is_available():
    if not compilecheck.find_xelatex():
        pytest.skip("xelatex is unavailable")
    source = "\n".join((
        r"\documentclass{article}",
        r"\usepackage{amsmath}",
        r"\begin{document}",
        "The bounds",
        "",
        r"2^{k/2} \le R(k) \le 4^k \qquad (1)",
        "",
        "There exists a constant such that",
        "",
        r"R(k) \le (4-\varepsilon)^k",
        "",
        "for all sufficiently large values.",
        r"\end{document}",
    ))

    result = compile_ocr_baseline(source)

    assert result.preview_status == OcrPreviewStatus.COMPILED
    assert result.successful_passes == 2
    assert len(result.compile_invocations) == 4
    assert result.pdf_bytes.startswith(b"%PDF-")
    assert [note["status"] for note in result.syntax_repairs] == [
        "repaired-missing-math-delimiters",
        "repaired-missing-math-delimiters",
    ]


def test_source_preview_is_explicit_when_no_pdf(monkeypatch):
    monkeypatch.setattr(
        "latexstruct.core.ocr_baseline.compile_latex_artifact",
        lambda *_args, **_kwargs: _artifact(ok=False, errors=("fatal",)),
    )
    result = compile_ocr_baseline("plain text")
    assert result.preview_status == OcrPreviewStatus.SOURCE_PREVIEW
    assert result.pdf_bytes.startswith(b"%PDF-")
    assert "这不是 LaTeX 编译结果" in result.log
    import pymupdf

    document = pymupdf.open(stream=result.pdf_bytes, filetype="pdf")
    try:
        assert "NOT A LATEX COMPILE RESULT" in document[0].get_text().upper()
        assert "plain text" in "".join(page.get_text() for page in document[1:])
    finally:
        document.close()


def test_compile_invocation_evidence_keeps_each_raw_log_and_hash_separate(monkeypatch):
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        index = len(calls)
        return _artifact(
            ok=True,
            pdf=f"%PDF-1.7\nresult-{index}".encode(),
            code=0,
            log=f"independent compiler log {index}",
            engine=r"C:\private\texlive\xelatex.exe",
        )

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline("\\begin{document}x\\end{document}")

    evidence = result.compile_invocation_dicts()
    assert len(calls) == len(evidence) == 2
    assert [item["sequence"] for item in evidence] == [1, 2]
    assert [item["log"] for item in evidence] == [
        "independent compiler log 1",
        "independent compiler log 2",
    ]
    assert all(item["engine"] == "xelatex.exe" for item in evidence)
    assert all(item["ok"] is True and item["exit_code"] == 0 for item in evidence)
    assert all(
        item["log_sha256"] == hashlib.sha256(item["log"].encode()).hexdigest()
        for item in evidence
    )
    assert evidence[0]["evidence_sha256"] != evidence[1]["evidence_sha256"]


def test_compile_invocation_evidence_carries_actual_private_safe_execution_metadata(
    monkeypatch,
):
    extra_files = {"figures/plot.pdf": b"real figure bytes"}
    call_count = 0

    def compile_once(text, **kwargs):
        nonlocal call_count
        call_count += 1
        assert kwargs["extra_files"] == extra_files
        input_manifest = compilecheck.build_compile_input_manifest(text, extra_files)
        command = [
            "xelatex.exe",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "main.tex",
        ]
        return {
            **_artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0),
            "command": command,
            "command_history": [command],
            "compile_workdir": (
                compilecheck.COMPILE_WORKDIR_ID_PREFIX + f"{call_count:064x}"
            ),
            "input_manifest": input_manifest,
            "compile_input_sha256": input_manifest["manifest_sha256"],
        }

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline(
        "\\begin{document}x\\end{document}",
        extra_files=extra_files,
    )

    evidence = result.compile_invocation_dicts()
    assert len(evidence) == 2
    for item in evidence:
        assert item["command"] == [
            "xelatex.exe",
            "-interaction=nonstopmode",
            "-halt-on-error",
            "main.tex",
        ]
        assert item["command_history"] == [item["command"]]
        assert item["compile_workdir"].startswith(
            compilecheck.COMPILE_WORKDIR_ID_PREFIX
        )
        assert item["compile_input_sha256"]
        assert item["input_inventory"] == sorted(
            item["input_inventory"], key=lambda entry: entry["path"]
        )
        assert {entry["path"] for entry in item["input_inventory"]} == {
            "figures/plot.pdf",
            "main.tex",
        }
        assert all(
            set(entry) == {"path", "bytes", "sha256"}
            for entry in item["input_inventory"]
        )
        serialized = repr(item)
        assert "C:\\" not in serialized
        assert "C:/" not in serialized


def test_compile_invocation_rejects_inventory_not_bound_to_actual_candidate(monkeypatch):
    wrong_manifest = compilecheck.build_compile_input_manifest("different candidate")

    def compile_once(*_args, **_kwargs):
        command = ["xelatex", "-halt-on-error", "main.tex"]
        return {
            **_artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0),
            "command": command,
            "command_history": [command],
            "compile_workdir": compilecheck.COMPILE_WORKDIR_ID_PREFIX + ("a" * 64),
            "input_manifest": wrong_manifest,
            "compile_input_sha256": wrong_manifest["manifest_sha256"],
        }

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    with pytest.raises(ValueError, match="does not bind the candidate TeX"):
        compile_ocr_baseline("actual candidate")


def test_internal_pass_count_cannot_masquerade_as_two_independent_invocations(monkeypatch):
    calls = []

    def compile_once(text, **_kwargs):
        calls.append(text)
        return _artifact(
            ok=True,
            pdf=b"%PDF-1.7\nreal",
            code=0,
            passes_completed=2,
            log=f"compiler call {len(calls)} claims two internal passes",
        )

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline("\\begin{document}x\\end{document}")

    assert len(calls) == 2
    assert len(result.compile_invocations) == 2
    assert result.successful_passes == 2
    assert result.compile_invocations[0].passes_completed == 2
    assert result.compile_invocations[0].sequence == 1


@pytest.mark.parametrize(
    "artifact",
    [
        _artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=7),
        _artifact(ok=True, pdf=b"%PDF-1.7\nreal", code=0, log=""),
        _artifact(ok=True, pdf=b"not pdf", code=0),
    ],
)
def test_optimistic_ok_flag_without_exit_log_and_pdf_evidence_fails_closed(
    monkeypatch, artifact,
):
    calls = []

    def compile_once(*_args, **_kwargs):
        calls.append(1)
        return dict(artifact)

    monkeypatch.setattr("latexstruct.core.ocr_baseline.compile_latex_artifact", compile_once)
    result = compile_ocr_baseline("plain text")

    assert len(calls) == 1
    assert result.successful_passes == 0
    assert result.preview_status != OcrPreviewStatus.COMPILED
    assert len(result.compile_invocations) == 1


def test_evidence_value_object_rejects_contradictory_pass_counters():
    with pytest.raises(ValueError, match="pass counters"):
        OcrCompileInvocationEvidence(
            sequence=1,
            exit_code=0,
            ok=True,
            engine="xelatex",
            log="real log",
            input_tex_sha256="a" * 64,
            output_pdf_sha256="b" * 64,
            passes_requested=1,
            passes_attempted=1,
            passes_completed=2,
        )


def test_existing_result_construction_remains_compatible_without_new_evidence():
    result = OcrBaselineResult(
        tex="baseline",
        log="legacy aggregate log",
        preview_status=OcrPreviewStatus.COMPILED,
        pdf_bytes=b"%PDF-1.7\nlegacy",
        exit_code=0,
        successful_passes=2,
        syntax_repairs=(),
        error_lines=(),
        engine="xelatex",
    )
    assert result.compile_invocations == ()
    assert result.compile_invocation_dicts() == ()
