# -*- coding: utf-8 -*-

from latexstruct.core.ocr_baseline import compile_ocr_baseline
from latexstruct.core.ocr_runtime import OcrPreviewStatus


def _artifact(*, ok, pdf=b"", code=1, errors=()):
    return {
        "engine": "xelatex.exe",
        "ok": ok,
        "exit_code": code,
        "passes_completed": 1 if ok else 0,
        "pdf_bytes": pdf,
        "errors": list(errors),
        "log": "real compiler log",
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
