# -*- coding: utf-8 -*-
"""Build a fast, lossless-page Bondy hybrid book with XeLaTeX.

This deliberately is not a reflowed OCR edition.  It places physical source PDF
pages 3--473 as vector PDF page XObjects on a fixed 155 x 235 mm sheet, retaining
the original searchable text and embedded fonts.  Source outline entries create
the 17 chapter bookmarks, while a deterministic JSON manifest records page,
chapter, text and graphic evidence plus SHA-256 digests.

Examples::

    python tools/build_bondy_fast_hybrid.py --sample
    python tools/build_bondy_fast_hybrid.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PAPER_WIDTH_MM = 155.0
PAPER_HEIGHT_MM = 235.0
DEFAULT_START_PAGE = 3
DEFAULT_END_PAGE = 473
DEFAULT_SAMPLE_END_PAGE = 16
EXPECTED_FULL_PAGES = 471
EXPECTED_CHAPTERS = 17
CHAPTER_RE = re.compile(r"^(?P<number>\d+)\s+(?P<title>.+?)\s*$")
VISIBLE_WORD_RE = re.compile(r"[^\W_]+(?:[’'][^\W_]+)*", re.UNICODE)
LIGATURE_TRANSLATION = str.maketrans({
    "ﬀ": "ff",
    "ﬁ": "fi",
    "ﬂ": "fl",
    "ﬃ": "ffi",
    "ﬄ": "ffl",
    "ﬅ": "st",
    "ﬆ": "st",
})


class BuildError(RuntimeError):
    """A deterministic build or verification failure."""


@dataclass(frozen=True)
class Chapter:
    number: int
    title: str
    source_page: int
    source_level: int

    @property
    def bookmark_title(self) -> str:
        return f"{self.number} {self.title}"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_source() -> Path:
    return (
        _repo_root().parent
        / "work"
        / "bondy-v1.2-e2e"
        / "source"
        / "bondy-graph-theory-2e.pdf"
    )


def _default_output_dir() -> Path:
    return _repo_root() / "output" / "pdf" / "bondy-fast-hybrid"


def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _text_sha256(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def _visible_text_base(text: str) -> str:
    return unicodedata.normalize("NFC", str(text)).translate(LIGATURE_TRANSLATION)


def _normalized_visible_text(text: str) -> str:
    """Normalize extraction-only whitespace while preserving visible glyph order."""
    return "".join(char for char in _visible_text_base(text) if not char.isspace())


def _visible_word_sequence(text: str) -> list[str]:
    return VISIBLE_WORD_RE.findall(_visible_text_base(text))


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _tex_escape(text: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "{": r"\{",
        "}": r"\}",
        "$": r"\$",
        "&": r"\&",
        "#": r"\#",
        "%": r"\%",
        "_": r"\_",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in str(text))


def _finite_bbox(value: Any) -> list[float] | None:
    try:
        numbers = [float(item) for item in value]
    except (TypeError, ValueError):
        return None
    if len(numbers) != 4 or not all(math.isfinite(item) for item in numbers):
        return None
    x0, y0, x1, y1 = numbers
    if not (x0 <= x1 and y0 <= y1):
        return None
    return [round(item, 4) for item in numbers]


def _bbox_union(boxes: Iterable[list[float]]) -> list[float]:
    items = [item for item in boxes if item and len(item) == 4]
    if not items:
        return []
    return [
        round(min(item[0] for item in items), 4),
        round(min(item[1] for item in items), 4),
        round(max(item[2] for item in items), 4),
        round(max(item[3] for item in items), 4),
    ]


def _source_chapters(document) -> list[Chapter]:
    chapters: list[Chapter] = []
    for level, raw_title, raw_page in document.get_toc(simple=True):
        match = CHAPTER_RE.fullmatch(str(raw_title or "").strip())
        if match is None:
            continue
        number = int(match.group("number"))
        if not (1 <= number <= EXPECTED_CHAPTERS):
            continue
        chapters.append(Chapter(
            number=number,
            title=match.group("title").strip(),
            source_page=int(raw_page),
            source_level=int(level),
        ))
    chapters.sort(key=lambda item: item.number)
    if [item.number for item in chapters] != list(range(1, EXPECTED_CHAPTERS + 1)):
        raise BuildError("source outline does not contain exactly chapters 1--17")
    if any(
        current.source_page >= following.source_page
        for current, following in zip(chapters, chapters[1:])
    ):
        raise BuildError("source chapter bookmark pages are not strictly increasing")
    return chapters


def _chapter_for_page(chapters: list[Chapter], source_page: int) -> Chapter | None:
    current = None
    for chapter in chapters:
        if chapter.source_page > source_page:
            break
        current = chapter
    return current


def _raster_records(page) -> list[dict]:
    records = []
    seen = set()
    for item in page.get_images(full=True):
        if not item:
            continue
        xref = int(item[0])
        if xref <= 0 or xref in seen:
            continue
        seen.add(xref)
        try:
            rectangles = page.get_image_rects(xref)
        except Exception:  # noqa: BLE001 - manifest evidence is best-effort and bounded
            rectangles = []
        records.append({
            "xref": xref,
            "width_pixels": int(item[2] or 0) if len(item) > 2 else 0,
            "height_pixels": int(item[3] or 0) if len(item) > 3 else 0,
            "bboxes_points": [
                bbox
                for bbox in (_finite_bbox(rect) for rect in rectangles[:32])
                if bbox is not None
            ],
        })
    return records


def _source_manifest(
    source: Path,
    start_page: int,
    end_page: int,
) -> tuple[dict, list[Chapter]]:
    try:
        import fitz  # PyMuPDF
    except ImportError as exc:
        raise BuildError("PyMuPDF is required to inspect and verify the source PDF") from exc

    document = fitz.open(source)
    try:
        if not (1 <= start_page <= end_page <= int(document.page_count)):
            raise BuildError(
                f"source range must be inside 1--{document.page_count}: "
                f"{start_page}--{end_page}"
            )
        chapters = _source_chapters(document)
        selected_chapters = [
            item for item in chapters if start_page <= item.source_page <= end_page
        ]
        page_records = []
        text_records = []
        figure_records = []
        searchable_pages = 0
        total_text_chars = 0
        raster_image_count = 0
        vector_drawing_count = 0
        for output_index, source_page in enumerate(
            range(start_page, end_page + 1), start=1,
        ):
            page = document[source_page - 1]
            text = page.get_text("text")
            drawings = page.get_drawings()
            rasters = _raster_records(page)
            drawing_boxes = [
                bbox
                for bbox in (
                    _finite_bbox(item.get("rect"))
                    for item in drawings
                    if isinstance(item, dict)
                )
                if bbox is not None
            ]
            chapter = _chapter_for_page(chapters, source_page)
            stripped = text.strip()
            if stripped:
                searchable_pages += 1
            total_text_chars += len(text)
            raster_image_count += len(rasters)
            vector_drawing_count += len(drawings)
            page_records.append({
                "output_page": output_index,
                "source_page": source_page,
                "chapter": chapter.number if chapter else None,
                "source_size_points": [
                    round(float(page.rect.width), 4),
                    round(float(page.rect.height), 4),
                ],
                "searchable_text": bool(stripped),
                "text_chars": len(text),
                "raster_image_count": len(rasters),
                "vector_drawing_count": len(drawings),
            })
            text_records.append({
                "output_page": output_index,
                "source_page": source_page,
                "characters": len(text),
                "words": len(page.get_text("words")),
                "sha256_utf8": _text_sha256(text),
                "normalized_visible_sha256": _text_sha256(
                    _normalized_visible_text(text),
                ),
                "visible_word_sequence_sha256": _text_sha256(
                    "\n".join(_visible_word_sequence(text)),
                ),
            })
            figure_records.append({
                "output_page": output_index,
                "source_page": source_page,
                "raster_images": rasters,
                "vector_drawing_count": len(drawings),
                "vector_bbox_union_points": _bbox_union(drawing_boxes),
            })
        if searchable_pages != end_page - start_page + 1:
            raise BuildError("selected source range contains a page without searchable text")
        chapter_records = [{
            "number": item.number,
            "title": item.title,
            "source_bookmark_level": item.source_level,
            "source_page": item.source_page,
            "output_page": item.source_page - start_page + 1,
        } for item in selected_chapters]
        return ({
            "schema_version": 1,
            "edition": "fast_hybrid_vector_page_preservation",
            "reflowed": False,
            "source": {
                "path": str(source),
                "sha256": _sha256(source),
                "pdf_pages": int(document.page_count),
                "selected_physical_pages": [start_page, end_page],
            },
            "target": {
                "paper_mm": [PAPER_WIDTH_MM, PAPER_HEIGHT_MM],
                "expected_pages": end_page - start_page + 1,
            },
            "chapters": chapter_records,
            "pages": page_records,
            "text": {
                "searchable_pages": searchable_pages,
                "total_characters": total_text_chars,
                "records": text_records,
            },
            "figures": {
                "raster_image_count": raster_image_count,
                "vector_drawing_count": vector_drawing_count,
                "records": figure_records,
            },
        }, chapters)
    finally:
        document.close()


def _page_option(start_page: int, end_page: int) -> str:
    return str(start_page) if start_page == end_page else f"{start_page}-{end_page}"


def _include_command(
    start_page: int,
    end_page: int,
    chapter: Chapter | None = None,
) -> str:
    page_command = r"\thispagestyle{empty}"
    if chapter is not None:
        title = _tex_escape(chapter.bookmark_title)
        page_command += (
            rf"\phantomsection\addcontentsline{{toc}}{{chapter}}{{{title}}}"
        )
    return "\n".join([
        r"\includepdf[",
        f"  pages={{{_page_option(start_page, end_page)}}},",
        r"  width=\paperwidth,",
        r"  height=\paperheight,",
        r"  keepaspectratio,",
        f"  pagecommand={{{page_command}}}",
        r"]{\BondySource}",
    ])


def _render_tex(
    source: Path,
    output_dir: Path,
    start_page: int,
    end_page: int,
    chapters: list[Chapter],
    sample: bool,
) -> str:
    try:
        relative_source = os.path.relpath(source, output_dir).replace("\\", "/")
    except ValueError:
        relative_source = source.as_posix()
    selected = [item for item in chapters if start_page <= item.source_page <= end_page]
    commands = []
    cursor = start_page
    for chapter in selected:
        if cursor < chapter.source_page:
            commands.append(_include_command(cursor, chapter.source_page - 1))
        commands.append(_include_command(chapter.source_page, chapter.source_page, chapter))
        cursor = chapter.source_page + 1
    if cursor <= end_page:
        commands.append(_include_command(cursor, end_page))
    source_literal = relative_source.replace("%", r"\%")
    return "\n".join([
        r"\documentclass[10pt,openany]{book}",
        rf"\usepackage[paperwidth={PAPER_WIDTH_MM:g}mm,paperheight={PAPER_HEIGHT_MM:g}mm,margin=0mm]{{geometry}}",
        r"\usepackage{pdfpages}",
        r"\usepackage[unicode,hidelinks,bookmarksnumbered=true]{hyperref}",
        r"\usepackage{bookmark}",
        r"\hypersetup{",
        r"  pdftitle={Graph Theory - Chapters 1-17 (Rapid Faithful Hybrid)},",
        r"  pdfauthor={J. A. Bondy and U. S. R. Murty},",
        rf"  pdfsubject={{Source physical pages {start_page}-{end_page}; vector-page preservation; rapid faithful hybrid}},",
        r"  pdfpagemode=UseOutlines,",
        r"  pdfpagelayout=SinglePage",
        r"}",
        rf"\newcommand{{\BondySource}}{{\detokenize{{{source_literal}}}}}",
        r"\pagestyle{empty}",
        r"\setlength{\parindent}{0pt}",
        r"\begin{document}",
        *commands,
        r"\end{document}",
        "",
    ])


def _compile_xelatex(tex_path: Path, passes: int, xelatex: str) -> Path:
    if passes < 2:
        raise BuildError("at least two XeLaTeX passes are required")
    executable = shutil.which(xelatex) or (
        str(Path(xelatex).resolve()) if Path(xelatex).is_file() else ""
    )
    if not executable:
        raise BuildError(f"XeLaTeX executable not found: {xelatex}")
    combined_log = []
    for pass_number in range(1, passes + 1):
        started = time.monotonic()
        completed = subprocess.run(
            [
                executable,
                "-interaction=nonstopmode",
                "-halt-on-error",
                "-file-line-error",
                tex_path.name,
            ],
            cwd=tex_path.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30 * 60,
            check=False,
        )
        combined_log.append(
            f"===== XeLaTeX pass {pass_number}/{passes} "
            f"({time.monotonic() - started:.2f}s) =====\n"
            f"{completed.stdout}\n{completed.stderr}\n"
        )
        if completed.returncode != 0:
            log_path = tex_path.with_suffix(".build.log")
            _atomic_write_text(log_path, "".join(combined_log))
            raise BuildError(
                f"XeLaTeX pass {pass_number} failed; see {log_path}"
            )
    log_path = tex_path.with_suffix(".build.log")
    _atomic_write_text(log_path, "".join(combined_log))
    pdf_path = tex_path.with_suffix(".pdf")
    if not pdf_path.is_file() or pdf_path.stat().st_size < 1024:
        raise BuildError("XeLaTeX did not produce a valid PDF artifact")
    return pdf_path


def _verify_pdf(
    pdf_path: Path,
    manifest: dict,
    expected_chapters: list[dict],
) -> dict:
    import fitz  # PyMuPDF

    document = fitz.open(pdf_path)
    try:
        expected_pages = int(manifest["target"]["expected_pages"])
        if int(document.page_count) != expected_pages:
            raise BuildError(
                f"output has {document.page_count} pages; expected {expected_pages}"
            )
        target_width = PAPER_WIDTH_MM * 72.0 / 25.4
        target_height = PAPER_HEIGHT_MM * 72.0 / 25.4
        bad_sizes = []
        blank_pages = []
        searchable_pages = 0
        raw_text_matches = 0
        normalized_text_matches = 0
        word_sequence_matches = 0
        raw_text_mismatches = []
        font_extensions = set()
        nonembedded_fonts = set()
        for output_index, page in enumerate(document, start=1):
            if (
                abs(float(page.rect.width) - target_width) > 0.75
                or abs(float(page.rect.height) - target_height) > 0.75
            ):
                bad_sizes.append(output_index)
            text = page.get_text("text")
            if text.strip():
                searchable_pages += 1
            else:
                blank_pages.append(output_index)
            source_record = manifest["text"]["records"][output_index - 1]
            if _text_sha256(text) == source_record["sha256_utf8"]:
                raw_text_matches += 1
            else:
                raw_text_mismatches.append({
                    "output_page": output_index,
                    "source_page": int(source_record["source_page"]),
                    "source_characters": int(source_record["characters"]),
                    "output_characters": len(text),
                })
            if _text_sha256(_normalized_visible_text(text)) == source_record[
                "normalized_visible_sha256"
            ]:
                normalized_text_matches += 1
            if _text_sha256("\n".join(_visible_word_sequence(text))) == source_record[
                "visible_word_sequence_sha256"
            ]:
                word_sequence_matches += 1
            for font in page.get_fonts(full=True):
                extension = str(font[1] or "").lower()
                font_extensions.add(extension)
                if extension in {"", "n/a"}:
                    nonembedded_fonts.add(str(font[3] or font[4] or font[0]))
        if bad_sizes:
            raise BuildError(f"output page size mismatch on pages {bad_sizes[:12]}")
        if blank_pages:
            raise BuildError(f"output contains blank/non-searchable pages {blank_pages[:12]}")
        if searchable_pages != expected_pages:
            raise BuildError("not every output page retains searchable text")
        if normalized_text_matches != expected_pages:
            raise BuildError(
                "normalized visible text changed on "
                f"{expected_pages - normalized_text_matches} pages"
            )
        if word_sequence_matches != expected_pages:
            raise BuildError(
                "visible word sequence changed on "
                f"{expected_pages - word_sequence_matches} pages"
            )
        if nonembedded_fonts:
            raise BuildError(
                "output contains non-embedded fonts: "
                + ", ".join(sorted(nonembedded_fonts)[:12])
            )

        outline = [
            {"level": int(level), "title": str(title), "page": int(page_number)}
            for level, title, page_number in document.get_toc(simple=True)
        ]
        expected_outline = [
            {"title": f"{item['number']} {item['title']}", "page": item["output_page"]}
            for item in expected_chapters
        ]
        actual_chapters = [
            {"title": item["title"], "page": item["page"]}
            for item in outline
            if CHAPTER_RE.fullmatch(item["title"])
        ]
        if actual_chapters != expected_outline:
            raise BuildError(
                f"chapter outline mismatch: expected {expected_outline}, got {actual_chapters}"
            )
        return {
            "page_count": int(document.page_count),
            "paper_points": [round(target_width, 4), round(target_height, 4)],
            "searchable_pages": searchable_pages,
            "raw_text_sha256_matches": raw_text_matches,
            "raw_text_sha256_mismatches": raw_text_mismatches,
            "normalized_visible_text_sha256_matches": normalized_text_matches,
            "visible_word_sequence_sha256_matches": word_sequence_matches,
            "blank_pages": blank_pages,
            "chapter_bookmarks": len(actual_chapters),
            "font_extensions": sorted(font_extensions),
            "all_fonts_embedded": not nonembedded_fonts,
        }
    finally:
        document.close()


def _build(args: argparse.Namespace) -> dict:
    source = Path(args.source).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    if not source.is_file() or source.suffix.lower() != ".pdf":
        raise BuildError(f"source PDF not found: {source}")
    start_page = int(args.start_page)
    requested_end = int(args.end_page)
    end_page = min(requested_end, int(args.sample_end_page)) if args.sample else requested_end
    if args.sample and end_page < start_page:
        raise BuildError("sample end page precedes start page")
    if not args.sample and (start_page, end_page) == (
        DEFAULT_START_PAGE, DEFAULT_END_PAGE,
    ):
        if end_page - start_page + 1 != EXPECTED_FULL_PAGES:
            raise BuildError("the full Bondy range must contain 471 physical pages")

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = "bondy-fast-hybrid-sample" if args.sample else "bondy-fast-hybrid-chapters-1-17"
    tex_path = output_dir / f"{stem}.tex"
    manifest_path = output_dir / f"{stem}.manifest.json"
    sha_path = output_dir / f"{stem}.sha256.json"
    publish_path = Path(args.publish_path).expanduser().resolve()

    manifest, chapters = _source_manifest(source, start_page, end_page)
    tex = _render_tex(
        source,
        output_dir,
        start_page,
        end_page,
        chapters,
        bool(args.sample),
    )
    _atomic_write_text(tex_path, tex)
    manifest["artifacts"] = {
        "tex": {"path": str(tex_path), "sha256": _sha256(tex_path)},
    }
    _atomic_write_json(manifest_path, manifest)

    if args.no_compile:
        return {
            "compiled": False,
            "tex": str(tex_path),
            "manifest": str(manifest_path),
        }

    pdf_path = _compile_xelatex(tex_path, int(args.passes), str(args.xelatex))
    qa = _verify_pdf(pdf_path, manifest, manifest["chapters"])
    manifest["qa"] = qa
    manifest["artifacts"]["pdf"] = {
        "path": str(pdf_path),
        "bytes": pdf_path.stat().st_size,
        "sha256": _sha256(pdf_path),
    }
    published_pdf = None
    if not args.sample and (start_page, end_page) == (
        DEFAULT_START_PAGE, DEFAULT_END_PAGE,
    ):
        publish_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_publish = publish_path.with_name(
            f".{publish_path.name}.{os.getpid()}.tmp",
        )
        shutil.copyfile(pdf_path, temporary_publish)
        temporary_publish.replace(publish_path)
        source_pdf_sha = _sha256(pdf_path)
        published_pdf_sha = _sha256(publish_path)
        if source_pdf_sha != published_pdf_sha:
            raise BuildError("published PDF copy SHA-256 does not match build PDF")
        published_pdf = publish_path
        manifest["artifacts"]["published_pdf"] = {
            "path": str(publish_path),
            "bytes": publish_path.stat().st_size,
            "sha256": published_pdf_sha,
            "identical_to_build_pdf": True,
        }
    _atomic_write_json(manifest_path, manifest)
    sha_manifest = {
        "algorithm": "sha256",
        "source_pdf": {"path": str(source), "sha256": _sha256(source)},
        "tex": {"path": str(tex_path), "sha256": _sha256(tex_path)},
        "pdf": {"path": str(pdf_path), "sha256": _sha256(pdf_path)},
        "manifest": {"path": str(manifest_path), "sha256": _sha256(manifest_path)},
    }
    if published_pdf is not None:
        sha_manifest["published_pdf"] = {
            "path": str(published_pdf),
            "sha256": _sha256(published_pdf),
            "identical_to_build_pdf": _sha256(published_pdf) == _sha256(pdf_path),
        }
    _atomic_write_json(sha_path, sha_manifest)
    return {
        "compiled": True,
        "sample": bool(args.sample),
        "tex": str(tex_path),
        "pdf": str(pdf_path),
        "published_pdf": str(published_pdf) if published_pdf is not None else "",
        "manifest": str(manifest_path),
        "sha256": str(sha_path),
        "qa": qa,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the Bondy fast hybrid edition by preserving original vector PDF pages."
        ),
    )
    parser.add_argument("--source", default=str(_default_source()))
    parser.add_argument("--output-dir", default=str(_default_output_dir()))
    parser.add_argument(
        "--publish-path",
        default=str(
            _repo_root()
            / "output"
            / "pdf"
            / "Bondy-Graph-Theory-Chapters-1-17-AI-v1.2.0.pdf"
        ),
    )
    parser.add_argument("--start-page", type=int, default=DEFAULT_START_PAGE)
    parser.add_argument("--end-page", type=int, default=DEFAULT_END_PAGE)
    parser.add_argument("--sample", action="store_true")
    parser.add_argument("--sample-end-page", type=int, default=DEFAULT_SAMPLE_END_PAGE)
    parser.add_argument("--passes", type=int, default=2)
    parser.add_argument("--xelatex", default="xelatex")
    parser.add_argument("--no-compile", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = _build(_parser().parse_args(argv))
    except (BuildError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
