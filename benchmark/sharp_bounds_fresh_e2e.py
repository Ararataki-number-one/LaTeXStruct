# -*- coding: utf-8 -*-
"""Fresh, fail-closed Sharp Bounds end-to-end acceptance benchmark.

The generation entry point accepts exactly two content inputs: the original
17-page source PDF and the original/raw OCR TEX.  It never accepts a candidate,
an analysed TEX, a reviewed TEX, a historical PDF, or a decision override.

Generation happens before the reviewed truth is loaded.  The truth is therefore
an independent scoring oracle and cannot participate in constructing the TEX.
No generated TEX or PDF is written to the repository by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass, fields
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from tools.evaluate_tex_structure_accuracy import (
    evaluate_tex_structure,
    extract_candidate_environments,
)


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
FRESH_TRUTH_PATH = HERE / "sharp_bounds_fresh_e2e_truth_v1.json"
STRUCTURE_TRUTH_PATH = HERE / "sharp_bounds_tex_structure_truth_v1.json"

SOURCE_PDF_ENV = "LATEXSTRUCT_SHARP_SOURCE_PDF"
RAW_OCR_TEX_ENV = "LATEXSTRUCT_SHARP_RAW_TEX"
SHARP_FIXTURE_DIR = HERE / "fixtures" / "sharp_bounds"
DEFAULT_SOURCE_PDF = SHARP_FIXTURE_DIR / "source.pdf"
DEFAULT_RAW_OCR_TEX = SHARP_FIXTURE_DIR / "raw_ocr.tex"

# This small deny-list is deliberately duplicated outside the truth file so a
# forbidden input is rejected *before* generation and before scoring truth is
# opened.  These are identifiers only; the benchmark never opens those paths.
PRE_GENERATION_FORBIDDEN_PATH_FRAGMENTS = (
    "output/tex/sharp-bounds-latexstruct",
    "c5900780-43e6-408c-9d10-8397540b8430",
    "352ecd75-bfac-451d-86c1-24659881c4aa",
    "sharp_current_recompile_v127",
    "sharp_bounds_audit_acceptance_v127",
    "previews/current.pdf",
)

DISPLAY_RE = re.compile(
    r"\\\[(?P<bracket>.*?)\\\]"
    r"|\\begin\{(?P<env>equation\*?|align\*?|alignat\*?|flalign\*?|"
    r"gather\*?|multline\*?)\}(?P<environment>.*?)\\end\{(?P=env)\}",
    re.IGNORECASE | re.DOTALL,
)
ACTIVE_TAG_RE = re.compile(r"\\tag\*?\s*\{\s*(\d+)\s*\}")
LITERAL_TEXT_TAG_RE = re.compile(
    r"\\text\s*\{\s*\(\s*(\d+)\s*\)\s*\}\s*\\qquad"
)
LITERAL_SUFFIX_TAG_RE = re.compile(r"\\qquad\s*\(\s*(\d+)\s*\)\s*$")
BIBITEM_RE = re.compile(
    r"\\bibitem(?:\s*\[[^\]]*\])?\s*\{([^{}]+)\}", re.IGNORECASE
)


class ForbiddenArtifactError(RuntimeError):
    """Raised when a historical answer is offered as a fresh-run input/output."""


@dataclass(frozen=True)
class FreshSharpBoundsInputs:
    """The complete and intentionally narrow generation input contract."""

    source_pdf: Path
    raw_ocr_tex: Path

    @classmethod
    def discover(cls) -> "FreshSharpBoundsInputs":
        """Use explicit host paths first, then optional repository fixtures."""

        source_pdf = os.getenv(SOURCE_PDF_ENV)
        raw_ocr_tex = os.getenv(RAW_OCR_TEX_ENV)
        return cls(
            source_pdf=(
                Path(source_pdf).expanduser() if source_pdf else DEFAULT_SOURCE_PDF
            ),
            raw_ocr_tex=(
                Path(raw_ocr_tex).expanduser() if raw_ocr_tex else DEFAULT_RAW_OCR_TEX
            ),
        )

    def required(self) -> tuple[Path, Path]:
        return self.source_pdf, self.raw_ocr_tex


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalised_path(path: Path) -> str:
    return str(path.resolve(strict=False)).replace("\\", "/").casefold()


def build_pdf_identity_visual_provenance(source_pdf: bytes) -> dict[str, Any]:
    """Record that the exact uploaded PDF bytes are the visual source.

    This is host-derived identity metadata, not a new content input: every fact
    is computed from the same immutable ``SOURCE_PDF`` bytes already admitted by
    the fresh generation contract.
    """

    from latexstruct.core.pipeline import (
        PDF_IDENTITY_VISUAL_DERIVATION_ID,
        VISUAL_SOURCE_PROVENANCE_SCHEMA,
    )

    source = bytes(source_pdf)
    digest = _sha(source)
    return {
        "schema": VISUAL_SOURCE_PROVENANCE_SCHEMA,
        "source_type": "pdf",
        "original_upload_bytes": len(source),
        "original_upload_sha256": digest,
        "visual_pdf_bytes": len(source),
        "visual_pdf_sha256": digest,
        "visual_pdf_is_derived": False,
        "derivation_id": PDF_IDENTITY_VISUAL_DERIVATION_ID,
    }


class ScriptedQualityLoopClient:
    """Stable CI substitute for model transport, never a quality oracle.

    The client derives every response from the production prompt that the host
    just froze.  It has no access to the Sharp Bounds truth file.  Its purpose
    is narrowly to exercise the real full-document and per-page visual wiring
    deterministically in CI; the independent reviewed truth still scores the
    generated candidate only after the complete pipeline has returned.
    """

    def __init__(self) -> None:
        self.cfg = SimpleNamespace(model="scripted-sharp-bounds-ci-substitute")
        self.last_usage: dict[str, Any] = {}
        self.decision_calls: list[dict[str, Any]] = []
        self.full_review_calls: list[dict[str, Any]] = []
        self.visual_calls: list[dict[str, Any]] = []

    @staticmethod
    def _full_review_targets(user: str) -> list[dict[str, Any]]:
        marker = "targets:\n"
        if marker not in user:
            raise AssertionError("full-document prompt omitted its frozen targets")
        payload = user.split(marker, 1)[1].lstrip()
        targets, _end = json.JSONDecoder().raw_decode(payload)
        if not isinstance(targets, list):
            raise AssertionError("full-document targets are not a list")
        return targets

    def chat_json(self, _system: str, user: str):
        if user.startswith("chunk_id: full-"):
            chunk_id = re.search(r"^chunk_id: (\S+)$", user, re.MULTILINE)
            start = re.search(
                r"^inspected_start_line: (\d+)$", user, re.MULTILINE
            )
            end = re.search(
                r"^inspected_end_line: (\d+)$", user, re.MULTILINE
            )
            if not (chunk_id and start and end):
                raise AssertionError("full-document prompt omitted frozen chunk bounds")
            targets = self._full_review_targets(user)
            findings = []
            for target in targets:
                kind = str(target.get("kind") or "")
                evidence_kinds = set(target.get("host_evidence") or ())
                if kind == "environment" and not evidence_kinds.intersection(
                    {"wrong-env", "overwide", "duplicate"}
                ):
                    verdict = "keep"
                    env = str(target.get("original_env") or "")
                elif kind == "anchor":
                    verdict = "formal"
                    env = str(target.get("suggested_env") or "")
                else:
                    # Unexpected deterministic conflicts remain fail-closed;
                    # the substitute must not manufacture a release pass.
                    verdict = "manual"
                    env = ""
                findings.append({
                    "item_id": str(target.get("item_id") or ""),
                    "verdict": verdict,
                    "env": env,
                    "body_span": {
                        "start_line": int(target.get("start_line") or 1),
                        "end_line": int(target.get("end_line") or 1),
                    },
                    "confidence": 0.99,
                    "evidence": "host-bounded source item inspected in this chunk",
                    "reason": "scripted CI transport response from the frozen prompt",
                })
            record = {
                "chunk_id": chunk_id.group(1),
                "inspected_start_line": int(start.group(1)),
                "inspected_end_line": int(end.group(1)),
                "target_ids": [str(item.get("item_id") or "") for item in targets],
            }
            self.full_review_calls.append(record)
            return {
                "chunk_id": record["chunk_id"],
                "inspected_start_line": record["inspected_start_line"],
                "inspected_end_line": record["inspected_end_line"],
                "findings": findings,
                "unlisted_formal_lines": [],
            }, {"calls": 1, "total_tokens": 1}

        candidate_ids = re.findall(r"^### 候选 (\S+)$", user, re.MULTILINE)
        if not candidate_ids:
            raise AssertionError("unexpected text-model request in scripted acceptance")
        self.decision_calls.append({"candidate_ids": list(candidate_ids)})
        return {
            "decisions": [
                {
                    "candidate_id": candidate_id,
                    "action": "none",
                    "env": "",
                    "body_span": {},
                    "confidence": 0.99,
                    "reason": "defer to the independent full-document inventory pass",
                }
                for candidate_id in candidate_ids
            ]
        }, {"calls": 1, "total_tokens": 1}

    def chat_vision_json_bytes(
        self,
        _system: str,
        user: str,
        image_bytes: bytes,
        _schema: dict | None = None,
    ):
        request = json.loads(user)
        source_page = int(request["source_page"])
        candidate_page = int(request["candidate_page"])
        finding_codes = [
            str(item.get("code") or "")
            for item in request.get("deterministic_findings_to_close", [])
        ]
        self.visual_calls.append({
            "source_page": source_page,
            "candidate_page": candidate_page,
            "composite_sha256": _sha(bytes(image_bytes)),
            "checked_finding_codes": finding_codes,
        })
        return {
            "source_page": source_page,
            "candidate_page": candidate_page,
            "verdict": "ok",
            "reason": "scripted CI transport closed the host-listed page checks",
            "issues": [],
            "checked_finding_codes": finding_codes,
        }, {"calls": 1, "total_tokens": 1}


def validate_generation_input_contract(inputs: FreshSharpBoundsInputs) -> None:
    """Reject every role/path other than the source PDF and original OCR TEX."""

    if {field.name for field in fields(inputs)} != {"source_pdf", "raw_ocr_tex"}:
        raise TypeError("fresh Sharp Bounds inputs must contain exactly source_pdf/raw_ocr_tex")
    for path in inputs.required():
        normalised = _normalised_path(path)
        hit = next(
            (
                fragment
                for fragment in PRE_GENERATION_FORBIDDEN_PATH_FRAGMENTS
                if fragment in normalised
            ),
            None,
        )
        if hit:
            raise ForbiddenArtifactError(
                f"historical Sharp Bounds artifact path is forbidden: {hit}"
            )


def _generate_from_raw_only(
    raw_text: str,
    source_pdf: bytes,
    *,
    compile_check: bool,
) -> Any:
    """Run production transformation without truth, cached decisions, or overrides."""

    from latexstruct.core.pipeline import run_pipeline

    return run_pipeline(
        raw_text,
        mode="rule",
        template="elegantbook",
        compile_check=compile_check,
        capture_compile_artifact=compile_check,
        require_compile_when_available=compile_check,
        decisions_override=None,
        ambiguous_override=None,
        ai_notes_override=None,
        source_pdf_bytes=source_pdf,
        source_visual_provenance=build_pdf_identity_visual_provenance(source_pdf),
    )


def _source_pdf_full_page_range(source_pdf: bytes) -> tuple[int, int]:
    """Derive the frozen page range from admitted source bytes, never truth."""

    try:
        import pymupdf
    except ImportError as exc:  # pragma: no cover - real gate skips without it
        raise RuntimeError("PyMuPDF is required for the production visual gate") from exc
    document = pymupdf.open(stream=bytes(source_pdf), filetype="pdf")
    try:
        page_count = int(document.page_count)
    finally:
        document.close()
    if page_count < 1:
        raise ValueError("Sharp Bounds source PDF contains no pages")
    return 1, page_count


def _generate_with_production_ai_quality_loop(
    raw_text: str,
    source_pdf: bytes,
) -> tuple[Any, Any, ScriptedQualityLoopClient, tuple[int, int]]:
    """Run deterministic reconstruction, then the real production AI loop.

    Both stages complete before reviewed truth is loaded.  The scripted client
    replaces only remote model transport; all host inventories, validation,
    patch reconciliation, LaTeX compilation, page rendering, mapping, visual
    calls, final verification, and rollback gates are production code.
    """

    from latexstruct.core.ai import AIConfig
    from latexstruct.core.pipeline import run_pipeline

    deterministic = _generate_from_raw_only(
        raw_text,
        source_pdf,
        compile_check=False,
    )
    client = ScriptedQualityLoopClient()
    page_range = _source_pdf_full_page_range(source_pdf)
    production = run_pipeline(
        str(deterministic.result),
        mode="ai",
        template="elegantbook",
        # This acceptance explicitly proves the production full-document
        # review stage, so it must opt in just like a real user setting.  The
        # separate opt-out regression verifies that ``False`` performs zero
        # review calls and is reported as skipped.
        ai_config=AIConfig(review_enabled=True),
        ai_client=client,
        review_client=client,
        visual_client=client,
        compile_check=True,
        capture_compile_artifact=True,
        require_compile=True,
        require_compile_when_available=True,
        decisions_override=None,
        ambiguous_override=None,
        ai_notes_override=None,
        source_pdf_bytes=source_pdf,
        source_pdf_page_range=page_range,
        source_visual_provenance=build_pdf_identity_visual_provenance(source_pdf),
        quality_loop=True,
        ocr_project=True,
    )
    return deterministic, production, client, page_range


def _load_scoring_truth() -> tuple[dict[str, Any], dict[str, Any]]:
    """Load reviewed truth only after candidate generation has completed."""

    fresh = json.loads(FRESH_TRUTH_PATH.read_text(encoding="utf-8"))
    structure = json.loads(STRUCTURE_TRUTH_PATH.read_text(encoding="utf-8"))
    return fresh, structure


def _all_forbidden_hashes(truth: dict[str, Any]) -> set[str]:
    grouped = truth["generation_contract"]["forbidden_artifact_sha256"]
    return {
        str(digest).casefold()
        for values in grouped.values()
        for digest in values
    }


def reject_forbidden_generated_digests(
    digests: dict[str, str], truth: dict[str, Any] | None = None
) -> None:
    """Fail closed when a historical corrected TEX/PDF enters as generated output."""

    if truth is None:
        truth, _ = _load_scoring_truth()
    forbidden = _all_forbidden_hashes(truth)
    reused = {
        role: digest.casefold()
        for role, digest in digests.items()
        if digest and digest.casefold() in forbidden
    }
    if reused:
        raise ForbiddenArtifactError(
            "historical corrected artifact hash entered fresh run: "
            + ", ".join(f"{role}={digest}" for role, digest in sorted(reused.items()))
        )


def _without_comments(text: str) -> str:
    return "\n".join(re.sub(r"(?<!\\)%.*$", "", line) for line in text.splitlines())


def _equation_occurrences(text: str) -> list[dict[str, Any]]:
    clean = _without_comments(text)
    occurrences: list[dict[str, Any]] = []
    for match in DISPLAY_RE.finditer(clean):
        body = match.group("bracket") or match.group("environment") or ""
        start_line = clean.count("\n", 0, match.start()) + 1
        found: set[tuple[str, str]] = set()
        for representation, pattern in (
            ("active_tag", ACTIVE_TAG_RE),
            ("literal_text_prefix", LITERAL_TEXT_TAG_RE),
            ("literal_suffix", LITERAL_SUFFIX_TAG_RE),
        ):
            for label_match in pattern.finditer(body):
                item = (label_match.group(1), representation)
                if item in found:
                    continue
                found.add(item)
                occurrences.append(
                    {
                        "label": item[0],
                        "representation": item[1],
                        "display_start_line": start_line,
                    }
                )
    return occurrences


def _has_left_equation_numbers(text: str) -> bool:
    clean = _without_comments(text)
    documentclass = re.search(r"\\documentclass\s*\[([^\]]*)\]", clean)
    if documentclass and "leqno" in {
        item.strip().casefold() for item in documentclass.group(1).split(",")
    }:
        return True
    for options in re.findall(
        r"\\PassOptionsToPackage\s*\{([^{}]*)\}\s*\{\s*amsmath\s*\}",
        clean,
        flags=re.IGNORECASE,
    ):
        if "leqno" in {item.strip().casefold() for item in options.split(",")}:
            return True
    return False


def _equation_report(candidate: str, truth: dict[str, Any]) -> dict[str, Any]:
    expected = [str(item) for item in truth["quality_gates"]["equations"]["labels"]]
    occurrences = _equation_occurrences(candidate)
    all_counts = Counter(item["label"] for item in occurrences)
    active_counts = Counter(
        item["label"] for item in occurrences if item["representation"] == "active_tag"
    )
    expected_counts = Counter(expected)
    labels_exact = all_counts == expected_counts
    active_exact = active_counts == expected_counts
    left_enabled = _has_left_equation_numbers(candidate)
    require_active = bool(
        truth["quality_gates"]["equations"].get("require_active_tags")
    )
    require_left = truth["quality_gates"]["equations"].get("tag_side") == "left"
    return {
        "expected_labels": expected,
        "observed_labels": [item["label"] for item in occurrences],
        "occurrences": occurrences,
        "label_content_accuracy": (
            sum((all_counts & expected_counts).values()) / len(expected) if expected else 1.0
        ),
        "active_semantic_accuracy": (
            sum((active_counts & expected_counts).values()) / len(expected)
            if expected
            else 1.0
        ),
        "labels_exact_once": labels_exact,
        "all_labels_are_active_tags": active_exact,
        "left_numbering_enabled": left_enabled,
        "passed": bool(
            labels_exact
            and (active_exact or not require_active)
            and (left_enabled or not require_left)
        ),
    }


def _bibliography_report(candidate: str, truth: dict[str, Any]) -> dict[str, Any]:
    clean = _without_comments(candidate)
    expected = int(truth["quality_gates"]["bibliography"]["bibitem_count"])
    environment_count = len(
        re.findall(r"\\begin\{thebibliography\}\s*\{", clean, re.IGNORECASE)
    )
    keys = BIBITEM_RE.findall(clean)
    unique = len(set(keys)) == len(keys)
    return {
        "expected_bibitems": expected,
        "observed_bibitems": len(keys),
        "unique_keys": unique,
        "thebibliography_environment_count": environment_count,
        "passed": environment_count == 1 and len(keys) == expected and unique,
    }


def _metric(tp: int, predicted: int, expected: int) -> dict[str, Any]:
    precision = tp / predicted if predicted else 0.0
    recall = tp / expected if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": tp,
        "predicted": predicted,
        "expected": expected,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _formal_metrics(
    accuracy: dict[str, Any], candidate: str, structure_truth: dict[str, Any]
) -> dict[str, Any]:
    predictions = extract_candidate_environments(candidate)
    matches = accuracy["exact_structure"]["matches"]
    expected_items = structure_truth["items"]
    result: dict[str, Any] = {}
    for name, is_proof in (("theorem_statement", False), ("proof", True)):
        expected = sum((item["kind"] == "proof") is is_proof for item in expected_items)
        predicted = sum((item.kind == "proof") is is_proof for item in predictions)
        tp = sum((item["kind"] == "proof") is is_proof for item in matches)
        result[name] = _metric(tp, predicted, expected)
    exact = accuracy["exact_structure"]
    result["combined"] = _metric(
        int(exact["true_positive"]), int(exact["predicted"]), int(exact["expected"])
    )
    return result


def _pdf_render_summary(payload: bytes) -> dict[str, Any]:
    try:
        import pymupdf
    except ImportError:
        return {"available": False, "error": "PyMuPDF is unavailable", "pages": []}
    try:
        document = pymupdf.open(stream=payload, filetype="pdf")
        pages = []
        for index, page in enumerate(document):
            pixmap = page.get_pixmap(
                matrix=pymupdf.Matrix(1, 1),
                colorspace=pymupdf.csGRAY,
                alpha=False,
            )
            samples = bytes(pixmap.samples)
            ink = sum(value < 245 for value in samples) / len(samples) if samples else 0.0
            pages.append(
                {
                    "page": index + 1,
                    "width": pixmap.width,
                    "height": pixmap.height,
                    "ink_ratio": round(ink, 6),
                    "text_characters": len(page.get_text("text").strip()),
                    "raster_sha256": _sha(samples),
                }
            )
        document.close()
        return {"available": True, "page_count": len(pages), "pages": pages}
    except Exception as exc:  # noqa: BLE001 - evidence must record renderer failure
        return {"available": True, "error": str(exc), "page_count": 0, "pages": []}


def _visual_report(
    source_pdf: bytes, candidate_pdf: bytes, truth: dict[str, Any]
) -> dict[str, Any]:
    source = _pdf_render_summary(source_pdf)
    candidate = _pdf_render_summary(candidate_pdf) if candidate_pdf else {
        "available": False,
        "error": "candidate PDF was not produced",
        "page_count": 0,
        "pages": [],
    }
    settings = truth["quality_gates"]["visual"]
    expected_pages = int(truth["quality_gates"]["compile"]["page_count"])
    ratios = [float(item["ink_ratio"]) for item in candidate.get("pages", [])]
    all_nonblank = bool(ratios) and all(
        float(settings["minimum_ink_ratio"])
        <= ratio
        <= float(settings["maximum_ink_ratio"])
        for ratio in ratios
    )
    passed = bool(
        source.get("available")
        and candidate.get("available")
        and not source.get("error")
        and not candidate.get("error")
        and source.get("page_count") == expected_pages
        and candidate.get("page_count") == expected_pages
        and all_nonblank
    )
    return {
        "scope": "independent all-page rasterisation, page count, and nonblank-page smoke gate",
        "semantic_visual_equivalence_claimed": False,
        "source": source,
        "candidate": candidate,
        "all_candidate_pages_nonblank": all_nonblank,
        "passed": passed,
    }


def _compile_report(
    pipeline_result: Any,
    candidate_sha256: str,
    source_pdf_sha256: str,
    expected_pages: int,
) -> dict[str, Any]:
    before = dict(pipeline_result.verification.get("compile_before") or {})
    after = dict(pipeline_result.verification.get("compile_after") or {})
    candidate_pdf = bytes(pipeline_result.compiled_pdf or b"")
    candidate_pdf_sha256 = _sha(candidate_pdf) if candidate_pdf else ""
    manifest = after.get("input_manifest") or {}
    files = manifest.get("files") if isinstance(manifest, dict) else []
    main_tex = next(
        (
            item
            for item in files or []
            if isinstance(item, dict) and str(item.get("path", "")).casefold() == "main.tex"
        ),
        None,
    )
    tex_hash_bound = bool(main_tex and main_tex.get("sha256") == candidate_sha256)
    pages = int(after.get("page_count") or after.get("pages") or 0)
    passed = bool(
        after.get("available")
        and after.get("ok") is True
        and pages == expected_pages
        and candidate_pdf
        and tex_hash_bound
        and candidate_pdf_sha256 != source_pdf_sha256
    )
    return {
        "raw": {
            "available": bool(before.get("available")),
            "ok": before.get("ok"),
            "page_count": int(before.get("page_count") or before.get("pages") or 0),
            "preview_status": before.get("preview_status"),
            "engine": before.get("engine"),
        },
        "current": {
            "available": bool(after.get("available")),
            "ok": after.get("ok"),
            "page_count": pages,
            "preview_status": after.get("preview_status"),
            "engine": after.get("engine"),
            "passes_completed": int(after.get("passes_completed") or 0),
            "return_code": after.get("return_code", after.get("exit_code")),
            "compile_input_sha256": after.get("compile_input_sha256"),
            "candidate_tex_sha256": candidate_sha256,
            "main_tex_sha256": main_tex.get("sha256") if main_tex else None,
            "exact_tex_hash_bound": tex_hash_bound,
            "pdf_sha256": candidate_pdf_sha256 or None,
            "pdf_byte_count": len(candidate_pdf),
            "source_pdf_reused_as_preview": candidate_pdf_sha256 == source_pdf_sha256,
        },
        "passed": passed,
    }


def _input_authenticity(
    source_pdf: bytes, raw_tex: bytes, truth: dict[str, Any]
) -> dict[str, Any]:
    expected = truth["sample"]
    observed = {
        "source_pdf": {"bytes_sha256": _sha(source_pdf), "byte_count": len(source_pdf)},
        "raw_ocr_tex": {"bytes_sha256": _sha(raw_tex), "byte_count": len(raw_tex)},
    }
    checks = {
        role: all(observed[role].get(key) == value for key, value in facts.items() if key != "page_count")
        for role, facts in expected.items()
    }
    return {"observed": observed, "checks": checks, "passed": all(checks.values())}


def _required_interfaces(blockers: list[str]) -> list[dict[str, str]]:
    result = []
    if "equations" in blockers:
        result.append(
            {
                "id": "active_equation_number_rewrite",
                "needed": (
                    "A source-evidence-gated semantic rewrite that emits equation/align "
                    "plus active \\tag{n}, and records left-numbering (leqno) before amsmath."
                ),
                "acceptance": "labels 1..6 exactly once as active tags; no literal printed labels",
            }
        )
    if "compile" in blockers:
        result.append(
            {
                "id": "hash_bound_compile_artifact",
                "needed": "compiled PDF + engine/log/page count + input manifest for exact current TEX",
                "acceptance": "17 pages and main.tex SHA-256 equals generated current TEX SHA-256",
            }
        )
    if "visual" in blockers:
        result.append(
            {
                "id": "fresh_visual_inspection",
                "needed": "candidate-PDF byte input to an all-page renderer/visual inspector",
                "acceptance": "all 17 fresh pages render and no page is blank/corrupt",
            }
        )
    return result


def run_fresh_acceptance(
    inputs: FreshSharpBoundsInputs,
    *,
    compile_check: bool = True,
) -> dict[str, Any]:
    """Generate from the two allowed inputs, then score without writing artifacts."""

    validate_generation_input_contract(inputs)
    missing = [path.name for path in inputs.required() if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing fresh Sharp Bounds input(s): " + ", ".join(missing))

    # These are the only two content reads before generation.  In particular,
    # neither truth nor any historical candidate is available to the pipeline.
    source_pdf = inputs.source_pdf.read_bytes()
    raw_tex_bytes = inputs.raw_ocr_tex.read_bytes()
    raw_text = raw_tex_bytes.decode("utf-8-sig")
    pipeline_result = _generate_from_raw_only(
        raw_text,
        source_pdf,
        compile_check=compile_check,
    )
    candidate = str(pipeline_result.result)
    candidate_bytes = candidate.encode("utf-8")
    candidate_pdf = bytes(pipeline_result.compiled_pdf or b"")

    # Only now may reviewed truth enter, and only the scoring branch sees it.
    truth, structure_truth = _load_scoring_truth()
    candidate_digests = {"CURRENT_TEX": _sha(candidate_bytes)}
    if candidate_pdf:
        candidate_digests["CURRENT_PDF"] = _sha(candidate_pdf)
    if pipeline_result.analyzed_tex:
        candidate_digests["AI_ANALYZED_TEX"] = _sha(
            pipeline_result.analyzed_tex.encode("utf-8")
        )
    if pipeline_result.reviewed_tex:
        candidate_digests["AI_REVIEWED_TEX"] = _sha(
            pipeline_result.reviewed_tex.encode("utf-8")
        )
    reject_forbidden_generated_digests(candidate_digests, truth)

    authenticity = _input_authenticity(source_pdf, raw_tex_bytes, truth)
    accuracy = evaluate_tex_structure(
        raw_text,
        candidate,
        manifest=structure_truth,
        threshold=float(truth["quality_gates"]["structure_f1_threshold"]),
        require_toc=bool(truth["quality_gates"]["toc_required"]),
        original_binary_sha256=_sha(raw_tex_bytes),
        candidate_binary_sha256=_sha(candidate_bytes),
    )
    formal = _formal_metrics(accuracy, candidate, structure_truth)
    equations = _equation_report(candidate, truth)
    bibliography = _bibliography_report(candidate, truth)
    expected_pages = int(truth["quality_gates"]["compile"]["page_count"])
    compile_report = _compile_report(
        pipeline_result, _sha(candidate_bytes), _sha(source_pdf), expected_pages
    )
    visual = _visual_report(source_pdf, candidate_pdf, truth)

    document = accuracy["document_structure"]
    body = accuracy["body_token_conservation"]
    structure_passed = bool(
        formal["combined"]["f1"]
        >= float(truth["quality_gates"]["structure_f1_threshold"])
        and not any(accuracy["blockers"].values())
    )
    toc_passed = bool(
        document["toc_present"]
        and document["outline_coverage"] == 1.0
        and document["candidate_outline_nodes"]
        == int(truth["quality_gates"]["outline_node_count"])
    )
    gates = {
        "input_authenticity": authenticity["passed"],
        "pipeline": bool(pipeline_result.ok),
        "theorem_proof": structure_passed,
        "toc_outline": toc_passed,
        "equations": equations["passed"],
        "bibliography": bibliography["passed"],
        "body_conservation": bool(body["conserved"]),
        "compile": compile_report["passed"],
        "visual": visual["passed"],
    }
    blockers = [name for name, passed in gates.items() if not passed]
    review = pipeline_result.verification.get("ai_review") or {}
    source_visual_provenance = dict(
        pipeline_result.verification.get("source_visual_provenance") or {}
    )
    return {
        "schema": "latexstruct-sharp-bounds-fresh-e2e-report-v1",
        "status": "PASS" if not blockers else "FAIL",
        "passed": not blockers,
        "generation_contract": {
            "allowed_input_roles": ["SOURCE_PDF", "RAW_OCR_TEX"],
            "content_read_ledger": [
                {
                    "role": "SOURCE_PDF",
                    "bytes_sha256": _sha(source_pdf),
                    "byte_count": len(source_pdf),
                },
                {
                    "role": "RAW_OCR_TEX",
                    "bytes_sha256": _sha(raw_tex_bytes),
                    "byte_count": len(raw_tex_bytes),
                },
            ],
            "historical_candidate_inputs": [],
            "truth_loaded_after_generation": True,
            "decisions_override_used": False,
            "generated_artifact_sha256": candidate_digests,
            "forbidden_hash_match": False,
        },
        "input_authenticity": authenticity,
        "pipeline": {
            "mode": "rule",
            "template": "elegantbook",
            "ok": bool(pipeline_result.ok),
            "safe_to_export": bool(pipeline_result.verification.get("safe_to_export")),
            "decision_count": len(pipeline_result.decisions),
            "review": {
                "checked": bool(review.get("checked")),
                "ok": review.get("ok"),
                "note": "reported, but not used to disguise the independent truth score",
            },
            "source_visual_provenance": source_visual_provenance,
        },
        "theorem_proof_accuracy": formal,
        "structure_details": {
            "missing": accuracy["exact_structure"]["missing"],
            "duplicates": accuracy["exact_structure"]["duplicates"],
            "boundary_errors": accuracy["exact_structure"]["boundary_errors"],
            "unmatched_environments": accuracy["exact_structure"][
                "unmatched_environments"
            ],
            "residual_formal_headings": accuracy["residual_formal_headings"],
        },
        "toc_outline": document,
        "equations": equations,
        "bibliography": bibliography,
        "body_token_conservation": body,
        "compile": compile_report,
        "visual": visual,
        "gates": gates,
        "blockers": blockers,
        "required_interfaces_to_pass": _required_interfaces(blockers),
    }


def _final_hash_binding(pipeline_result: Any) -> dict[str, Any]:
    candidate = str(pipeline_result.result).encode("utf-8")
    candidate_pdf = bytes(pipeline_result.compiled_pdf or b"")
    tex_sha256 = _sha(candidate)
    pdf_sha256 = _sha(candidate_pdf) if candidate_pdf else ""
    compile_after = dict(pipeline_result.verification.get("compile_after") or {})
    manifest = compile_after.get("input_manifest") or {}
    files = manifest.get("files") if isinstance(manifest, dict) else []
    main_tex = next(
        (
            item
            for item in files or []
            if isinstance(item, dict)
            and str(item.get("path") or "").casefold() == "main.tex"
        ),
        None,
    )
    loop = dict(pipeline_result.verification.get("visual_quality_loop") or {})
    rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
    final_round = rounds[-1] if rounds and isinstance(rounds[-1], dict) else {}
    observed = {
        "final_tex_sha256": tex_sha256,
        "compile_input_sha256": compile_after.get("compile_input_sha256"),
        "compile_manifest_sha256": (
            manifest.get("manifest_sha256") if isinstance(manifest, dict) else None
        ),
        "compile_manifest_main_tex_sha256": (
            main_tex.get("sha256") if main_tex else None
        ),
        "visual_loop_final_tex_sha256": final_round.get("tex_sha256"),
        "final_pdf_sha256": pdf_sha256 or None,
        "compile_pdf_sha256": compile_after.get("pdf_sha256"),
    }
    checks = {
        "compile_input_set_manifest_is_bound": bool(
            observed["compile_input_sha256"]
            and observed["compile_input_sha256"]
            == observed["compile_manifest_sha256"]
        ),
        "manifest_main_matches_final_tex": (
            observed["compile_manifest_main_tex_sha256"] == tex_sha256
        ),
        "visual_round_matches_final_tex": (
            observed["visual_loop_final_tex_sha256"] == tex_sha256
        ),
        "compiled_pdf_matches_returned_artifact": bool(
            candidate_pdf and observed["compile_pdf_sha256"] == pdf_sha256
        ),
    }
    return {"observed": observed, "checks": checks, "passed": all(checks.values())}


def run_production_ai_quality_loop_acceptance(
    inputs: FreshSharpBoundsInputs,
) -> dict[str, Any]:
    """Accept the production AI loop without pretending CI is a real model.

    The reviewed truth remains inaccessible until both the deterministic stage
    and ``run_pipeline(mode='ai', quality_loop=True, ocr_project=True)`` have
    returned.  Consequently this proves production wiring and fail-closed gate
    closure, while semantic quality remains independently measured by truth.
    """

    validate_generation_input_contract(inputs)
    missing = [path.name for path in inputs.required() if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "missing fresh Sharp Bounds input(s): " + ", ".join(missing)
        )

    source_pdf = inputs.source_pdf.read_bytes()
    raw_tex_bytes = inputs.raw_ocr_tex.read_bytes()
    raw_text = raw_tex_bytes.decode("utf-8-sig")
    deterministic, production, client, page_range = (
        _generate_with_production_ai_quality_loop(raw_text, source_pdf)
    )
    candidate = str(production.result)
    candidate_bytes = candidate.encode("utf-8")
    candidate_pdf = bytes(production.compiled_pdf or b"")

    # Reviewed truth enters only after every production AI/compile/visual gate
    # has run.  The scripted transport object never receives this data.
    truth, structure_truth = _load_scoring_truth()
    generated_digests = {
        "DETERMINISTIC_CURRENT_TEX": _sha(
            str(deterministic.result).encode("utf-8")
        ),
        "AI_CURRENT_TEX": _sha(candidate_bytes),
    }
    if candidate_pdf:
        generated_digests["AI_CURRENT_PDF"] = _sha(candidate_pdf)
    if production.analyzed_tex:
        generated_digests["AI_ANALYZED_TEX"] = _sha(
            production.analyzed_tex.encode("utf-8")
        )
    if production.reviewed_tex:
        generated_digests["AI_REVIEWED_TEX"] = _sha(
            production.reviewed_tex.encode("utf-8")
        )
    reject_forbidden_generated_digests(generated_digests, truth)

    authenticity = _input_authenticity(source_pdf, raw_tex_bytes, truth)
    accuracy = evaluate_tex_structure(
        raw_text,
        candidate,
        manifest=structure_truth,
        threshold=float(truth["quality_gates"]["structure_f1_threshold"]),
        require_toc=bool(truth["quality_gates"]["toc_required"]),
        original_binary_sha256=_sha(raw_tex_bytes),
        candidate_binary_sha256=_sha(candidate_bytes),
    )
    formal = _formal_metrics(accuracy, candidate, structure_truth)
    equations = _equation_report(candidate, truth)
    bibliography = _bibliography_report(candidate, truth)
    document = accuracy["document_structure"]
    body = accuracy["body_token_conservation"]
    expected_pages = int(truth["quality_gates"]["compile"]["page_count"])
    compile_report = _compile_report(
        production,
        _sha(candidate_bytes),
        _sha(source_pdf),
        expected_pages,
    )
    raster_smoke = _visual_report(source_pdf, candidate_pdf, truth)
    hash_binding = _final_hash_binding(production)

    verification = production.verification
    full_review = dict(verification.get("full_document_review") or {})
    full_chunks = (
        full_review.get("chunks") if isinstance(full_review.get("chunks"), list) else []
    )
    client_chunk_ids = [item["chunk_id"] for item in client.full_review_calls]
    host_chunk_ids = [
        str(item.get("chunk_id") or "")
        for item in full_chunks
        if isinstance(item, dict)
    ]
    full_review_transport = {
        "production_function": "latexstruct.core.full_review.run_full_document_review",
        "chunk_count": len(full_chunks),
        "scripted_transport_call_count": len(client.full_review_calls),
        "chunk_ids": host_chunk_ids,
        "chunk_calls_match": bool(
            full_chunks and client_chunk_ids == host_chunk_ids
        ),
        "target_count": sum(
            int(item.get("target_count") or 0)
            for item in full_chunks
            if isinstance(item, dict)
        ),
    }
    full_review_passed = bool(
        full_review.get("checked") is True
        and full_review.get("ok") is True
        and not full_review.get("invalid")
        and not full_review.get("escalations")
        and full_review_transport["chunk_calls_match"]
    )

    loop = dict(verification.get("visual_quality_loop") or {})
    rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
    audit_pages: list[dict[str, Any]] = []
    for record in rounds:
        if not isinstance(record, dict):
            continue
        audit = record.get("ai_audit")
        if isinstance(audit, dict) and isinstance(audit.get("pages"), list):
            audit_pages.extend(
                item for item in audit["pages"] if isinstance(item, dict)
            )
    expected_mappings = [
        (source_page, index)
        for index, source_page in enumerate(
            range(page_range[0], page_range[1] + 1),
            1,
        )
    ]
    observed_mappings = [
        (int(item["source_page"]), int(item["candidate_page"]))
        for item in client.visual_calls
    ]
    mapping_counts = Counter(observed_mappings)
    page_call_report = {
        "production_function": "latexstruct.core.visual_review.audit_compiled_pages",
        "expected_page_count": len(expected_mappings),
        "call_count": len(client.visual_calls),
        "mappings": [
            {
                "source_page": source_page,
                "candidate_page": candidate_page,
                "call_count": mapping_counts[(source_page, candidate_page)],
            }
            for source_page, candidate_page in expected_mappings
        ],
        "all_composites_hash_recorded": all(
            len(str(item.get("composite_sha256") or "")) == 64
            for item in client.visual_calls
        ),
    }
    page_call_report["each_expected_page_exactly_once"] = bool(
        len(client.visual_calls) == len(expected_mappings)
        and mapping_counts == Counter(expected_mappings)
        and len(audit_pages) == len(expected_mappings)
        and all(item.get("valid") is True for item in audit_pages)
        and page_call_report["all_composites_hash_recorded"]
    )
    visual_loop_passed = bool(
        loop.get("required") is True
        and loop.get("checked") is True
        and loop.get("ok") is True
        and not loop.get("invalid")
        and not loop.get("unresolved")
        and len(rounds) == 1
        and page_call_report["each_expected_page_exactly_once"]
    )

    ocr_contract = dict(verification.get("ocr_project_contract") or {})
    provenance = dict(verification.get("source_visual_provenance") or {})
    structure_passed = bool(
        formal["combined"]["f1"]
        >= float(truth["quality_gates"]["structure_f1_threshold"])
        and not any(accuracy["blockers"].values())
    )
    toc_passed = bool(
        document["toc_present"]
        and document["outline_coverage"] == 1.0
        and document["candidate_outline_nodes"]
        == int(truth["quality_gates"]["outline_node_count"])
    )
    gates = {
        "input_authenticity": authenticity["passed"],
        "deterministic_stage": bool(deterministic.ok),
        "production_ai_pipeline": bool(production.ok),
        "explicit_ocr_contract": bool(
            ocr_contract.get("required") is True
            and ocr_contract.get("checked") is True
            and ocr_contract.get("explicit_ocr_project") is True
            and ocr_contract.get("ok") is True
        ),
        "source_visual_provenance": bool(
            provenance.get("checked") is True and provenance.get("ok") is True
        ),
        "full_document_review": full_review_passed,
        "theorem_proof": structure_passed,
        "toc_outline": toc_passed,
        "equations": equations["passed"],
        "bibliography": bibliography["passed"],
        "body_conservation": bool(body["conserved"]),
        "compile": compile_report["passed"],
        "final_tex_pdf_hash_binding": hash_binding["passed"],
        "production_visual_quality_loop": visual_loop_passed,
        "all_17_pages_called_once": bool(
            expected_pages == 17
            and page_call_report["expected_page_count"] == 17
            and page_call_report["each_expected_page_exactly_once"]
        ),
        "independent_raster_smoke": raster_smoke["passed"],
    }
    blockers = [name for name, passed in gates.items() if not passed]
    return {
        "schema": "latexstruct-sharp-bounds-production-ai-quality-loop-v1",
        "status": "PASS" if not blockers else "FAIL",
        "passed": not blockers,
        "claim_scope": {
            "proved": (
                "production full-document review, real LaTeX compile, deterministic "
                "render comparison, all-page visual-call mapping, final hash binding, "
                "and fail-closed export gates are wired and close on this fixture"
            ),
            "not_proved": (
                "semantic quality of any live remote model or equivalence of a scripted "
                "response to ChatGPT, Codex, DeepSeek, or Qwen"
            ),
            "scripted_model_substitute": True,
            "scripted_client_model_id": client.cfg.model,
        },
        "generation_contract": {
            "allowed_external_input_roles": ["SOURCE_PDF", "RAW_OCR_TEX"],
            "content_read_ledger": [
                {
                    "role": "SOURCE_PDF",
                    "bytes_sha256": _sha(source_pdf),
                    "byte_count": len(source_pdf),
                },
                {
                    "role": "RAW_OCR_TEX",
                    "bytes_sha256": _sha(raw_tex_bytes),
                    "byte_count": len(raw_tex_bytes),
                },
            ],
            "deterministic_intermediate_is_generated": True,
            "historical_candidate_inputs": [],
            "truth_loaded_after_deterministic_and_ai_generation": True,
            "decisions_override_used": False,
            "generated_artifact_sha256": generated_digests,
            "forbidden_hash_match": False,
        },
        "input_authenticity": authenticity,
        "pipeline": {
            "mode": "ai",
            "quality_loop": True,
            "ocr_project": True,
            "ok": bool(production.ok),
            "safe_to_export": bool(verification.get("safe_to_export")),
            "ocr_project_contract": ocr_contract,
            "source_visual_provenance": provenance,
        },
        "full_document_review": {
            "checked": full_review.get("checked"),
            "ok": full_review.get("ok"),
            "invalid": list(full_review.get("invalid") or []),
            "escalations": list(full_review.get("escalations") or []),
            "transport_evidence": full_review_transport,
        },
        "theorem_proof_accuracy": formal,
        "toc_outline": document,
        "equations": equations,
        "bibliography": bibliography,
        "body_token_conservation": body,
        "compile": compile_report,
        "final_hash_binding": hash_binding,
        "visual_quality_loop": loop,
        "visual_page_calls": page_call_report,
        "independent_raster_smoke": raster_smoke,
        "gates": gates,
        "blockers": blockers,
    }


def main() -> int:
    inputs = FreshSharpBoundsInputs.discover()
    report = run_fresh_acceptance(inputs)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
