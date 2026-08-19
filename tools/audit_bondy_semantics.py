# -*- coding: utf-8 -*-
"""Offline, fail-closed text and mathematical-token audit for Bondy pages 3--473.

This is deliberately a *source-versus-output extraction audit*, not a semantic
oracle.  It never calls a model or the network, never consumes a hidden/blind
gold file, and never claims that matching extraction proves mathematical
correctness.  A successful run establishes only the two declared mechanical
thresholds (normalized text and mathematical-token alignment, both at least
98%) plus conservative critical-structure, confusable, and reference checks.

The publication gate always remains ``not_established`` because definitions,
theorems, algorithms, and exercises still require independent human or Codex
review against the visible source PDF.

Exit codes::

    0  offline alignment audit passed; publication semantics remain unverified
    1  audit completed and at least one fail-closed quality gate failed
    2  audit could not be completed; JSON/Markdown error reports are still written
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

try:  # Works both as ``python -m tools...`` and ``python tools/...py``.
    from tools.evaluate_pdf_fidelity import (
        EvaluationError,
        _atomic_write,
        _sha256,
        load_manifest,
        normalize_text,
        normalized_text_similarity,
        open_pdf,
    )
except ModuleNotFoundError:  # pragma: no cover - direct-script import path
    from evaluate_pdf_fidelity import (  # type: ignore[no-redef]
        EvaluationError,
        _atomic_write,
        _sha256,
        load_manifest,
        normalize_text,
        normalized_text_similarity,
        open_pdf,
    )


SCHEMA_VERSION = 1
TOOL_VERSION = "1.0"
GATE_NAME = "bondy_first17_offline_semantic_alignment"
EXPECTED_SOURCE_RANGE = (3, 473)
EXPECTED_CHAPTER_COUNT = 17
TEXT_THRESHOLD = 0.98
MATH_THRESHOLD = 0.98
CRITICAL_REVIEW_THRESHOLD = 0.995

TARGET_CRITICAL_KINDS = {"definition", "theorem", "algorithm", "exercise"}
STRUCTURE_HEADING_RE = re.compile(
    r"(?im)^[ \t]*(?P<kind>Definition|Theorem|Algorithm|Exercises?|Lemma|"
    r"Proposition|Corollary|Conjecture|Proof|Remark|Example|Notes?)"
    r"(?:[ \t]+(?P<number>[0-9]+(?:\.[0-9]+)*(?:[A-Za-z])?))?\b"
)

TEXT_TOKEN_RE = re.compile(r"[^\W_]+|[^\w\s]", re.UNICODE)
MATH_LEXEME_RE = re.compile(
    r"(?P<multi><=>|<->|<=|>=|!=|:=|->|<-|=>)"
    r"|(?P<number>[0-9]+(?:\.[0-9]+)*(?:[A-Za-z])?)"
    r"|(?P<word>[^\W\d_]+)"
    r"|(?P<symbol>[^\w\s])",
    re.UNICODE,
)

GREEK_WORDS = {
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    "zeta",
    "eta",
    "theta",
    "iota",
    "kappa",
    "lambda",
    "mu",
    "nu",
    "xi",
    "omicron",
    "pi",
    "rho",
    "sigma",
    "tau",
    "upsilon",
    "phi",
    "chi",
    "psi",
    "omega",
}
NAMED_OPERATORS = {
    "arg",
    "cos",
    "deg",
    "det",
    "dim",
    "exp",
    "gcd",
    "inf",
    "lim",
    "log",
    "max",
    "min",
    "mod",
    "sin",
    "sup",
    "tan",
}
OPERATOR_CHARS = set(
    "+=*/<>|^~"
    "−×÷±∓·⋅∘∗"
    "≤≥≠≈≃≡∼∝"
    "∈∉∋∅∪∩⊂⊆⊃⊇∖"
    "←→↔⇐⇒⇔↦"
    "∑∏√∞∂∇∫∬"
    "∧∨¬∀∃⊢⊨⊥∣∥"
    "′″†"
)
OPERATOR_ALIASES = {
    "<=": "≤",
    ">=": "≥",
    "!=": "≠",
    "->": "→",
    "<-": "←",
    "<->": "↔",
    "=>": "⇒",
    "−": "-",
    "⋅": "·",
}
GREEK_ALIASES = {
    "ϵ": "ε",
    "ϑ": "θ",
    "ϕ": "φ",
    "ϖ": "π",
    "ϱ": "ρ",
    "ς": "σ",
}

MEANING_PHRASES = (
    "if and only if",
    "at most",
    "at least",
    "there exists",
    "does not",
    "do not",
    "is not",
    "no",
    "not",
    "never",
    "without",
    "unless",
    "exactly",
    "unique",
    "distinct",
    "every",
    "all",
    "some",
)

REFERENCE_RE = re.compile(
    r"(?i)\b(?P<kind>Fig(?:ure)?\.?|Theorem|Lemma|Proposition|Corollary|"
    r"Definition|Algorithm|Section|Chapter|Exercises?|Eq(?:uation)?\.?)"
    r"\s*\(?\s*(?P<number>[0-9]+(?:\.[0-9]+)*(?:[A-Za-z])?)\s*\)?"
)
REFERENCE_KIND_ALIASES = {
    "fig": "figure",
    "fig.": "figure",
    "figure": "figure",
    "eq": "equation",
    "eq.": "equation",
    "exercise": "exercise",
    "exercises": "exercise",
}
UNRESOLVED_REFERENCE_PATTERNS = (
    ("double_question_mark", re.compile(r"(?<!\?)\?\?(?!\?)")),
    (
        "undefined_reference",
        re.compile(r"(?i)\b(?:undefined\s+(?:reference|citation)|reference\s+source\s+not\s+found)\b"),
    ),
    ("missing_reference_marker", re.compile(r"(?i)\bmissing\s+(?:reference|citation)\b")),
)

CYRILLIC_LOOKALIKES = {
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Т": "T",
    "Х": "X",
    "а": "a",
    "с": "c",
    "е": "e",
    "о": "o",
    "р": "p",
    "х": "x",
    "у": "y",
}
# U+25A1/U+25A0 are legitimate graph vertices and proof-end symbols in this
# mathematics source.  Only the actual Unicode replacement character is a
# fail-closed extraction finding.
REPLACEMENT_GLYPHS = {"\ufffd"}


@dataclass(frozen=True)
class MathToken:
    """A normalized, ordered token carrying its conservative category."""

    category: str
    value: str
    raw: str

    @property
    def key(self) -> str:
        return f"{self.category}:{self.value}"


def _round(value: float, digits: int = 6) -> float:
    return round(float(value), digits)


def _ratio(numerator: int, denominator: int, *, empty: float = 1.0) -> float:
    return numerator / denominator if denominator else empty


def _counter_list(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"token": token, "count": int(count)}
        for token, count in sorted(counter.items())
        if count > 0
    ]


def _comparison_tokens(text: str) -> list[str]:
    """Mirror evaluator normalization while retaining word/symbol token order."""

    value = unicodedata.normalize("NFKC", str(text or "")).casefold().replace("\u00ad", "")
    tokens: list[str] = []
    for match in TEXT_TOKEN_RE.finditer(value):
        token = match.group(0)
        if token and unicodedata.category(token[0])[:1] in {"L", "N", "S"}:
            tokens.append(token)
    return tokens


def sequence_alignment(source: Sequence[str], generated: Sequence[str]) -> dict[str, Any]:
    """Return multiset coverage and order-preserving alignment, both directional."""

    left, right = list(source), list(generated)
    source_counter, generated_counter = Counter(left), Counter(right)
    common_multiset = sum((source_counter & generated_counter).values())
    matcher = SequenceMatcher(None, left, right, autojunk=len(left) >= 200 or len(right) >= 200)
    ordered_matches = sum(block.size for block in matcher.get_matching_blocks())

    if not left and not right:
        precision = recall = ordered_precision = ordered_recall = 1.0
    else:
        precision = _ratio(common_multiset, len(right), empty=0.0)
        recall = _ratio(common_multiset, len(left), empty=0.0)
        ordered_precision = _ratio(ordered_matches, len(right), empty=0.0)
        ordered_recall = _ratio(ordered_matches, len(left), empty=0.0)

    def f1(p: float, r: float) -> float:
        return 2.0 * p * r / (p + r) if p + r else 0.0

    multiset_f1 = f1(precision, recall)
    ordered_f1 = f1(ordered_precision, ordered_recall)
    order_preservation = _ratio(ordered_matches, common_multiset, empty=1.0)
    return {
        "source_tokens": len(left),
        "generated_tokens": len(right),
        "multiset_matches": common_multiset,
        "ordered_matches": ordered_matches,
        "coverage_recall": _round(recall),
        "coverage_precision": _round(precision),
        "multiset_f1": _round(multiset_f1),
        "ordered_recall": _round(ordered_recall),
        "ordered_precision": _round(ordered_precision),
        "ordered_f1": _round(ordered_f1),
        "order_preservation": _round(order_preservation),
        "accuracy": _round(min(multiset_f1, ordered_f1)),
    }


def text_alignment(source: str, generated: str) -> dict[str, Any]:
    """Normalized text coverage/order, plus the existing evaluator's metric."""

    result = sequence_alignment(_comparison_tokens(source), _comparison_tokens(generated))
    source_normalized = normalize_text(source)
    generated_normalized = normalize_text(generated)
    evaluator_metric = normalized_text_similarity(source, generated)
    result.update(
        {
            "source_normalized_characters": len(source_normalized),
            "generated_normalized_characters": len(generated_normalized),
            "evaluator_character_sequence": evaluator_metric["character_sequence"],
            "evaluator_token_multiset_f1": evaluator_metric["token_multiset_f1"],
            "evaluator_combined": evaluator_metric["combined"],
        }
    )
    return result


def _is_greek(value: str) -> bool:
    letters = [char for char in value if char.isalpha()]
    return bool(letters) and all("GREEK" in unicodedata.name(char, "") for char in letters)


def extract_math_tokens(text: str) -> list[MathToken]:
    """Extract ordered math/Greek/operator/numbering tokens without a model.

    Single Latin letters are treated as identifiers because Bondy's graph
    notation relies heavily on ``G``, ``V``, ``E``, ``u``, and ``v``.  Ordinary
    single-letter prose may therefore be included; this is conservative and is
    explicitly not a proof of formula semantics.
    """

    value = unicodedata.normalize("NFKC", str(text or "")).replace("\u00ad", "")
    tokens: list[MathToken] = []
    for match in MATH_LEXEME_RE.finditer(value):
        raw = match.group(0)
        if match.lastgroup == "multi":
            normalized = OPERATOR_ALIASES.get(raw, raw)
            tokens.append(MathToken("operator", normalized, raw))
            continue
        if match.lastgroup == "number":
            tokens.append(MathToken("numbering", raw.casefold(), raw))
            continue
        if match.lastgroup == "word":
            folded = raw.casefold()
            if _is_greek(raw):
                for char in raw:
                    if char.isalpha():
                        canonical = GREEK_ALIASES.get(char.casefold(), char.casefold())
                        tokens.append(MathToken("greek", canonical, char))
            elif folded in GREEK_WORDS:
                tokens.append(MathToken("greek", folded, raw))
            elif folded in NAMED_OPERATORS:
                tokens.append(MathToken("operator", folded, raw))
            elif len(raw) == 1 and raw.isalpha() and raw.isascii():
                tokens.append(MathToken("identifier", folded, raw))
            continue
        if match.lastgroup == "symbol" and raw in OPERATOR_CHARS:
            normalized = OPERATOR_ALIASES.get(raw, raw)
            tokens.append(MathToken("operator", normalized, raw))
    return tokens


def math_alignment(source: str, generated: str) -> dict[str, Any]:
    source_tokens = extract_math_tokens(source)
    generated_tokens = extract_math_tokens(generated)
    result = sequence_alignment(
        [token.key for token in source_tokens],
        [token.key for token in generated_tokens],
    )
    categories: dict[str, dict[str, Any]] = {}
    for category in ("identifier", "greek", "operator", "numbering"):
        categories[category] = sequence_alignment(
            [token.value for token in source_tokens if token.category == category],
            [token.value for token in generated_tokens if token.category == category],
        )
    result["categories"] = categories
    return result


def _meaning_markers(text: str) -> Counter[str]:
    normalized = " ".join(_comparison_tokens(text))
    markers: Counter[str] = Counter()
    # Longest-first and non-overlapping replacement prevent "not" from double
    # counting inside "does not".
    remainder = f" {normalized} "
    for phrase in sorted(MEANING_PHRASES, key=len, reverse=True):
        pattern = re.compile(rf"(?<!\w){re.escape(phrase)}(?!\w)")
        matches = list(pattern.finditer(remainder))
        if matches:
            markers[phrase] += len(matches)
            remainder = pattern.sub(" ", remainder)
    return markers


def reference_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for match in REFERENCE_RE.finditer(str(text or "")):
        kind = match.group("kind").casefold().rstrip(".")
        kind = REFERENCE_KIND_ALIASES.get(kind, kind)
        tokens.append(f"{kind}:{match.group('number').casefold()}")
    return tokens


def unresolved_reference_markers(text: str, page: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    value = str(text or "")
    for kind, pattern in UNRESOLVED_REFERENCE_PATTERNS:
        for match in pattern.finditer(value):
            findings.append(
                {
                    "page": page,
                    "kind": kind,
                    "match": match.group(0),
                    "context": _context(value, match.start()),
                }
            )
    return findings


def _context(text: str, offset: int, radius: int = 24) -> str:
    start, end = max(0, offset - radius), min(len(text), offset + radius + 1)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def _confusable_kind(char: str) -> Optional[str]:
    codepoint = ord(char)
    name = unicodedata.name(char, "")
    if char in REPLACEMENT_GLYPHS:
        return "replacement_glyph"
    if "CYRILLIC" in name:
        return "cyrillic"
    if 0xFF01 <= codepoint <= 0xFF5E or char == "\u3000":
        return "fullwidth"
    return None


def scan_unicode_confusables(text: str, page: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    value = str(text or "")
    for offset, char in enumerate(value):
        kind = _confusable_kind(char)
        if kind is None:
            continue
        normalized = unicodedata.normalize("NFKC", char)
        findings.append(
            {
                "page": page,
                "offset": offset,
                "kind": kind,
                "character": char,
                "codepoint": f"U+{ord(char):04X}",
                "unicode_name": unicodedata.name(char, "UNKNOWN"),
                "looks_like": CYRILLIC_LOOKALIKES.get(char),
                "nfkc": normalized if normalized != char else None,
                "context": _context(value, offset),
            }
        )
    return findings


def _unexpected_confusables(
    source: Sequence[dict[str, Any]], generated: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    allowance = Counter((item["kind"], item["character"]) for item in source)
    unexpected: list[dict[str, Any]] = []
    for item in generated:
        # U+FFFD means extraction could not identify the generated glyph.  A
        # matching source extraction cannot make that generated uncertainty safe.
        if item["kind"] == "replacement_glyph":
            unexpected.append(item)
            continue
        key = (item["kind"], item["character"])
        if allowance[key] > 0:
            allowance[key] -= 1
        else:
            unexpected.append(item)
    return unexpected


def _normalized_sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest().upper()


def critical_segments(text: str) -> list[dict[str, Any]]:
    """Locate target structure statements and stop each at the next heading."""

    value = str(text or "")
    headings = list(STRUCTURE_HEADING_RE.finditer(value))
    occurrences: Counter[str] = Counter()
    segments: list[dict[str, Any]] = []
    for index, match in enumerate(headings):
        raw_kind = match.group("kind").casefold()
        kind = "exercise" if raw_kind.startswith("exercise") else raw_kind
        if kind not in TARGET_CRITICAL_KINDS:
            continue
        number = (match.group("number") or "unnumbered").casefold()
        base_key = f"{kind}:{number}"
        occurrences[base_key] += 1
        key = f"{base_key}#{occurrences[base_key]}"
        end = headings[index + 1].start() if index + 1 < len(headings) else len(value)
        end = min(end, match.start() + 4000)
        segment_text = value[match.start():end].strip()
        segments.append(
            {
                "key": key,
                "kind": kind,
                "number": number,
                "heading": re.sub(r"\s+", " ", match.group(0)).strip()[:160],
                "text": segment_text,
            }
        )
    return segments


def _critical_segment_diagnostics(
    source_text: str,
    generated_text: str,
    *,
    source_page: int,
    generated_page: int,
) -> list[dict[str, Any]]:
    source_segments = critical_segments(source_text)
    generated_segments = critical_segments(generated_text)
    source_keys = {item["key"] for item in source_segments}
    generated_by_key = {item["key"]: item for item in generated_segments}
    diagnostics: list[dict[str, Any]] = []
    for source in source_segments:
        generated = generated_by_key.get(source["key"])
        reasons: list[str] = []
        if generated is None:
            reasons.append("critical_heading_or_statement_missing")
            text_metric = None
            math_metric = None
            missing_meaning: Counter[str] = _meaning_markers(source["text"])
            extra_meaning: Counter[str] = Counter()
            missing_references = Counter(reference_tokens(source["text"]))
            extra_references: Counter[str] = Counter()
        else:
            text_metric = text_alignment(source["text"], generated["text"])
            math_metric = math_alignment(source["text"], generated["text"])
            source_content_tokens = _comparison_tokens(source["text"])
            generated_content_tokens = _comparison_tokens(generated["text"])
            source_math_keys = [token.key for token in extract_math_tokens(source["text"])]
            generated_math_keys = [
                token.key for token in extract_math_tokens(generated["text"])
            ]
            source_meaning = _meaning_markers(source["text"])
            generated_meaning = _meaning_markers(generated["text"])
            missing_meaning = source_meaning - generated_meaning
            extra_meaning = generated_meaning - source_meaning
            source_references = Counter(reference_tokens(source["text"]))
            generated_references = Counter(reference_tokens(generated["text"]))
            missing_references = source_references - generated_references
            extra_references = generated_references - source_references
            if float(text_metric["accuracy"]) < TEXT_THRESHOLD:
                reasons.append("critical_text_alignment_below_98_percent")
            if float(math_metric["accuracy"]) < MATH_THRESHOLD:
                reasons.append("critical_math_token_alignment_below_98_percent")
            if source_content_tokens != generated_content_tokens:
                reasons.append("critical_normalized_content_token_sequence_changed")
            if source_math_keys != generated_math_keys:
                reasons.append("critical_math_token_sequence_changed")
            source_relations = Counter(
                token.value
                for token in extract_math_tokens(source["text"])
                if token.category == "operator"
            )
            generated_relations = Counter(
                token.value
                for token in extract_math_tokens(generated["text"])
                if token.category == "operator"
            )
            if source_relations != generated_relations:
                reasons.append("critical_operator_inventory_changed")
        if missing_meaning or extra_meaning:
            reasons.append("critical_quantifier_or_negation_inventory_changed")
        if missing_references or extra_references:
            reasons.append("critical_reference_or_number_inventory_changed")
        diagnostics.append(
            {
                "source_page": source_page,
                "generated_page": generated_page,
                "key": source["key"],
                "kind": source["kind"],
                "number": source["number"],
                "heading": source["heading"],
                "source_normalized_sha256": _normalized_sha256(source["text"]),
                "generated_normalized_sha256": (
                    _normalized_sha256(generated["text"]) if generated is not None else None
                ),
                "text_alignment": text_metric,
                "math_token_alignment": math_metric,
                "missing_meaning_markers": _counter_list(missing_meaning),
                "extra_meaning_markers": _counter_list(extra_meaning),
                "missing_reference_tokens": _counter_list(missing_references),
                "extra_reference_tokens": _counter_list(extra_references),
                "suspected_meaning_change": bool(reasons),
                "reasons": sorted(set(reasons)),
            }
        )
    for generated in generated_segments:
        if generated["key"] in source_keys:
            continue
        diagnostics.append(
            {
                "source_page": source_page,
                "generated_page": generated_page,
                "key": generated["key"],
                "kind": generated["kind"],
                "number": generated["number"],
                "heading": generated["heading"],
                "source_normalized_sha256": None,
                "generated_normalized_sha256": _normalized_sha256(generated["text"]),
                "text_alignment": None,
                "math_token_alignment": None,
                "missing_meaning_markers": [],
                "extra_meaning_markers": _counter_list(_meaning_markers(generated["text"])),
                "missing_reference_tokens": [],
                "extra_reference_tokens": _counter_list(
                    Counter(reference_tokens(generated["text"]))
                ),
                "suspected_meaning_change": True,
                "reasons": ["unexpected_generated_critical_heading_or_statement"],
            }
        )
    return diagnostics


def _aggregate_alignments(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    records = list(items)
    source_count = sum(int(item["source_tokens"]) for item in records)
    generated_count = sum(int(item["generated_tokens"]) for item in records)
    multiset_matches = sum(int(item["multiset_matches"]) for item in records)
    ordered_matches = sum(int(item["ordered_matches"]) for item in records)
    if source_count == 0 and generated_count == 0:
        precision = recall = ordered_precision = ordered_recall = 1.0
    else:
        precision = _ratio(multiset_matches, generated_count, empty=0.0)
        recall = _ratio(multiset_matches, source_count, empty=0.0)
        ordered_precision = _ratio(ordered_matches, generated_count, empty=0.0)
        ordered_recall = _ratio(ordered_matches, source_count, empty=0.0)

    def f1(p: float, r: float) -> float:
        return 2.0 * p * r / (p + r) if p + r else 0.0

    multiset_f1 = f1(precision, recall)
    ordered_f1 = f1(ordered_precision, ordered_recall)
    return {
        "source_tokens": source_count,
        "generated_tokens": generated_count,
        "multiset_matches": multiset_matches,
        "ordered_matches": ordered_matches,
        "coverage_recall": _round(recall),
        "coverage_precision": _round(precision),
        "multiset_f1": _round(multiset_f1),
        "ordered_recall": _round(ordered_recall),
        "ordered_precision": _round(ordered_precision),
        "ordered_f1": _round(ordered_f1),
        "order_preservation": _round(_ratio(ordered_matches, multiset_matches, empty=1.0)),
        "accuracy": _round(min(multiset_f1, ordered_f1)),
    }


def _validate_manifest_scope(
    manifest: dict[str, Any],
    required_source_range: Optional[tuple[int, int]],
) -> tuple[int, int]:
    source_range = manifest.get("source_range")
    if not source_range:
        raise EvaluationError("manifest must declare an inclusive source range")
    source_start, source_end = int(source_range[0]), int(source_range[1])
    if required_source_range is not None and (source_start, source_end) != required_source_range:
        raise EvaluationError(
            f"Bondy audit is fixed to physical source pages "
            f"{required_source_range[0]}-{required_source_range[1]}; manifest requested "
            f"{source_start}-{source_end}"
        )
    if required_source_range is not None:
        if manifest.get("expected_chapter_count") != EXPECTED_CHAPTER_COUNT:
            raise EvaluationError("Bondy manifest must declare exactly 17 chapters")
        chapters = manifest.get("chapters") or []
        if len(chapters) != EXPECTED_CHAPTER_COUNT:
            raise EvaluationError("Bondy manifest must contain 17 ordered chapter records")
        if int(chapters[0]["source_start"]) != 12 or int(chapters[-1]["source_end"]) != 473:
            raise EvaluationError("Bondy chapter records must cover chapter pages 12-473")
    return source_start, source_end


def _inspect_page(document: Any, index: int, label: str) -> Any:
    try:
        return document.inspect_page(index)
    except Exception as exc:
        raise EvaluationError(f"cannot inspect {label} physical page {index + 1}: {exc}") from exc


def audit_pdf_semantics(
    source_path: Path | str,
    generated_path: Path | str,
    *,
    manifest: dict[str, Any],
    generated_start: Optional[int] = None,
    generated_end: Optional[int] = None,
    backend: str = "auto",
    progress: bool = False,
    required_source_range: Optional[tuple[int, int]] = EXPECTED_SOURCE_RANGE,
) -> dict[str, Any]:
    """Audit exactly one mapped source/output page range, without AI or network."""

    source_path = Path(source_path).expanduser().resolve()
    generated_path = Path(generated_path).expanduser().resolve()
    source_start, source_end = _validate_manifest_scope(manifest, required_source_range)
    expected_pages = source_end - source_start + 1
    source_document = generated_document = None
    try:
        source_document = open_pdf(source_path, backend)
        generated_document = open_pdf(generated_path, source_document.backend_name)
        if source_end > source_document.page_count:
            raise EvaluationError(
                f"source mapping ends at page {source_end}, but source has "
                f"{source_document.page_count} pages"
            )
        manifest_sha = manifest.get("source_sha256")
        observed_sha = _sha256(source_path)
        if manifest_sha and observed_sha != str(manifest_sha).upper():
            raise EvaluationError(
                f"source SHA-256 mismatch: expected {manifest_sha}, observed {observed_sha}"
            )

        same_pdf = source_path == generated_path
        if same_pdf and generated_start is None and generated_end is None:
            generated_start, generated_end = source_start, source_end
            alignment_mode = "same_pdf_source_range"
        elif generated_start is None and generated_end is None:
            if generated_document.page_count != expected_pages:
                raise EvaluationError(
                    f"cannot infer a {expected_pages}-page generated mapping from a "
                    f"{generated_document.page_count}-page PDF; pass --generated-start and "
                    f"--generated-end for an exact mapped range"
                )
            generated_start, generated_end = 1, expected_pages
            alignment_mode = "whole_generated_pdf"
        else:
            if generated_start is None or generated_end is None:
                raise EvaluationError(
                    "--generated-start and --generated-end must be supplied together"
                )
            generated_start, generated_end = int(generated_start), int(generated_end)
            alignment_mode = "explicit_generated_range"
        if generated_start < 1 or generated_end > generated_document.page_count:
            raise EvaluationError(
                f"invalid generated range {generated_start}-{generated_end}; PDF has "
                f"{generated_document.page_count} pages"
            )
        if generated_end - generated_start + 1 != expected_pages:
            raise EvaluationError(
                f"generated mapping must contain exactly {expected_pages} pages, got "
                f"{generated_end - generated_start + 1}"
            )

        page_diagnostics: list[dict[str, Any]] = []
        all_critical: list[dict[str, Any]] = []
        all_source_confusables: list[dict[str, Any]] = []
        all_generated_confusables: list[dict[str, Any]] = []
        all_unexpected_confusables: list[dict[str, Any]] = []
        all_unresolved_references: list[dict[str, Any]] = []
        source_reference_counter: Counter[str] = Counter()
        generated_reference_counter: Counter[str] = Counter()
        text_errors: list[str] = []

        for offset in range(expected_pages):
            source_number = source_start + offset
            generated_number = generated_start + offset
            source = _inspect_page(source_document, source_number - 1, "source")
            generated = _inspect_page(generated_document, generated_number - 1, "generated")
            if progress and (offset == 0 or (offset + 1) % 25 == 0 or offset + 1 == expected_pages):
                print(
                    f"audited {offset + 1}/{expected_pages} mapped pages "
                    f"(source {source_number}, generated {generated_number})",
                    file=sys.stderr,
                )
            if source.text_error:
                text_errors.append(f"source page {source_number}: {source.text_error}")
            if generated.text_error:
                text_errors.append(f"generated page {generated_number}: {generated.text_error}")

            page_text_alignment = text_alignment(source.text, generated.text)
            page_math_alignment = math_alignment(source.text, generated.text)
            source_refs = Counter(reference_tokens(source.text))
            generated_refs = Counter(reference_tokens(generated.text))
            source_reference_counter.update(source_refs)
            generated_reference_counter.update(generated_refs)
            missing_page_refs = source_refs - generated_refs
            extra_page_refs = generated_refs - source_refs
            source_confusables = scan_unicode_confusables(source.text, source_number)
            generated_confusables = scan_unicode_confusables(generated.text, generated_number)
            unexpected_confusables = _unexpected_confusables(
                source_confusables, generated_confusables
            )
            unresolved = unresolved_reference_markers(generated.text, generated_number)
            critical = _critical_segment_diagnostics(
                source.text,
                generated.text,
                source_page=source_number,
                generated_page=generated_number,
            )
            critical_kinds = sorted({item["kind"] for item in critical})
            critical_suspicions = [item["key"] for item in critical if item["suspected_meaning_change"]]

            all_critical.extend(critical)
            all_source_confusables.extend(source_confusables)
            all_generated_confusables.extend(generated_confusables)
            all_unexpected_confusables.extend(unexpected_confusables)
            all_unresolved_references.extend(unresolved)
            page_diagnostics.append(
                {
                    "source_page": source_number,
                    "generated_page": generated_number,
                    "text_extraction_ok": not source.text_error and not generated.text_error,
                    "normalized_text_alignment": page_text_alignment,
                    "math_token_alignment": page_math_alignment,
                    "critical_structure_kinds": critical_kinds,
                    "critical_segment_count": len(critical),
                    "suspected_critical_changes": critical_suspicions,
                    "missing_reference_tokens_on_mapped_page": _counter_list(missing_page_refs),
                    "extra_reference_tokens_on_mapped_page": _counter_list(extra_page_refs),
                    "generated_unresolved_reference_markers": unresolved,
                    "generated_unicode_confusables": generated_confusables,
                    "unexpected_generated_unicode_confusables": unexpected_confusables,
                }
            )

        overall_text = _aggregate_alignments(
            item["normalized_text_alignment"] for item in page_diagnostics
        )
        overall_math = _aggregate_alignments(
            item["math_token_alignment"] for item in page_diagnostics
        )
        category_alignment: dict[str, Any] = {}
        for category in ("identifier", "greek", "operator", "numbering"):
            category_alignment[category] = _aggregate_alignments(
                item["math_token_alignment"]["categories"][category]
                for item in page_diagnostics
            )
        overall_math["categories"] = category_alignment

        missing_global_references = source_reference_counter - generated_reference_counter
        extra_global_references = generated_reference_counter - source_reference_counter
        suspected_changes = [item for item in all_critical if item["suspected_meaning_change"]]
        low_similarity_pages: list[dict[str, Any]] = []
        for page in page_diagnostics:
            if not page["critical_structure_kinds"]:
                continue
            page_critical = [
                item
                for item in all_critical
                if item["source_page"] == page["source_page"]
            ]
            segment_scores = [
                min(
                    float(item["text_alignment"]["accuracy"]),
                    float(item["math_token_alignment"]["accuracy"]),
                )
                for item in page_critical
                if item["text_alignment"] is not None
                and item["math_token_alignment"] is not None
            ]
            score = min(
                [
                    float(page["normalized_text_alignment"]["accuracy"]),
                    float(page["math_token_alignment"]["accuracy"]),
                    *segment_scores,
                ]
            )
            if score < CRITICAL_REVIEW_THRESHOLD or page["suspected_critical_changes"]:
                low_similarity_pages.append(
                    {
                        "source_page": page["source_page"],
                        "generated_page": page["generated_page"],
                        "critical_kinds": page["critical_structure_kinds"],
                        "lowest_alignment": _round(score),
                        "suspected_change_keys": page["suspected_critical_changes"],
                        "review_required": True,
                    }
                )
        low_similarity_pages.sort(key=lambda item: (item["lowest_alignment"], item["source_page"]))

        failed_hard_gates: list[str] = []
        if text_errors:
            failed_hard_gates.append("complete_text_extraction")
        if float(overall_text["coverage_recall"]) < TEXT_THRESHOLD:
            failed_hard_gates.append("normalized_text_coverage_at_least_98_percent")
        if float(overall_text["ordered_f1"]) < TEXT_THRESHOLD:
            failed_hard_gates.append("normalized_text_order_at_least_98_percent")
        if float(overall_math["accuracy"]) < MATH_THRESHOLD:
            failed_hard_gates.append("math_token_alignment_at_least_98_percent")
        for category, metric in category_alignment.items():
            if metric["source_tokens"] and float(metric["accuracy"]) < MATH_THRESHOLD:
                failed_hard_gates.append(f"math_category_{category}_at_least_98_percent")
        if suspected_changes:
            failed_hard_gates.append("no_suspected_meaning_change_on_critical_structure_pages")
        if all_unexpected_confusables:
            failed_hard_gates.append("no_unexpected_unicode_confusables")
        if all_unresolved_references:
            failed_hard_gates.append("no_unresolved_reference_markers")
        if missing_global_references or extra_global_references:
            failed_hard_gates.append("global_reference_inventory_match")

        review_items: list[dict[str, Any]] = [
            {
                "id": "independent_mathematical_semantic_review",
                "status": "required_not_completed",
                "scope": "definitions, theorems, algorithms, exercises, and a stratified sample of ordinary pages",
                "reason": (
                    "Extraction/token agreement cannot establish logical equivalence, diagram meaning, "
                    "proof validity, or the absence of a visually substituted symbol."
                ),
                "required_action": (
                    "A human or an independent Codex review must compare the visible source and "
                    "generated pages; record page-level evidence separately."
                ),
            }
        ]
        if low_similarity_pages:
            review_items.append(
                {
                    "id": "critical_low_similarity_pages",
                    "status": "required_not_completed",
                    "source_pages": [item["source_page"] for item in low_similarity_pages],
                    "reason": "One or more critical pages fell below the conservative 99.5% review band.",
                    "required_action": "Visually and semantically compare every listed statement.",
                }
            )
        if all_unexpected_confusables:
            review_items.append(
                {
                    "id": "unexpected_unicode_confusables",
                    "status": "blocking",
                    "source_pages": sorted({item["page"] for item in all_unexpected_confusables}),
                    "reason": "Generated extraction contains Cyrillic/fullwidth/replacement glyphs absent from its mapped source page.",
                    "required_action": "Resolve each glyph against the rendered source and regenerate the page.",
                }
            )
        if all_unresolved_references or missing_global_references or extra_global_references:
            review_items.append(
                {
                    "id": "reference_integrity",
                    "status": "blocking",
                    "reason": "Unresolved markers or a changed reference inventory was detected.",
                    "required_action": "Repair references and rerun both LaTeX compilation and this audit.",
                }
            )

        decision = "fail" if failed_hard_gates else "pass"
        report = {
            "schema": "latexstruct-bondy-semantic-audit-v1",
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "audit_bondy_semantics",
                "version": TOOL_VERSION,
                "offline": True,
                "model_invoked": False,
                "network_used": False,
                "blind_gold_used": False,
                "comparison_basis": "visible source PDF extraction and generated PDF extraction only",
            },
            "gate": {
                "name": GATE_NAME,
                "decision": decision,
                "exit_code": 1 if failed_hard_gates else 0,
                "thresholds": {
                    "normalized_text_alignment": TEXT_THRESHOLD,
                    "math_token_alignment": MATH_THRESHOLD,
                    "critical_review_band": CRITICAL_REVIEW_THRESHOLD,
                },
                "observed": {
                    "normalized_text_coverage": overall_text["coverage_recall"],
                    "normalized_text_ordered_f1": overall_text["ordered_f1"],
                    "normalized_text_accuracy": overall_text["accuracy"],
                    "math_token_accuracy": overall_math["accuracy"],
                },
                "failed_hard_gates": failed_hard_gates,
                "publication_readiness": "not_established",
                "mathematical_semantic_accuracy": "not_proven",
                "semantic_100_percent_claimed": False,
                "scope_note": (
                    "PASS means the offline extraction alignment gates passed; it does not "
                    "establish publication readiness or mathematical-semantic correctness."
                ),
            },
            "inputs": {
                "source_pdf": str(source_path),
                "generated_pdf": str(generated_path),
                "manifest": manifest.get("path"),
                "source_sha256_expected": manifest_sha,
                "source_sha256_observed": observed_sha,
                "source_range": [source_start, source_end],
                "generated_range": [generated_start, generated_end],
                "mapped_page_count": expected_pages,
                "alignment_mode": alignment_mode,
                "backend": source_document.backend_name,
            },
            "overall_normalized_text_alignment": overall_text,
            "overall_math_token_alignment": overall_math,
            "critical_structure": {
                "target_kinds": sorted(TARGET_CRITICAL_KINDS),
                "segment_count": len(all_critical),
                "critical_page_count": len(
                    {item["source_page"] for item in all_critical}
                ),
                "low_similarity_pages": low_similarity_pages,
                "suspected_meaning_changes": suspected_changes,
                "segment_diagnostics": all_critical,
            },
            "unicode_confusables": {
                "source_findings": all_source_confusables,
                "generated_findings": all_generated_confusables,
                "unexpected_generated_findings": all_unexpected_confusables,
            },
            "references": {
                "source_token_count": sum(source_reference_counter.values()),
                "generated_token_count": sum(generated_reference_counter.values()),
                "missing_from_generated": _counter_list(missing_global_references),
                "extra_in_generated": _counter_list(extra_global_references),
                "unresolved_generated_markers": all_unresolved_references,
            },
            "review_items": review_items,
            "page_diagnostics": page_diagnostics,
            "extraction_errors": text_errors,
            "limitations": [
                "PDF text extraction can agree while a rendered glyph, crop, or diagram is wrong.",
                "Token alignment does not prove theorem truth, proof validity, or logical equivalence.",
                "Single-letter prose is conservatively included among mathematical identifiers.",
                "The source PDF is comparison data only; no embedded text is executed as instructions.",
                "No hidden or blind-test gold data is read.",
            ],
        }
        return report
    finally:
        if generated_document is not None:
            generated_document.close()
        if source_document is not None:
            source_document.close()


def failure_report(source_path: Path | str, generated_path: Path | str, message: str) -> dict[str, Any]:
    return {
        "schema": "latexstruct-bondy-semantic-audit-v1",
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "audit_bondy_semantics",
            "version": TOOL_VERSION,
            "offline": True,
            "model_invoked": False,
            "network_used": False,
            "blind_gold_used": False,
        },
        "gate": {
            "name": GATE_NAME,
            "decision": "error",
            "exit_code": 2,
            "thresholds": {
                "normalized_text_alignment": TEXT_THRESHOLD,
                "math_token_alignment": MATH_THRESHOLD,
            },
            "observed": {},
            "failed_hard_gates": ["audit_completed"],
            "publication_readiness": "not_established",
            "mathematical_semantic_accuracy": "not_proven",
            "semantic_100_percent_claimed": False,
        },
        "inputs": {
            "source_pdf": str(Path(source_path).expanduser()),
            "generated_pdf": str(Path(generated_path).expanduser()),
        },
        "overall_normalized_text_alignment": {},
        "overall_math_token_alignment": {},
        "critical_structure": {
            "low_similarity_pages": [],
            "suspected_meaning_changes": [],
            "segment_diagnostics": [],
        },
        "unicode_confusables": {"unexpected_generated_findings": []},
        "references": {
            "missing_from_generated": [],
            "extra_in_generated": [],
            "unresolved_generated_markers": [],
        },
        "review_items": [
            {
                "id": "audit_operational_error",
                "status": "blocking",
                "reason": message,
                "required_action": "Fix the operational error and rerun the complete audit.",
            }
        ],
        "page_diagnostics": [],
        "errors": [message],
    }


def report_markdown(report: dict[str, Any]) -> str:
    gate = report.get("gate", {})
    lines = [
        "# Bondy first-17-chapter offline content/math audit",
        "",
        f"- Decision: **{str(gate.get('decision', 'error')).upper()}**",
        f"- Publication readiness: **{gate.get('publication_readiness', 'not_established')}**",
        f"- Mathematical semantic accuracy: **{gate.get('mathematical_semantic_accuracy', 'not_proven')}**",
        "- Offline/model/network/blind gold: **yes / no / no / no**",
        "",
        "> A PASS here means only that the declared offline extraction-alignment gates passed. "
        "It does not establish publication readiness, mathematical equivalence, or 100% semantic accuracy.",
        "",
    ]
    if gate.get("decision") == "error":
        lines.extend(["## Operational errors", ""])
        lines.extend(f"- {item}" for item in report.get("errors", []))
    else:
        observed = gate.get("observed", {})
        thresholds = gate.get("thresholds", {})
        lines.extend(
            [
                "## Gate summary",
                "",
                "| Metric | Observed | Required |",
                "|---|---:|---:|",
                f"| Normalized text coverage | {float(observed.get('normalized_text_coverage', 0)):.4%} | {float(thresholds.get('normalized_text_alignment', TEXT_THRESHOLD)):.2%} |",
                f"| Normalized text ordered F1 | {float(observed.get('normalized_text_ordered_f1', 0)):.4%} | {float(thresholds.get('normalized_text_alignment', TEXT_THRESHOLD)):.2%} |",
                f"| Math/Greek/operator/number token alignment | {float(observed.get('math_token_accuracy', 0)):.4%} | {float(thresholds.get('math_token_alignment', MATH_THRESHOLD)):.2%} |",
                "",
            ]
        )
    failed = gate.get("failed_hard_gates", [])
    lines.extend(["## Failed hard gates", ""])
    lines.extend(f"- `{item}`" for item in failed)
    if not failed:
        lines.append("- None in this offline audit.")

    critical = report.get("critical_structure", {})
    lines.extend(["", "## Critical-structure low-similarity pages", ""])
    lines.extend(
        [
            "| Source | Generated | Kinds | Lowest alignment | Suspected change |",
            "|---:|---:|---|---:|---|",
        ]
    )
    for item in critical.get("low_similarity_pages", []):
        lines.append(
            f"| {item['source_page']} | {item['generated_page']} | "
            f"{', '.join(item['critical_kinds'])} | {float(item['lowest_alignment']):.4%} | "
            f"{', '.join(item['suspected_change_keys']) or '-'} |"
        )
    if not critical.get("low_similarity_pages"):
        lines.append("| - | - | - | - | none detected by the conservative 99.5% review band |")

    lines.extend(["", "## Suspected critical meaning changes", ""])
    for item in critical.get("suspected_meaning_changes", []):
        lines.append(
            f"- Source {item['source_page']} -> generated {item['generated_page']}, "
            f"`{item['key']}`: {', '.join(item['reasons'])}"
        )
    if not critical.get("suspected_meaning_changes"):
        lines.append("- None mechanically suspected; independent semantic review is still required.")

    confusables = report.get("unicode_confusables", {}).get(
        "unexpected_generated_findings", []
    )
    lines.extend(["", "## Unexpected Unicode confusables", ""])
    for item in confusables:
        lines.append(
            f"- Generated page {item['page']}: `{item['character']}` "
            f"({item['codepoint']}, {item['kind']}), context: `{item['context']}`"
        )
    if not confusables:
        lines.append("- None.")

    references = report.get("references", {})
    lines.extend(["", "## References", ""])
    lines.append(
        f"- Missing from generated: `{json.dumps(references.get('missing_from_generated', []), ensure_ascii=False)}`"
    )
    lines.append(
        f"- Extra in generated: `{json.dumps(references.get('extra_in_generated', []), ensure_ascii=False)}`"
    )
    unresolved = references.get("unresolved_generated_markers", [])
    lines.append(f"- Unresolved `??`/reference markers: **{len(unresolved)}**")

    lines.extend(["", "## Required human/Codex review", ""])
    for item in report.get("review_items", []):
        lines.append(
            f"- **{item['id']}** (`{item['status']}`): {item['reason']} "
            f"Required: {item['required_action']}"
        )

    pages = report.get("page_diagnostics", [])
    lines.extend(
        [
            "",
            "## Per-page normalized text and math alignment",
            "",
            "| Source | Generated | Text coverage | Text order F1 | Math tokens | Critical | Confusables | Page ref deltas |",
            "|---:|---:|---:|---:|---:|---|---:|---:|",
        ]
    )
    for item in pages:
        text_metric = item["normalized_text_alignment"]
        math_metric = item["math_token_alignment"]
        ref_delta = sum(
            int(entry["count"])
            for entry in item["missing_reference_tokens_on_mapped_page"]
            + item["extra_reference_tokens_on_mapped_page"]
        )
        lines.append(
            f"| {item['source_page']} | {item['generated_page']} | "
            f"{float(text_metric['coverage_recall']):.4%} | "
            f"{float(text_metric['ordered_f1']):.4%} | "
            f"{float(math_metric['accuracy']):.4%} | "
            f"{', '.join(item['critical_structure_kinds']) or '-'} | "
            f"{len(item['unexpected_generated_unicode_confusables'])} | {ref_delta} |"
        )
    if not pages:
        lines.append("| - | - | - | - | - | - | - | - |")
    lines.append("")
    return "\n".join(lines)


def write_reports(report: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    json_path, markdown_path = json_path.resolve(), markdown_path.resolve()
    if json_path == markdown_path:
        raise EvaluationError("JSON and Markdown output paths must differ")
    _atomic_write(json_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(markdown_path, report_markdown(report))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline, fail-closed normalized-text and mathematical-token audit for "
            "Bondy physical source pages 3-473."
        )
    )
    parser.add_argument("source_pdf", type=Path)
    parser.add_argument("generated_pdf", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--generated-start", type=int)
    parser.add_argument("--generated-end", type=int)
    parser.add_argument("--backend", choices=("auto", "pymupdf", "pypdf"), default="auto")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    generated = args.generated_pdf.expanduser()
    json_path = args.json_out or generated.with_suffix(".semantic-audit.json")
    markdown_path = args.markdown_out or generated.with_suffix(".semantic-audit.md")
    try:
        manifest = load_manifest(args.manifest)
        report = audit_pdf_semantics(
            args.source_pdf,
            args.generated_pdf,
            manifest=manifest,
            generated_start=args.generated_start,
            generated_end=args.generated_end,
            backend=args.backend,
            progress=not args.quiet,
        )
        exit_code = int(report["gate"]["exit_code"])
    except Exception as exc:
        report = failure_report(args.source_pdf, args.generated_pdf, str(exc))
        exit_code = 2
    try:
        write_reports(report, json_path, markdown_path)
    except Exception as exc:
        print(f"failed to write semantic-audit reports: {exc}", file=sys.stderr)
        return 2
    print(
        f"{report['gate']['decision'].upper()} "
        f"publication={report['gate']['publication_readiness']} "
        f"json={json_path} markdown={markdown_path}",
        file=sys.stderr,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
