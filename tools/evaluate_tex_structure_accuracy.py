#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed evaluation of structural edits made to a LaTeX document.

The evaluator is deliberately independent of LaTeXStruct's production parser.
It compares formal environments against line-bounded truth, checks that prose
was conserved, and verifies that an outline and a table of contents survived.
It never treats compilation success or a visually plausible PDF as accuracy.

Truth manifest example::

    {
      "schema": "latexstruct-tex-structure-truth-v1",
      "items": [
        {"kind": "theorem", "id": "1.1", "start_line": 20, "end_line": 24},
        {"kind": "proof", "id": "P1.1", "start_line": 26, "end_line": 30}
      ]
    }

Without a manifest, simple bold formal headings and italic proof headings are
discovered automatically.  Release evidence should use a reviewed manifest so
that a detector cannot silently define its own ground truth.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


TRUTH_SCHEMA = "latexstruct-tex-structure-truth-v1"
FORMAL_KINDS = (
    "theorem",
    "lemma",
    "proposition",
    "corollary",
    "conjecture",
    "claim",
    "fact",
    "definition",
    "remark",
    "observation",
    "note",
    "example",
    "problem",
    "question",
)
ALL_KINDS = FORMAL_KINDS + ("proof",)
KIND_PATTERN = "|".join(FORMAL_KINDS)

FORMAL_HEADING_RE = re.compile(
    rf"\\textbf\s*\{{\s*(?P<kind>{KIND_PATTERN})\s+"
    r"(?P<id>\d+(?:\.\d+)*)(?:\.)?[^{}]*\}",
    re.IGNORECASE,
)
PLAIN_FORMAL_HEADING_RE = re.compile(
    rf"(?m)^\s*(?P<kind>{KIND_PATTERN})\s+"
    r"(?P<id>\d+(?:\.\d+)*)(?:\.(?!\d)|(?=\s+\())\s*"
    r"\s*",
    re.IGNORECASE,
)
PROOF_HEADING_RE = re.compile(
    r"\\textit\s*\{\s*(?:proof|sketch\s+of\s+the\s+proof|proof\s+of\b)[^{}]*\}",
    re.IGNORECASE,
)
PLAIN_PROOF_HEADING_RE = re.compile(
    r"(?m)^\s*(?:Proof(?:\s+of\s+[^\n]*?)?|Sketch\s+of\s+the\s+proof)"
    r"\.(?!\d)\s*"
)
ENV_BEGIN_RE = re.compile(
    rf"\\begin\{{(?P<kind>{'|'.join(ALL_KINDS)})(?P<star>\*)?\}}",
    re.IGNORECASE,
)
STRUCTURAL_COMMAND_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection)\*?\s*\{"
)
OUTLINE_COMMAND_RE = re.compile(
    r"\\(?P<command>part|chapter|section|subsection|subsubsection)"
    r"(?P<star>\*)?\s*\{",
    re.IGNORECASE,
)
INLINE_OUTLINE_RE = re.compile(
    r"\\textbf\s*\{\s*(?P<number>\d+(?:\.\d+)*)\.\s*(?P<title>[^{}]+)\}",
    re.IGNORECASE,
)
PLAIN_OUTLINE_RE = re.compile(
    r"(?m)^\s*(?:(?P<number>\d+)\.\s+)?(?P<title>[A-Z][A-Z\s.'’\\\-–—]+)\s*$"
)
PLAIN_OUTLINE_STRUCTURAL_RE = re.compile(
    r"(?mi)^\s*(?:\d+\.\s+[A-Z][A-Z\s.'’\\\-–—]+|REFERENCES)\s*$"
)
TOKEN_RE = re.compile(r"\\[A-Za-z@]+|\\[^\s]|[^\W_]+|_|[^\s]", re.UNICODE)


@dataclass(frozen=True)
class TruthItem:
    kind: str
    item_id: str
    start_line: int
    end_line: int
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class CandidateEnvironment:
    kind: str
    item_id: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int
    tokens: tuple[str, ...]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _strip_comments(text: str) -> str:
    cleaned = []
    for line in text.splitlines():
        cut = len(line)
        for index, char in enumerate(line):
            if char != "%":
                continue
            slash_count = 0
            cursor = index - 1
            while cursor >= 0 and line[cursor] == "\\":
                slash_count += 1
                cursor -= 1
            if slash_count % 2 == 0:
                cut = index
                break
        cleaned.append(line[:cut])
    return "\n".join(cleaned)


def _document_body(text: str) -> str:
    match = re.search(r"\\begin\{document\}", text)
    if not match:
        return text
    end = re.search(r"\\end\{document\}", text[match.end():])
    if not end:
        return text[match.end():]
    return text[match.end():match.end() + end.start()]


def _balanced_group_end(text: str, opening_brace: int) -> int | None:
    depth = 0
    index = opening_brace
    while index < len(text):
        char = text[index]
        if char in "{}":
            slash_count = 0
            cursor = index - 1
            while cursor >= 0 and text[cursor] == "\\":
                slash_count += 1
                cursor -= 1
            if slash_count % 2:
                index += 1
                continue
            depth += 1 if char == "{" else -1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _remove_balanced_commands(text: str, pattern: re.Pattern[str]) -> str:
    output: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(text, cursor)
        if not match:
            output.append(text[cursor:])
            break
        opening = text.find("{", match.start(), match.end())
        end = _balanced_group_end(text, opening)
        if end is None:
            output.append(text[cursor:])
            break
        output.append(text[cursor:match.start()])
        output.append(" ")
        cursor = end
    return "".join(output)


def _remove_formal_markup(text: str) -> str:
    text = FORMAL_HEADING_RE.sub(" ", text)
    text = PLAIN_FORMAL_HEADING_RE.sub(" ", text)
    text = PROOF_HEADING_RE.sub(" ", text)
    text = PLAIN_PROOF_HEADING_RE.sub(" ", text)
    text = re.sub(
        rf"\\(?:begin|end)\{{(?:{'|'.join(ALL_KINDS)})\*?\}}"
        r"(?:\s*\[[^\]\n]*\])?",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\\ifcsname\s+qedsymbol\\endcsname\s*"
        r"\\let\\qedsymbol\\empty\\fi",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    return text


def _normalise_fragment(text: str, *, document_scope: bool = False) -> tuple[str, ...]:
    if document_scope:
        text = _document_body(text)
    text = _strip_comments(text)
    text = _remove_formal_markup(text)
    text = INLINE_OUTLINE_RE.sub(" ", text)
    text = PLAIN_OUTLINE_STRUCTURAL_RE.sub(" ", text)
    text = _remove_balanced_commands(text, STRUCTURAL_COMMAND_RE)
    text = re.sub(
        r"\\(?:tableofcontents|maketitle|frontmatter|mainmatter|backmatter)\b",
        " ",
        text,
    )
    # FaithfulBook inserts these zero-argument layout controls in the document
    # body.  They affect navigation/pagination only and must not be counted as
    # source prose added by the structural transformation.
    text = re.sub(
        r"\\(?:LSFirstPageEmpty|LSMainMatter|LSChapterContents)\b",
        " ",
        text,
    )
    text = re.sub(
        r"\\(?:clearpage|cleardoublepage|newpage|pagebreak)\b"
        r"(?:[ \t]*\[[^\]\r\n]*\])?",
        " ",
        text,
    )
    text = re.sub(r"\\(?:label|hypertarget)\s*\{[^{}]*\}", " ", text)
    text = re.sub(r"\\(?:begin|end)\{center\}", " ", text)
    text = re.sub(
        r"\\addcontentsline\s*\{[^{}]*\}\s*\{[^{}]*\}\s*\{[^{}]*\}",
        " ",
        text,
    )
    # A full stop is sometimes outside the bold formal-heading group.  It is
    # heading punctuation, not statement content.
    text = re.sub(r"(?m)^\s*[.:]\s*", " ", text)
    return tuple(TOKEN_RE.findall(text))


def _normalise_item(text: str) -> tuple[str, ...]:
    return _normalise_fragment(text)


def _validate_truth_items(raw_items: object, lines: Sequence[str]) -> list[TruthItem]:
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("truth manifest items must be a non-empty array")
    result: list[TruthItem] = []
    seen: set[tuple[str, str]] = set()
    occupied: list[tuple[int, int, str]] = []
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            raise ValueError(f"truth item {index} must be an object")
        kind = str(raw.get("kind", "")).strip().lower()
        item_id = str(raw.get("id", "")).strip()
        start = raw.get("start_line")
        end = raw.get("end_line")
        if kind not in ALL_KINDS or not item_id:
            raise ValueError(f"truth item {index} has invalid kind or id")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
            or end > len(lines)
        ):
            raise ValueError(f"truth item {kind}:{item_id} has invalid line bounds")
        key = (kind, item_id.casefold())
        if key in seen:
            raise ValueError(f"duplicate truth key: {kind}:{item_id}")
        for other_start, other_end, other_key in occupied:
            if start <= other_end and other_start <= end:
                raise ValueError(
                    f"overlapping truth bounds: {kind}:{item_id} and {other_key}"
                )
        source = "\n".join(lines[start - 1:end])
        if kind == "proof":
            if not (PROOF_HEADING_RE.search(source) or PLAIN_PROOF_HEADING_RE.search(source)):
                raise ValueError(f"truth proof {item_id} has no proof heading at its boundary")
        else:
            header = FORMAL_HEADING_RE.search(source) or PLAIN_FORMAL_HEADING_RE.search(source)
            if not header:
                raise ValueError(f"truth item {kind}:{item_id} has no formal heading")
            if (
                header.group("kind").casefold() != kind
                or header.group("id").rstrip(".") != item_id.rstrip(".")
            ):
                raise ValueError(f"truth heading does not match {kind}:{item_id}")
        tokens = _normalise_item(source)
        if not tokens:
            raise ValueError(f"truth item {kind}:{item_id} has an empty body")
        seen.add(key)
        occupied.append((start, end, f"{kind}:{item_id}"))
        result.append(TruthItem(kind, item_id, start, end, tokens))
    return result


def _infer_truth_items(text: str) -> list[TruthItem]:
    lines = text.splitlines()
    raw: list[dict[str, object]] = []
    for line_number, line in enumerate(lines, start=1):
        formal = FORMAL_HEADING_RE.search(line) or PLAIN_FORMAL_HEADING_RE.search(line)
        proof = PROOF_HEADING_RE.search(line) or PLAIN_PROOF_HEADING_RE.search(line)
        if not formal and not proof:
            continue
        end = line_number
        while end < len(lines) and lines[end].strip():
            end += 1
        if formal:
            raw.append({
                "kind": formal.group("kind").casefold(),
                "id": formal.group("id").rstrip("."),
                "start_line": line_number,
                "end_line": end,
            })
        else:
            raw.append({
                "kind": "proof",
                "id": f"P{line_number}",
                "start_line": line_number,
                "end_line": end,
            })
    if not raw:
        raise ValueError("no formal truth items were discovered")
    return _validate_truth_items(raw, lines)


def load_truth(text: str, manifest: dict[str, object] | None) -> list[TruthItem]:
    if manifest is None:
        return _infer_truth_items(text)
    if not isinstance(manifest, dict) or manifest.get("schema") != TRUTH_SCHEMA:
        raise ValueError(f"truth manifest schema must be {TRUTH_SCHEMA!r}")
    return _validate_truth_items(manifest.get("items"), text.splitlines())


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _id_from_title(kind: str, title: str, body: str) -> str:
    if kind == "proof":
        return ""
    number = re.search(r"(?<!\d)(\d+(?:\.\d+)+|\d+)(?!\d)", title)
    if number:
        return number.group(1).rstrip(".")
    heading = FORMAL_HEADING_RE.search(body)
    if heading is None:
        heading = PLAIN_FORMAL_HEADING_RE.search(body)
    if heading and heading.group("kind").casefold() == kind:
        return heading.group("id").rstrip(".")
    label = re.search(
        rf"\\label\s*\{{(?:{kind[:3]}|{kind})[:._-]?(\d+(?:\.\d+)*)\}}",
        body,
        flags=re.IGNORECASE,
    )
    return label.group(1) if label else ""


def extract_candidate_environments(text: str) -> list[CandidateEnvironment]:
    environments: list[CandidateEnvironment] = []
    cursor = 0
    while True:
        begin = ENV_BEGIN_RE.search(text, cursor)
        if not begin:
            break
        kind = begin.group("kind").casefold()
        env_name = kind + ("*" if begin.group("star") else "")
        end_re = re.compile(rf"\\end\{{{re.escape(env_name)}\}}", re.IGNORECASE)
        end = end_re.search(text, begin.end())
        if not end:
            # An unbalanced candidate is a prediction with a body extending to
            # EOF.  Keeping it makes the scorer fail closed instead of hiding it.
            body_start = begin.end()
            body_end = len(text)
            end_offset = len(text)
        else:
            body_start = begin.end()
            body_end = end.start()
            end_offset = end.end()
        title = ""
        title_match = re.match(r"\s*\[([^\]\n]*)\]", text[body_start:body_end])
        if title_match:
            title = title_match.group(1)
            body_start += title_match.end()
        body = text[body_start:body_end]
        environments.append(CandidateEnvironment(
            kind=kind,
            item_id=_id_from_title(kind, title, body),
            start_line=_line_number(text, begin.start()),
            end_line=_line_number(text, end_offset),
            start_offset=begin.start(),
            end_offset=end_offset,
            tokens=_normalise_item(body),
        ))
        cursor = max(end_offset, begin.end())
    return environments


def _is_contiguous(needle: Sequence[str], haystack: Sequence[str]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    return any(tuple(haystack[index:index + width]) == tuple(needle)
               for index in range(len(haystack) - width + 1))


def _outline_title(title: str) -> str:
    title = re.sub(r"^\s*\d+(?:\.\d+)*\.?\s*", "", title)
    title = re.sub(r"\\(?:textbf|textit|emph|textsc)\s*", "", title)
    title = title.rstrip(" .")
    tokens = TOKEN_RE.findall(title.casefold())
    return "".join(tokens)


def extract_outline(text: str) -> list[dict[str, object]]:
    body = _strip_comments(_document_body(text))
    command_nodes: list[tuple[int, str, int]] = []
    ranks = {"part": 0, "chapter": 1, "section": 2, "subsection": 3,
             "subsubsection": 4}
    for match in OUTLINE_COMMAND_RE.finditer(body):
        opening = body.find("{", match.start(), match.end())
        end = _balanced_group_end(body, opening)
        if end is None:
            continue
        title = body[opening + 1:end - 1]
        command_nodes.append((match.start(), title, ranks[match.group("command").casefold()]))
    min_rank = min((rank for _, _, rank in command_nodes), default=2)
    nodes: list[dict[str, object]] = [
        {
            "level": rank - min_rank,
            "title": _outline_title(title),
            "line": _line_number(body, offset),
        }
        for offset, title, rank in command_nodes
        if _outline_title(title)
    ]
    for match in INLINE_OUTLINE_RE.finditer(body):
        number = match.group("number")
        title = _outline_title(match.group("title"))
        if title:
            nodes.append({
                "level": number.count("."),
                "title": title,
                "line": _line_number(body, match.start()),
            })
    occupied_lines = {int(item["line"]) for item in nodes}
    for match in PLAIN_OUTLINE_RE.finditer(body):
        line = _line_number(body, match.start())
        title_text = match.group("title").strip()
        number = match.group("number")
        if line in occupied_lines or (number is None and title_text.casefold() != "references"):
            continue
        title = _outline_title(title_text)
        if title:
            nodes.append({"level": 0, "title": title, "line": line})
    nodes.sort(key=lambda item: int(item["line"]))
    return nodes


def _masked_outside_environments(
    text: str, environments: Iterable[CandidateEnvironment]
) -> str:
    chars = list(text)
    for environment in environments:
        chars[environment.start_offset:environment.end_offset] = (
            " " * (environment.end_offset - environment.start_offset)
        )
    return "".join(chars)


def _line_token_deficits(original: str, candidate: str) -> tuple[list[int], list[int]]:
    def document_lines(text: str) -> list[tuple[int, str]]:
        lines = text.splitlines()
        start = next(
            (index for index, line in enumerate(lines)
             if re.search(r"\\begin\{document\}", line)),
            -1,
        )
        end = next(
            (index for index, line in enumerate(lines[start + 1:], start=start + 1)
             if re.search(r"\\end\{document\}", line)),
            len(lines),
        )
        return [(index + 1, lines[index]) for index in range(start + 1, end)]

    original_lines = document_lines(original)
    candidate_lines = document_lines(candidate)

    def line_tokens(line: str) -> tuple[str, ...]:
        return _normalise_fragment(line)

    original_units = [
        (line_number, tokens)
        for line_number, line in original_lines
        if (tokens := line_tokens(line))
    ]
    candidate_units = [
        (line_number, tokens)
        for line_number, line in candidate_lines
        if (tokens := line_tokens(line))
    ]
    matcher = difflib.SequenceMatcher(
        a=[tokens for _, tokens in original_units],
        b=[tokens for _, tokens in candidate_units],
        autojunk=False,
    )
    missing: list[int] = []
    excess: list[int] = []
    for operation, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        if operation in {"delete", "replace"}:
            missing.extend(line for line, _ in original_units[left_start:left_end])
        if operation in {"insert", "replace"}:
            excess.extend(line for line, _ in candidate_units[right_start:right_end])
    return missing, excess


def _first_difference(left: Sequence[str], right: Sequence[str]) -> int | None:
    for index, (left_token, right_token) in enumerate(zip(left, right)):
        if left_token != right_token:
            return index
    return None if len(left) == len(right) else min(len(left), len(right))


def evaluate_tex_structure(
    original: str,
    candidate: str,
    *,
    manifest: dict[str, object] | None = None,
    threshold: float = 0.95,
    require_toc: bool = True,
) -> dict[str, object]:
    """Return a content-free, JSON-serialisable accuracy report."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between zero and one")
    truth = load_truth(original, manifest)
    predicted = extract_candidate_environments(candidate)

    used_predictions: set[int] = set()
    exact_matches: list[dict[str, object]] = []
    missing: list[str] = []
    boundary_errors: list[dict[str, object]] = []
    duplicates: list[dict[str, object]] = []

    for expected in truth:
        if expected.kind == "proof":
            same_key = [
                (index, item) for index, item in enumerate(predicted)
                if item.kind == "proof"
            ]
        else:
            same_key = [
                (index, item) for index, item in enumerate(predicted)
                if item.kind == expected.kind
                and item.item_id.rstrip(".") == expected.item_id.rstrip(".")
            ]
        exact = [(index, item) for index, item in same_key
                 if item.tokens == expected.tokens]
        if exact:
            chosen_index, chosen = next(
                ((index, item) for index, item in exact if index not in used_predictions),
                exact[0],
            )
            if chosen_index not in used_predictions:
                used_predictions.add(chosen_index)
                exact_matches.append({
                    "kind": expected.kind,
                    "id": expected.item_id,
                    "candidate_start_line": chosen.start_line,
                    "candidate_end_line": chosen.end_line,
                })
            extra_exact = [item for index, item in exact if index != chosen_index]
            if extra_exact:
                duplicates.append({
                    "kind": expected.kind,
                    "id": expected.item_id,
                    "candidate_lines": [item.start_line for _, item in exact],
                })
            continue

        missing.append(f"{expected.kind}:{expected.item_id}")
        candidates = [(index, item) for index, item in same_key
                      if index not in used_predictions]
        if expected.kind == "proof":
            candidates = [
                (index, item) for index, item in candidates
                if _is_contiguous(item.tokens, expected.tokens)
                or _is_contiguous(expected.tokens, item.tokens)
            ]
        if candidates:
            index, closest = min(
                candidates,
                key=lambda pair: abs(len(pair[1].tokens) - len(expected.tokens)),
            )
            used_predictions.add(index)
            if _is_contiguous(expected.tokens, closest.tokens):
                error = "overwrapped"
            elif _is_contiguous(closest.tokens, expected.tokens):
                error = "underwrapped"
            else:
                error = "content_mismatch"
            boundary_errors.append({
                "kind": expected.kind,
                "id": expected.item_id,
                "error": error,
                "candidate_start_line": closest.start_line,
                "candidate_end_line": closest.end_line,
            })

    unmatched = [
        {
            "kind": item.kind,
            "id": item.item_id or None,
            "start_line": item.start_line,
            "end_line": item.end_line,
        }
        for index, item in enumerate(predicted)
        if index not in used_predictions
    ]
    true_positive = len(exact_matches)
    expected_count = len(truth)
    predicted_count = len(predicted)
    precision = true_positive / predicted_count if predicted_count else 0.0
    recall = true_positive / expected_count if expected_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    outside = _masked_outside_environments(candidate, predicted)
    residual = [
        {
            "kind": match.group("kind").casefold(),
            "id": match.group("id").rstrip("."),
            "line": _line_number(outside, match.start()),
        }
        for match in FORMAL_HEADING_RE.finditer(outside)
    ]
    residual.extend({
        "kind": match.group("kind").casefold(),
        "id": match.group("id").rstrip("."),
        "line": _line_number(outside, match.start()),
    } for match in PLAIN_FORMAL_HEADING_RE.finditer(outside))
    residual.extend({
        "kind": "proof",
        "id": None,
        "line": _line_number(outside, match.start()),
    } for match in PROOF_HEADING_RE.finditer(outside))
    residual.extend({
        "kind": "proof",
        "id": None,
        "line": _line_number(outside, match.start()),
    } for match in PLAIN_PROOF_HEADING_RE.finditer(outside))

    original_tokens = _normalise_fragment(original, document_scope=True)
    candidate_tokens = _normalise_fragment(candidate, document_scope=True)
    original_counter = Counter(original_tokens)
    candidate_counter = Counter(candidate_tokens)
    missing_token_count = sum((original_counter - candidate_counter).values())
    excess_token_count = sum((candidate_counter - original_counter).values())
    missing_lines, excess_lines = _line_token_deficits(original, candidate)
    token_conserved = original_tokens == candidate_tokens

    expected_outline = extract_outline(original)
    candidate_outline = extract_outline(candidate)
    expected_outline_counts = Counter(
        (item["level"], item["title"]) for item in expected_outline
    )
    candidate_outline_counts = Counter(
        (item["level"], item["title"]) for item in candidate_outline
    )
    outline_matched = sum((expected_outline_counts & candidate_outline_counts).values())
    outline_total = sum(expected_outline_counts.values())
    outline_coverage = outline_matched / outline_total if outline_total else 1.0
    missing_outline = [
        {"level": level, "title_hash": _sha256_text(str(title))[:16]}
        for (level, title), count in (expected_outline_counts - candidate_outline_counts).items()
        for _ in range(count)
    ]
    unexpected_outline = [
        {"level": level, "title_hash": _sha256_text(str(title))[:16]}
        for (level, title), count in (candidate_outline_counts - expected_outline_counts).items()
        for _ in range(count)
    ]
    toc_present = bool(re.search(
        r"\\tableofcontents\b", _strip_comments(_document_body(candidate))
    ))

    blockers = {
        "missing": bool(missing),
        "duplicate": bool(duplicates),
        "boundary_error": bool(boundary_errors),
        "unmatched_environment": bool(unmatched),
        "residual_formal_heading": bool(residual),
        "body_token_change": not token_conserved,
        "outline_incomplete": outline_coverage < 1.0 or bool(unexpected_outline),
        "toc_missing": require_toc and not toc_present,
    }
    score_passed = f1 >= threshold
    passed = score_passed and not any(blockers.values())
    return {
        "schema": "latexstruct-tex-structure-accuracy-report-v1",
        "passed": passed,
        "threshold": threshold,
        "score_passed": score_passed,
        "inputs": {
            "original_sha256": _sha256_text(original),
            "candidate_sha256": _sha256_text(candidate),
            "truth_mode": "manifest" if manifest is not None else "auto-discovery",
        },
        "exact_structure": {
            "true_positive": true_positive,
            "predicted": predicted_count,
            "expected": expected_count,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "matches": exact_matches,
            "missing": missing,
            "duplicates": duplicates,
            "boundary_errors": boundary_errors,
            "unmatched_environments": unmatched,
        },
        "residual_formal_headings": residual,
        "body_token_conservation": {
            "conserved": token_conserved,
            "original_token_count": len(original_tokens),
            "candidate_token_count": len(candidate_tokens),
            "missing_token_count": missing_token_count,
            "excess_token_count": excess_token_count,
            "first_difference_index": _first_difference(original_tokens, candidate_tokens),
            "missing_original_lines": missing_lines,
            "excess_candidate_lines": excess_lines,
        },
        "document_structure": {
            "toc_required": require_toc,
            "toc_present": toc_present,
            "expected_outline_nodes": outline_total,
            "candidate_outline_nodes": sum(candidate_outline_counts.values()),
            "matched_outline_nodes": outline_matched,
            "outline_coverage": outline_coverage,
            "missing_outline_nodes": missing_outline,
            "unexpected_outline_nodes": unexpected_outline,
        },
        "blockers": blockers,
    }


def _load_manifest(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("truth manifest must be a JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path, help="original LaTeX file")
    parser.add_argument("candidate", type=Path, help="structured candidate LaTeX file")
    parser.add_argument("--truth", type=Path, help="reviewed JSON truth manifest")
    parser.add_argument("--threshold", type=float, default=0.95)
    parser.add_argument("--no-require-toc", action="store_true")
    parser.add_argument("--json-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = evaluate_tex_structure(
        args.original.read_text(encoding="utf-8"),
        args.candidate.read_text(encoding="utf-8"),
        manifest=_load_manifest(args.truth),
        threshold=args.threshold,
        require_toc=not args.no_require_toc,
    )
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
