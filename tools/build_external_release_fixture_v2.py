#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the sealed, independent external release fixture v2.

The builder intentionally reads only the v2 provenance manifest, its frozen
source trees, and the current production parser/scanner/safety gate.  It never
opens an earlier fixture, prediction, score, or error-analysis file.

The public packet contains source context and a focus block, but no answer
fields.  Gold and validation are written separately under
``../work/external-results-v2``.  A deterministic v3-sized reserve is proved in
memory and is deliberately not serialized, so those contexts remain unspent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import preflight_external_corpus_v2 as preflight  # noqa: E402
from apply_external_safety_gate import (  # noqa: E402
    apply_safety_gate as production_apply_safety_gate,
)
from latexstruct.core.legalize import (  # noqa: E402
    _atomic_end,
    _proof_end_line,
    _reliable_stop_lines,
    has_proof_end_marker,
)
from latexstruct.core.ai import ALLOWED_WRAP_ENVS  # noqa: E402
from latexstruct.core.invariants import (  # noqa: E402
    GRAPHICSPATH_RE,
    check_image_resources,
    image_paths,
)
from latexstruct.core.parser import offset_to_line, parse_latex  # noqa: E402
from latexstruct.core.patch import AMSTHM_BLOCK, NEW_THEOREM_RE  # noqa: E402


SCHEMA = "latexstruct-external-release-fixture-v2"
V3_SCHEMA = "latexstruct-external-release-fixture-v3"
SEED = "latexstruct-release-v2-2026-08-19-sealed-01"
TARGETS = {"auto": 300, "preserve": 300, "manual": 120}
REGIONS = ("front", "middle", "back")
LANES = ("auto", "preserve", "manual")
MAX_BODY_CHARS = 8_000
MAX_BODY_ATOMS = 12
MAX_BODY_LINES = 240
MAX_PRESERVE_CHARS = 6_000
FIVE_GRAM_SIMILARITY_LIMIT = 0.82
SYNTHETIC_SCOPE_MARKER = (
    "% LaTeXStruct OCR provenance: body was left outside the environment."
)
SCOPE_FIX_PER_DOCUMENT = 4
V2_VALIDATION_SHA256 = (
    "6312a79a690024a4fac04390c7614a40574853af3f8c007b08b40dc3f0546836"
)
# The v3 reserve was selected and proved during the sealed v2 build.  Its
# legacy identity digest is intentionally kept compatible with that original
# audit: ordered tuples of ID/label/source interval/normalized context hash.
V3_RESERVE_IDENTITY_SHA256 = (
    "c42d48ab5dbf227237ee51e0945bf89dd2a210528176b6b067306ae2d9e9c18c"
)
# A stronger materialization digest freezes the same units' environment,
# boundaries, known environments, source/body/display hashes, and gold
# four-tuples.  Neither digest may be repaired by selecting replacement units.
V3_RESERVE_MATERIALIZATION_SHA256 = (
    "4ce2434374d01440b30884ad240234df5e362c2a4bbfcacae525b9916eba01af"
)
V3_FROZEN_SCOPE_FIX_COUNTS = {
    "V2B01": 53,
    "V2B02": 46,
    "V2B03": 0,
    "V2P01": 3,
    "V2P02": 7,
    "V2P03": 7,
}

TITLE_BY_ENV = {
    "theorem": "Theorem.",
    "lemma": "Lemma.",
    "definition": "Definition.",
    "proposition": "Proposition.",
    "corollary": "Corollary.",
    "remark": "Remark.",
    "example": "Example.",
    "proof": "Proof.",
}

# These are *packet key names*, not values.  A blind packet may explain the
# response contract outside the JSON, but may not carry its own answer.
FORBIDDEN_PACKET_KEYS = frozenset(
    {
        "action",
        "env",
        "start_block",
        "end_block",
        "gold",
        "expected",
        "label",
        "lane",
        "evidence",
        "canonical_env",
        "raw_env",
        "body_sha256",
        "source_sha256",
    }
)

_TOKEN_RE = re.compile(r"\\[A-Za-z@]+|[\w]+|[^\s]", re.UNICODE)
_BLANK_RUN_RE = re.compile(r"\n(?:[ \t]*(?:%[^\n]*)?\n)+")
_STRUCTURAL_PRESERVE_START_RE = re.compile(
    r"^\s*\\(?:part|chapter|section|subsection|subsubsection|paragraph|"
    r"begin|end|bibliography|printbibliography|maketitle|tableofcontents)\b"
)
_XREF_RE = re.compile(
    r"\\(?:[Cc]ref|ref|autoref|eqref|pageref|cite\w*)\b"
    r"|\b(?:Theorem|Lemma|Definition|Proposition|Corollary|Remark|Example|Proof)\b"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _normalized_context(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def _five_grams(text: str) -> frozenset[str]:
    tokens = _TOKEN_RE.findall(_normalized_context(text))
    if not tokens:
        return frozenset()
    width = min(5, len(tokens))
    return frozenset("\x1f".join(tokens[index : index + width]) for index in range(len(tokens) - width + 1))


def _gram_set_sha256(grams: Iterable[str]) -> str:
    payload = "\n".join(sorted(grams))
    return _sha256_text(payload)


def _display_context(blocks: Sequence[str]) -> str:
    return "\n\n".join(
        f"<<<BLOCK {index}>>>\n{text.strip()}" for index, text in enumerate(blocks)
    )


def _region(position: int, total: int) -> str:
    if total <= 0:
        return "front"
    ratio = position / total
    if ratio < 1 / 3:
        return "front"
    if ratio < 2 / 3:
        return "middle"
    return "back"


def _line_end_offset(text: str, offset: int) -> int:
    newline = text.find("\n", offset)
    return len(text) if newline < 0 else newline


def _protected_atomic_chunks(body: str) -> list[str]:
    """Split visible paragraph atoms without cutting nested TeX/math environments."""

    body_doc = parse_latex(body)
    protected = [(item[1], item[4]) for item in body_doc.env_ranges]
    protected.extend(body_doc.display_spans)
    cuts: list[tuple[int, int]] = []
    for match in _BLANK_RUN_RE.finditer(body):
        midpoint = match.start() + max(0, (match.end() - match.start()) // 2)
        if any(left < midpoint < right for left, right in protected):
            continue
        cuts.append((match.start(), match.end()))
    chunks: list[str] = []
    cursor = 0
    for left, right in cuts:
        piece = body[cursor:left].strip()
        if piece:
            chunks.append(piece)
        cursor = right
    tail = body[cursor:].strip()
    if tail:
        chunks.append(tail)
    return chunks


def _marker_closer_fact(atom: str) -> bool:
    """Use the production marker/atomic helpers to identify a closer after QED."""

    doc = parse_latex(atom)
    lines = doc.masked.split("\n")
    for line_no, active in enumerate(lines, start=1):
        if not has_proof_end_marker(active):
            continue
        return _atomic_end(doc, line_no, wrap_start=1) > line_no
    return False


def _optional_argument(text: str, begin_end: int, body_end: int) -> tuple[str, int]:
    """Return an environment's optional title and the semantic body start.

    ``find_env_ranges`` ends the opening token immediately after ``}``; the
    standard ``[title]`` therefore belongs to its raw interior.  This small
    balanced scanner preserves that title in the OCR-style bare heading instead
    of accidentally treating it as theorem body.
    """

    cursor = begin_end
    while cursor < body_end and text[cursor].isspace():
        cursor += 1
    if cursor >= body_end or text[cursor] != "[":
        return "", begin_end
    depth = 0
    escaped = False
    for index in range(cursor, body_end):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[cursor + 1 : index].strip(), index + 1
    return "", begin_end


def _bare_title(canonical_env: str, optional_title: str, unit_id: str) -> str:
    base = TITLE_BY_ENV[canonical_env].rstrip(".")
    title = optional_title.strip()
    if not title:
        return f"{base}."
    punctuation = ":" if int(_sha256_text(unit_id)[-1], 16) % 2 else "."
    if canonical_env == "proof":
        if title.casefold().startswith(("proof", "sketch of the proof")):
            return title.rstrip(".:：。") + punctuation
        return f"Proof [{title}]{punctuation}"
    return f"{base} ({title}){punctuation}"


def _packet_id(
    document: str,
    file_name: str,
    start: int,
    end: int,
    variant: str,
) -> str:
    digest = _sha256_text(
        f"{SEED}\0{document}\0{file_name}\0{start}\0{end}\0{variant}"
    )
    return f"V2U-{digest[:20]}"


@dataclass(frozen=True)
class SourceTarget:
    raw_env: str
    canonical_env: str
    begin_start: int
    begin_end: int
    end_start: int
    end_end: int
    start_line: int
    end_line: int


@dataclass(frozen=True)
class UnitCandidate:
    unit_id: str
    document: str
    document_kind: str
    document_title: str
    source_file: str
    region: str
    lane: str
    subtype: str
    canonical_env: str
    source_start: int
    source_end: int
    target_start: int
    target_end: int
    source_start_line: int
    source_end_line: int
    original_context: str
    original_source: str
    original_body: str
    blocks: tuple[str, ...]
    focus_block: int
    answer_end_block: int
    manual_probe_end_block: int
    known_structured_envs: tuple[str, ...]
    qed_followed_by_math_closer: bool = False

    @property
    def file_key(self) -> tuple[str, str]:
        return self.document, self.source_file

    @property
    def display(self) -> str:
        return _display_context(self.blocks)

    @property
    def normalized_hash(self) -> str:
        return _sha256_text(_normalized_context(self.display))

    @property
    def grams(self) -> frozenset[str]:
        return _five_grams(self.display)


def _targets_for_document(doc, env_map: dict[str, str]) -> list[SourceTarget]:
    result: list[SourceTarget] = []
    for raw_env, begin_start, begin_end, end_start, end_end in doc.env_ranges:
        canonical = env_map.get(raw_env)
        if canonical is None:
            continue
        result.append(
            SourceTarget(
                raw_env=raw_env,
                canonical_env=canonical,
                begin_start=begin_start,
                begin_end=begin_end,
                end_start=end_start,
                end_end=end_end,
                start_line=offset_to_line(doc.line_starts, begin_start),
                end_line=offset_to_line(doc.line_starts, max(begin_start, end_end - 1)),
            )
        )
    return sorted(result, key=lambda item: (item.begin_start, -item.end_end))


def _explicit_successor(
    text: str,
    doc,
    target: SourceTarget,
    targets_by_start: dict[int, SourceTarget],
) -> tuple[str, int] | None:
    cursor = preflight._skip_comments_and_blank(text, target.end_end)
    next_target = targets_by_start.get(cursor)
    if next_target is not None:
        # Keep the successor exactly as published.  The packet separately lists
        # the document's known structured environments, which is the same
        # external context accepted by production scan/legalize.
        return text[next_target.begin_start : next_target.end_end].strip(), next_target.end_end
    section = next(
        (item for item in doc.sections if item.span.start_off == cursor),
        None,
    )
    if section is not None:
        end = max(section.span.end_off, _line_end_offset(text, cursor))
        return text[cursor:end].strip(), end
    return None


def _source_files(source: dict, corpus_root: Path) -> list[tuple[Path, str, str]]:
    root = corpus_root / PurePosixPath(source["local_root"])
    files = preflight._resolve_tex_scope(root, source["tex_globs"])
    decoded: list[tuple[Path, str, str]] = []
    for path in files:
        _raw, text, encoding = preflight._decode_source(path)
        decoded.append((path, text, encoding))
    return decoded


def _make_packet_blocks(
    canonical_env: str,
    bare_title: str,
    atoms: Sequence[str],
    successor: tuple[str, int] | None,
) -> tuple[tuple[str, ...], int]:
    if not atoms:
        return (), -1
    first = f"{bare_title}\n{atoms[0].strip()}".strip()
    blocks = [first, *(item.strip() for item in atoms[1:] if item.strip())]
    answer_end = len(blocks) - 1
    if successor is not None:
        blocks.append(successor[0])
    return tuple(blocks), answer_end


def _single_plain_atom(atom: str) -> bool:
    doc = parse_latex(atom)
    blocks = [
        block
        for block in doc.blocks
        if block.kind in {"para", "env", "displaymath"}
        and not block.in_env
        and not (block.kind == "env" and block.name == "document")
    ]
    return (
        len(blocks) == 1
        and blocks[0].kind == "para"
        and blocks[0].text.strip() == atom.strip()
    )


def _append_scope_marker(atom: str) -> str:
    lines = atom.strip().split("\n")
    for index, line in enumerate(lines):
        if line.strip() and not line.lstrip().startswith("%"):
            # Preserve authentic trailing whitespace so removing the synthetic
            # audit comment reconstructs the real source-body atom byte-for-byte.
            lines[index] = line + " " + SYNTHETIC_SCOPE_MARKER
            return "\n".join(lines)
    raise ValueError("scope-fix body has no visible source line")


def _scope_candidate_from_environment(
    *,
    source: dict,
    relative: str,
    text: str,
    base_position: int,
    document_total: int,
    target: SourceTarget,
    all_targets: Sequence[SourceTarget],
) -> UnitCandidate | None:
    if target.canonical_env == "proof":
        return None
    optional_title, body_start = _optional_argument(
        text, target.begin_end, target.end_start
    )
    # The only-title scope signal is deliberately canonical and unambiguous.
    # Named-title environments remain in the normal wrap/preserve pools, where
    # their authentic parenthesized/bracketed OCR forms exercise the scanner.
    if optional_title:
        return None
    body = text[body_start : target.end_start]
    atoms = _protected_atomic_chunks(body)
    if len(atoms) != 1 or not _single_plain_atom(atoms[0]):
        return None
    if any(
        other.begin_start > target.begin_start and other.end_end < target.end_end
        for other in all_targets
    ):
        return None
    original = text[target.begin_start : target.end_end]
    if len(original) > MAX_BODY_CHARS or original.count("\n") + 1 > MAX_BODY_LINES:
        return None
    unit_id = _packet_id(
        source["id"], relative, target.begin_start, target.end_end, "scope-fix"
    )
    env = target.canonical_env
    malformed = f"\\begin{{{env}}}\n{TITLE_BY_ENV[env]}\n\\end{{{env}}}"
    marked_body = _append_scope_marker(atoms[0])
    known = tuple(sorted(source["inventory"]["environment_map"].keys()))
    return UnitCandidate(
        unit_id=unit_id,
        document=source["id"],
        document_kind=source["kind"],
        document_title=source["title"],
        source_file=relative,
        region=_region(base_position + target.begin_start, document_total),
        lane="auto",
        subtype="scope-fix-synthetic-boundary-marker-real-body",
        canonical_env=env,
        source_start=target.begin_start,
        source_end=target.end_end,
        target_start=target.begin_start,
        target_end=target.end_end,
        source_start_line=target.start_line,
        source_end_line=target.end_line,
        original_context=original,
        original_source=original,
        original_body=body,
        blocks=(malformed, marked_body),
        focus_block=0,
        answer_end_block=1,
        manual_probe_end_block=1,
        known_structured_envs=known,
    )


def _candidate_from_environment(
    *,
    source: dict,
    relative: str,
    text: str,
    doc,
    base_position: int,
    document_total: int,
    target: SourceTarget,
    all_targets: Sequence[SourceTarget],
    targets_by_start: dict[int, SourceTarget],
    lane: str,
) -> UnitCandidate | None:
    optional_title, body_start = _optional_argument(
        text, target.begin_end, target.end_start
    )
    body = text[body_start : target.end_start]
    original = text[target.begin_start : target.end_end]
    if not body.strip() or target.canonical_env not in TITLE_BY_ENV:
        return None
    known = tuple(sorted(source["inventory"]["environment_map"].keys()))
    unit_id = _packet_id(
        source["id"], relative, target.begin_start, target.end_end, lane
    )
    region = _region(base_position + target.begin_start, document_total)

    if lane == "preserve":
        if len(original) > MAX_BODY_CHARS or original.count("\n") + 1 > MAX_BODY_LINES:
            return None
        return UnitCandidate(
            unit_id=unit_id,
            document=source["id"],
            document_kind=source["kind"],
            document_title=source["title"],
            source_file=relative,
            region=region,
            lane="preserve",
            subtype="structured-environment",
            canonical_env=target.canonical_env,
            source_start=target.begin_start,
            source_end=target.end_end,
            target_start=target.begin_start,
            target_end=target.end_end,
            source_start_line=target.start_line,
            source_end_line=target.end_line,
            original_context=original,
            original_source=original,
            original_body=body,
            blocks=(original.strip(),),
            focus_block=0,
            answer_end_block=0,
            manual_probe_end_block=0,
            known_structured_envs=known,
        )

    atoms = _protected_atomic_chunks(body)
    if not atoms:
        return None
    nested = any(
        other.begin_start > target.begin_start and other.end_end < target.end_end
        for other in all_targets
    )
    too_long = (
        len(body) > MAX_BODY_CHARS
        or len(atoms) > MAX_BODY_ATOMS
        or body.count("\n") + 1 > MAX_BODY_LINES
    )
    successor = _explicit_successor(text, doc, target, targets_by_start)
    masked_body = parse_latex(body).masked
    masked_atoms = _protected_atomic_chunks(masked_body)
    final_masked_atom = masked_atoms[-1] if masked_atoms else ""
    body_doc = parse_latex(masked_body)
    internal_stop_lines = _reliable_stop_lines(body_doc, known)
    body_lines = body_doc.masked.split("\n")
    last_body_line = len(body_lines)
    while last_body_line > 0 and not body_lines[last_body_line - 1].strip():
        last_body_line -= 1
    final_body_atomic_end = (
        _atomic_end(body_doc, last_body_line, wrap_start=1)
        if last_body_line
        else 0
    )
    first_marker_end = (
        _proof_end_line(body_doc, 1, max(1, len(body_lines)))
        if target.canonical_env == "proof"
        else None
    )
    final_hard_marker = bool(
        target.canonical_env == "proof"
        and first_marker_end is not None
        and first_marker_end == final_body_atomic_end
        and has_proof_end_marker(final_masked_atom)
    )
    plain_single = len(atoms) == 1 and _single_plain_atom(atoms[0])

    if nested or internal_stop_lines:
        disposition, subtype = "manual", "nested-mapped-structure"
    elif too_long:
        disposition, subtype = "manual", "long-or-many-atomic-blocks"
    elif target.canonical_env == "proof":
        if final_hard_marker:
            disposition, subtype = "auto", "proof-hard-end-marker"
        elif first_marker_end is not None:
            disposition, subtype = "manual", "proof-nonfinal-marker-boundary-conflict"
        elif successor is not None:
            disposition, subtype = "auto", "proof-explicit-structural-successor"
        else:
            disposition, subtype = "manual", "proof-no-machine-verifiable-end"
    elif plain_single:
        disposition, subtype = (
            "auto",
            "single-atomic-named-title" if optional_title else "single-atomic-statement",
        )
    elif successor is not None:
        disposition, subtype = "auto", "multi-atomic-explicit-structural-successor"
    else:
        disposition, subtype = "manual", "multi-atomic-no-reliable-stop"

    if disposition != lane:
        return None
    # A hard marker is independently sufficient.  Do not append a successor in
    # that case: the test then proves the marker/atomic-closer behavior itself.
    rendered_successor = None if final_hard_marker else successor
    blocks, answer_end = _make_packet_blocks(
        target.canonical_env,
        _bare_title(target.canonical_env, optional_title, unit_id),
        atoms,
        rendered_successor,
    )
    if not blocks:
        return None
    source_end = (
        rendered_successor[1] if rendered_successor is not None else target.end_end
    )
    return UnitCandidate(
        unit_id=unit_id,
        document=source["id"],
        document_kind=source["kind"],
        document_title=source["title"],
        source_file=relative,
        region=region,
        lane=lane,
        subtype=subtype,
        canonical_env=target.canonical_env,
        source_start=target.begin_start,
        source_end=source_end,
        target_start=target.begin_start,
        target_end=target.end_end,
        source_start_line=target.start_line,
        source_end_line=target.end_line,
        original_context=text[target.begin_start:source_end],
        original_source=original,
        original_body=body,
        blocks=blocks,
        focus_block=0,
        answer_end_block=answer_end,
        manual_probe_end_block=answer_end,
        known_structured_envs=known,
        qed_followed_by_math_closer=(
            final_hard_marker and _marker_closer_fact(atoms[-1])
        ),
    )


def _candidate_from_paragraph(
    *,
    source: dict,
    relative: str,
    text: str,
    base_position: int,
    document_total: int,
    block,
) -> UnitCandidate | None:
    visible = block.text.strip()
    if block.in_env or len(visible) < 50 or len(visible) > MAX_PRESERVE_CHARS:
        return None
    if "\\begin{" in visible or "\\end{" in visible:
        return None
    if _STRUCTURAL_PRESERVE_START_RE.match(visible):
        return None
    if visible.startswith(("%", "\\[", "$$", "\\item", "\\label")):
        return None
    unit_id = _packet_id(
        source["id"],
        relative,
        block.span.start_off,
        block.span.end_off,
        "preserve-paragraph",
    )
    subtype = "cross-reference" if _XREF_RE.search(visible) else "narrative"
    known = tuple(sorted(source["inventory"]["environment_map"].keys()))
    return UnitCandidate(
        unit_id=unit_id,
        document=source["id"],
        document_kind=source["kind"],
        document_title=source["title"],
        source_file=relative,
        region=_region(base_position + block.span.start_off, document_total),
        lane="preserve",
        subtype=subtype,
        canonical_env="",
        source_start=block.span.start_off,
        source_end=block.span.end_off,
        target_start=block.span.start_off,
        target_end=block.span.end_off,
        source_start_line=block.span.start_line,
        source_end_line=block.span.end_line,
        original_context=text[block.span.start_off : block.span.end_off],
        original_source=text[block.span.start_off : block.span.end_off],
        original_body=text[block.span.start_off : block.span.end_off],
        blocks=(visible,),
        focus_block=0,
        answer_end_block=0,
        manual_probe_end_block=0,
        known_structured_envs=known,
    )


def _packet_unit(candidate: UnitCandidate) -> dict:
    blocks = [
        {"id": index, "text": value.strip()}
        for index, value in enumerate(candidate.blocks)
    ]
    result = {
        "id": candidate.unit_id,
        "document_id": candidate.document,
        "document_kind": candidate.document_kind,
        "document_title": candidate.document_title,
        "source_file": candidate.source_file,
        "region": candidate.region,
        "focus_anchor": candidate.focus_block,
        "known_structured_environments": list(candidate.known_structured_envs),
        "blocks": blocks,
    }
    if candidate.subtype == "scope-fix-synthetic-boundary-marker-real-body":
        result["context_annotations"] = [
            {
                "kind": "synthetic-ocr-provenance-comment",
                "text": SYNTHETIC_SCOPE_MARKER,
                "semantic_content_added": False,
                "note": (
                    "This audited fixture-only comment is not part of the published source "
                    "body and is not itself an answer field."
                ),
            }
        ]
    result["context_sha256"] = _sha256_text(_display_context(candidate.blocks))
    return result


def _gold(candidate: UnitCandidate) -> dict:
    if candidate.subtype == "scope-fix-synthetic-boundary-marker-real-body":
        action = "move-boundary"
    else:
        action = "wrap" if candidate.lane == "auto" else candidate.lane
    env = candidate.canonical_env if action in {"wrap", "move-boundary"} else ""
    end = (
        candidate.answer_end_block
        if action in {"wrap", "move-boundary"}
        else candidate.focus_block
    )
    return {
        "id": candidate.unit_id,
        "document": candidate.document,
        "action": action,
        "env": env,
        "start_block": candidate.focus_block,
        "end_block": end,
        "source_file": candidate.source_file,
        "source_start_offset": candidate.target_start,
        "source_end_offset": candidate.target_end,
        "source_start_line": candidate.source_start_line,
        "source_end_line": candidate.source_end_line,
        "source_sha256": _sha256_text(candidate.original_source),
        "body_sha256": _sha256_text(candidate.original_body),
        "context_sha256": _sha256_text(candidate.display),
        "region": candidate.region,
        "fixture_subtype": candidate.subtype,
    }


def _walk_keys(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


class SelectionState:
    def __init__(self, initial: Sequence[UnitCandidate] = ()) -> None:
        self.selected: list[UnitCandidate] = []
        self._intervals: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
        self._normalized_hashes: set[str] = set()
        self._grams: list[frozenset[str]] = []
        self._gram_index: dict[str, set[int]] = defaultdict(set)
        for candidate in initial:
            if not self.add(candidate):
                raise ValueError("initial selection is internally overlapping or duplicated")

    def _overlaps(self, candidate: UnitCandidate) -> bool:
        intervals = self._intervals[candidate.file_key]
        probe = (candidate.source_start, candidate.source_end)
        index = bisect_left(intervals, probe)
        neighbors = intervals[max(0, index - 1) : index + 1]
        return any(
            candidate.source_start < right and left < candidate.source_end
            for left, right in neighbors
        )

    def similarity(self, candidate: UnitCandidate) -> tuple[float, int | None]:
        grams = candidate.grams
        possible: set[int] = set()
        for gram in grams:
            possible.update(self._gram_index.get(gram, ()))
        best = 0.0
        nearest: int | None = None
        for index in possible:
            other = self._grams[index]
            union = len(grams | other)
            score = len(grams & other) / union if union else 1.0
            if score > best:
                best, nearest = score, index
        return best, nearest

    def can_add(self, candidate: UnitCandidate) -> bool:
        if self._overlaps(candidate):
            return False
        if candidate.normalized_hash in self._normalized_hashes:
            return False
        similarity, _nearest = self.similarity(candidate)
        return similarity < FIVE_GRAM_SIMILARITY_LIMIT

    def add(self, candidate: UnitCandidate) -> bool:
        if not self.can_add(candidate):
            return False
        intervals = self._intervals[candidate.file_key]
        intervals.insert(
            bisect_left(intervals, (candidate.source_start, candidate.source_end)),
            (candidate.source_start, candidate.source_end),
        )
        index = len(self.selected)
        grams = candidate.grams
        self.selected.append(candidate)
        self._normalized_hashes.add(candidate.normalized_hash)
        self._grams.append(grams)
        for gram in grams:
            self._gram_index[gram].add(index)
        return True


def _priority(candidate: UnitCandidate, phase: str) -> str:
    return _sha256_text(f"{SEED}\0{phase}\0{candidate.lane}\0{candidate.unit_id}")


def _select_lane(
    pool: Sequence[UnitCandidate],
    state: SelectionState,
    *,
    lane: str,
    count: int,
    phase: str,
    require_coverage: bool,
) -> list[UnitCandidate]:
    before = len(state.selected)
    lane_pool = [item for item in pool if item.lane == lane]

    if phase == "v2" and lane == "auto":
        for document in sorted({item.document for item in pool}):
            scope_pool = sorted(
                (
                    item
                    for item in lane_pool
                    if item.document == document
                    and item.subtype
                    == "scope-fix-synthetic-boundary-marker-real-body"
                ),
                key=lambda item: _priority(item, f"{phase}-scope-{document}"),
            )
            added = 0
            for item in scope_pool:
                if state.add(item):
                    added += 1
                    if added == SCOPE_FIX_PER_DOCUMENT:
                        break
            if added != SCOPE_FIX_PER_DOCUMENT:
                raise ValueError(
                    f"cannot select {SCOPE_FIX_PER_DOCUMENT} scope fixes for {document}"
                )

    if require_coverage:
        for document in sorted({item.document for item in pool}):
            for region in REGIONS:
                bucket = sorted(
                    (
                        item
                        for item in lane_pool
                        if item.document == document and item.region == region
                        and not (
                            phase == "v2"
                            and lane == "auto"
                            and item.subtype
                            == "scope-fix-synthetic-boundary-marker-real-body"
                        )
                    ),
                    key=lambda item: (
                        item.subtype
                        == "scope-fix-synthetic-boundary-marker-real-body",
                        _priority(item, f"{phase}-anchor-{document}-{region}"),
                    ),
                )
                if not any(state.add(item) for item in bucket):
                    raise ValueError(
                        f"cannot cover {lane} {document} {region} without overlap/duplication"
                    )

    if lane == "auto" and not any(
        item.qed_followed_by_math_closer for item in state.selected[before:]
    ):
        closer_pool = sorted(
            (item for item in lane_pool if item.qed_followed_by_math_closer),
            key=lambda item: _priority(item, f"{phase}-qed-math-closer"),
        )
        if not any(state.add(item) for item in closer_pool):
            raise ValueError("no selectable proof with QED followed by a math closer")

    desired_total = before + count
    queues: dict[str, list[UnitCandidate]] = {}
    fill_pool = lane_pool
    if phase == "v2" and lane == "auto":
        fill_pool = [
            item
            for item in lane_pool
            if item.subtype != "scope-fix-synthetic-boundary-marker-real-body"
        ]
    for document in sorted({item.document for item in fill_pool}):
        queues[document] = sorted(
            (item for item in fill_pool if item.document == document),
            key=lambda item: _priority(item, f"{phase}-fill"),
        )
    cursors = {document: 0 for document in queues}
    while len(state.selected) < desired_total:
        progress = False
        for document in sorted(queues):
            queue = queues[document]
            while cursors[document] < len(queue):
                item = queue[cursors[document]]
                cursors[document] += 1
                if state.add(item):
                    progress = True
                    break
            if len(state.selected) >= desired_total:
                break
        if not progress:
            selected_count = len(state.selected) - before
            raise ValueError(
                f"cannot select {count} {lane} items for {phase}; got {selected_count}"
            )
    return state.selected[before:desired_total]


def _collect_candidates(manifest: dict, corpus_root: Path) -> list[UnitCandidate]:
    candidates: list[UnitCandidate] = []
    for source in manifest["sources"]:
        decoded = _source_files(source, corpus_root)
        document_total = sum(len(text) + 1 for _path, text, _encoding in decoded)
        base_position = 0
        root = corpus_root / PurePosixPath(source["local_root"])
        env_map = dict(source["inventory"]["environment_map"])
        for path, text, _encoding in decoded:
            relative = path.relative_to(root).as_posix()
            doc = parse_latex(text)
            targets = _targets_for_document(doc, env_map)
            targets_by_start = {item.begin_start: item for item in targets}
            for target in targets:
                scope_item = _scope_candidate_from_environment(
                    source=source,
                    relative=relative,
                    text=text,
                    base_position=base_position,
                    document_total=document_total,
                    target=target,
                    all_targets=targets,
                )
                if scope_item is not None:
                    candidates.append(scope_item)
                for lane in LANES:
                    item = _candidate_from_environment(
                        source=source,
                        relative=relative,
                        text=text,
                        doc=doc,
                        base_position=base_position,
                        document_total=document_total,
                        target=target,
                        all_targets=targets,
                        targets_by_start=targets_by_start,
                        lane=lane,
                    )
                    if item is None:
                        continue
                    candidates.append(item)

            preamble_end = doc.preamble_span.end_line if doc.preamble_span else 0
            for block in doc.blocks_of_kind("para"):
                if block.span.start_line <= preamble_end:
                    continue
                item = _candidate_from_paragraph(
                    source=source,
                    relative=relative,
                    text=text,
                    base_position=base_position,
                    document_total=document_total,
                    block=block,
                )
                if item is None:
                    continue
                candidates.append(item)
            base_position += len(text) + 1
    return candidates


def _validate_source_hashes(
    selected: Sequence[UnitCandidate], manifest: dict, corpus_root: Path
) -> int:
    source_lookup: dict[tuple[str, str], str] = {}
    for source in manifest["sources"]:
        root = corpus_root / PurePosixPath(source["local_root"])
        for path, text, _encoding in _source_files(source, corpus_root):
            source_lookup[(source["id"], path.relative_to(root).as_posix())] = text
    checked = 0
    for item in selected:
        text = source_lookup[item.file_key]
        original = text[item.target_start : item.target_end]
        if original != item.original_source:
            raise ValueError(f"{item.unit_id}: source slice changed during fixture construction")
        context = text[item.source_start : item.source_end]
        if context != item.original_context:
            raise ValueError(f"{item.unit_id}: displayed source context slice changed")
        if item.original_body not in item.original_source:
            raise ValueError(f"{item.unit_id}: body is not a source substring")
        checked += 1
    return checked


def _source_lookup(
    manifest: dict, corpus_root: Path
) -> dict[tuple[str, str], tuple[str, Path, Path]]:
    result: dict[tuple[str, str], tuple[str, Path, Path]] = {}
    for source in manifest["sources"]:
        root = corpus_root / PurePosixPath(source["local_root"])
        for path, text, _encoding in _source_files(source, corpus_root):
            relative = path.relative_to(root).as_posix()
            result[(source["id"], relative)] = (text, path, root)
    return result


def _scope_body_unchanged(item: UnitCandidate) -> bool:
    if item.subtype != "scope-fix-synthetic-boundary-marker-real-body":
        return True
    displayed = item.blocks[1]
    if displayed.count(SYNTHETIC_SCOPE_MARKER) != 1:
        return False
    restored = displayed.replace(" " + SYNTHETIC_SCOPE_MARKER, "", 1).strip()
    atoms = _protected_atomic_chunks(item.original_body)
    return (
        len(atoms) == 1
        and restored == atoms[0].strip()
        and SYNTHETIC_SCOPE_MARKER not in item.original_body
    )


def _resource_check_for_item(
    item: UnitCandidate,
    source_lookup: dict[tuple[str, str], tuple[str, Path, Path]],
) -> dict:
    references = image_paths(item.original_context)
    if not references:
        return {
            "id": item.unit_id,
            "reference_count": 0,
            "resolved": True,
            "method": "production image_paths scan returned zero references",
        }
    full_text, path, root = source_lookup[item.file_key]
    graphicspaths = "\n".join(
        match.group(0) for match in GRAPHICSPATH_RE.finditer(full_text)
    )
    probe = graphicspaths + "\n" + item.original_context
    attempts: list[dict] = []
    for base in dict.fromkeys((path.parent.resolve(), root.resolve())):
        result = check_image_resources(probe, str(base))
        attempts.append({"base": str(base), **result})
        if result.get("checked") and result.get("ok"):
            return {
                "id": item.unit_id,
                "reference_count": len(references),
                "references": references,
                "resolved": True,
                "method": "production check_image_resources",
                "successful_base": str(base),
                "attempts": attempts,
            }
    return {
        "id": item.unit_id,
        "reference_count": len(references),
        "references": references,
        "resolved": False,
        "method": "production check_image_resources",
        "attempts": attempts,
    }


def _document_checks(
    selected: Sequence[UnitCandidate],
    manifest: dict,
    corpus_root: Path,
    gate_audit: dict,
) -> list[dict]:
    source_lookup = _source_lookup(manifest, corpus_root)
    gate_by_document = {
        item["document"]: item for item in gate_audit["document_verification"]
    }
    declared = {
        match.group(2).strip()
        for match in NEW_THEOREM_RE.finditer("\n".join(AMSTHM_BLOCK))
    }
    if any("\\usepackage{amsthm}" in line for line in AMSTHM_BLOCK):
        declared.add("proof")
    checks: list[dict] = []
    for document in sorted({item.document for item in selected}):
        items = [item for item in selected if item.document == document]
        gate = gate_by_document.get(document)
        if gate is None:
            raise ValueError(f"missing production gate document verification: {document}")

        reopened = 0
        for item in items:
            text, _path, _root = source_lookup[item.file_key]
            if text[item.target_start : item.target_end] != item.original_source:
                raise ValueError(f"{item.unit_id}: reopened source hash mismatch")
            if text[item.source_start : item.source_end] != item.original_context:
                raise ValueError(f"{item.unit_id}: reopened context hash mismatch")
            if item.original_body not in item.original_source:
                raise ValueError(f"{item.unit_id}: reopened body is not source content")
            reopened += 1

        scope_items = [
            item
            for item in items
            if item.subtype == "scope-fix-synthetic-boundary-marker-real-body"
        ]
        scope_unchanged = all(_scope_body_unchanged(item) for item in scope_items)
        if not scope_unchanged:
            raise ValueError(f"{document}: synthetic scope marker changed real body")

        resource_items = [
            _resource_check_for_item(item, source_lookup) for item in items
        ]
        resource_reference_count = sum(
            item["reference_count"] for item in resource_items
        )
        resources_complete = all(item["resolved"] for item in resource_items)
        if not resources_complete:
            failures = [item for item in resource_items if not item["resolved"]]
            raise ValueError(f"{document}: unresolved selected resources: {failures[:3]}")

        output_envs = sorted(
            {item.canonical_env for item in items if item.lane == "auto"}
        )
        declaration_sources = {
            env: (
                "latexstruct.core.patch.AMSTHM_BLOCK (amsthm proof environment)"
                if env == "proof"
                else "latexstruct.core.patch.AMSTHM_BLOCK (newtheorem declaration)"
            )
            for env in output_envs
        }
        known_context_envs = sorted(
            {name for item in items for name in item.known_structured_envs}
        )
        environments_declared = bool(
            set(output_envs) <= declared
            and set(output_envs) <= ALLOWED_WRAP_ENVS
            and gate["environments_supported"]
        )
        if not environments_declared:
            raise ValueError(
                f"{document}: production declaration evidence incomplete for {output_envs}"
            )

        standalone_fragments = sum(
            "\\documentclass" in item.display
            and "\\begin{document}" in item.display
            and "\\end{document}" in item.display
            for item in items
        )
        if standalone_fragments:
            raise ValueError(f"{document}: fixture unexpectedly contains standalone TeX")
        content_preserved = bool(
            reopened == len(items)
            and scope_unchanged
            and gate["content_preserved"]
            and gate["syntax_balanced"]
        )
        evidence = {
            "source_body_context_hashes_reopened": reopened,
            "production_gold_oracle": dict(gate),
            "scope_fix": {
                "count": len(scope_items),
                "classification": "synthetic-boundary-marker + real body",
                "marker": SYNTHETIC_SCOPE_MARKER,
                "real_body_hash_unchanged": scope_unchanged,
            },
            "resources": {
                "selected_fragment_count": len(items),
                "includegraphics_reference_count": resource_reference_count,
                "production_resolution_checks": resource_items,
            },
            "environments": {
                "automatic_output_environments": output_envs,
                "production_declaration_sources": declaration_sources,
                "known_structured_context_environments": known_context_envs,
                "gate_environments_supported": gate["environments_supported"],
            },
            "compile": {
                "reason": (
                    "Frozen units are isolated source fragments from multiple TeX "
                    "files and include OCR-derived contexts; none contains a complete "
                    "documentclass/document environment, so standalone compilation "
                    "is not a meaningful fixture-level check."
                ),
                "standalone_fragment_count": standalone_fragments,
                "compile_attempted": False,
            },
        }
        checks.append(
            {
                "document": document,
                "content_preserved": content_preserved,
                "resources_complete": resources_complete,
                "environments_declared": environments_declared,
                "compile_status": "not-required",
                "evidence": evidence,
                "evidence_sha256": _sha256_bytes(_json_bytes(evidence)),
            }
        )
    return checks


def _nonoverlap_check(items: Sequence[UnitCandidate]) -> None:
    by_file: dict[tuple[str, str], list[UnitCandidate]] = defaultdict(list)
    for item in items:
        by_file[item.file_key].append(item)
    for file_key, values in by_file.items():
        previous: UnitCandidate | None = None
        for item in sorted(values, key=lambda value: (value.source_start, value.source_end)):
            if previous is not None and item.source_start < previous.source_end:
                raise ValueError(
                    f"overlapping displayed contexts in {file_key}: "
                    f"{previous.unit_id}, {item.unit_id}"
                )
            previous = item


def _ledger(items: Sequence[UnitCandidate], *, schema_root: str = SCHEMA) -> dict:
    state = SelectionState()
    entries: list[dict] = []
    for item in sorted(items, key=lambda value: value.unit_id):
        similarity, nearest_index = state.similarity(item)
        nearest_id = (
            state.selected[nearest_index].unit_id if nearest_index is not None else None
        )
        if not state.add(item):
            raise ValueError(f"{item.unit_id}: ledger deduplication invariant failed")
        grams = item.grams
        entries.append(
            {
                "id": item.unit_id,
                "document": item.document,
                "source_file": item.source_file,
                "source_context_start_offset": item.source_start,
                "source_context_end_offset": item.source_end,
                "raw_source_context_sha256": _sha256_text(item.original_context),
                "display_context_sha256": _sha256_text(item.display),
                "normalized_exact_sha256": item.normalized_hash,
                "five_gram_set_sha256": _gram_set_sha256(grams),
                "five_gram_count": len(grams),
                "max_five_gram_jaccard_to_prior": similarity,
                "nearest_prior_id": nearest_id,
            }
        )
    return {
        "schema": f"{schema_root}-spent-ledger",
        "seed": SEED,
        "entry_count": len(entries),
        "normalization": "Unicode NFKC, casefold, collapse all whitespace",
        "five_gram": (
            "Jaccard similarity over consecutive 5 lexical-token grams; contexts with "
            f"similarity >= {FIVE_GRAM_SIMILARITY_LIMIT} are excluded"
        ),
        "entries": entries,
    }


def _summary_by_document(items: Sequence[UnitCandidate]) -> dict:
    result: dict[str, dict] = {}
    for document in sorted({item.document for item in items}):
        values = [item for item in items if item.document == document]
        result[document] = {
            "total": len(values),
            "lanes": dict(sorted(Counter(item.lane for item in values).items())),
            "regions": dict(sorted(Counter(item.region for item in values).items())),
            "subtypes": dict(sorted(Counter(item.subtype for item in values).items())),
            "front_middle_back_covered": all(
                any(item.region == region for item in values) for region in REGIONS
            ),
            "every_lane_front_middle_back_covered": all(
                any(item.lane == lane and item.region == region for item in values)
                for lane in LANES
                for region in REGIONS
            ),
        }
    return result


def _materialize_v2_and_reserve(
    manifest_path: Path, corpus_root: Path
) -> tuple[bytes, dict, Counter, list[UnitCandidate], list[UnitCandidate]]:
    """Rebuild the sealed v2 selection and its already-chosen v3 reserve.

    This function is the sole selection path for both generations.  In
    particular, v3 materialization never consults scanner/gate outcomes to
    replace, drop, or relabel reserve units.
    """

    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if manifest.get("schema") != preflight.SCHEMA:
        raise ValueError("unexpected v2 preflight manifest schema")
    if not manifest.get("status", {}).get("ready_for_later_blind_sampling"):
        raise ValueError("v2 preflight manifest is not ready for blind sampling")
    if not manifest.get("status", {}).get("v3_reserve_pass"):
        raise ValueError("v2 preflight did not prove a v3 reserve")

    pool = _collect_candidates(manifest, corpus_root)
    pool_counts = Counter(item.lane for item in pool)
    if any(pool_counts[lane] < TARGETS[lane] * 2 for lane in LANES):
        raise ValueError(f"source-truth pool cannot sustain v2+v3: {dict(pool_counts)}")

    state = SelectionState()
    selected: list[UnitCandidate] = []
    for lane in ("manual", "auto", "preserve"):
        selected.extend(
            _select_lane(
                pool,
                state,
                lane=lane,
                count=TARGETS[lane],
                phase="v2",
                require_coverage=True,
            )
        )
    selected = sorted(selected, key=lambda item: item.unit_id)
    if Counter(item.lane for item in selected) != Counter(TARGETS):
        raise ValueError("selected lane counts do not match targets")
    scope_counts = Counter(
        item.document
        for item in selected
        if item.subtype == "scope-fix-synthetic-boundary-marker-real-body"
    )
    expected_documents = {source["id"] for source in manifest["sources"]}
    if set(scope_counts) != expected_documents or any(
        scope_counts[document] != SCOPE_FIX_PER_DOCUMENT
        for document in expected_documents
    ):
        raise ValueError(f"scope-fix distribution is not 4 per document: {scope_counts}")

    # Prove a fresh v3-sized set after excluding every displayed v2 interval and
    # every exact/near-duplicate.  Do not serialize reserve contexts or labels.
    reserve_state = SelectionState(selected)
    reserve: list[UnitCandidate] = []
    for lane in ("manual", "auto", "preserve"):
        reserve.extend(
            _select_lane(
                pool,
                reserve_state,
                lane=lane,
                count=TARGETS[lane],
                phase="v3-reserve",
                require_coverage=False,
            )
        )
    reserve = [item for item in reserve if item not in selected]
    reserve_counts = Counter(item.lane for item in reserve)
    if reserve_counts != Counter(TARGETS):
        raise ValueError(f"v3 reserve mismatch: {dict(reserve_counts)}")

    _nonoverlap_check(selected)
    _nonoverlap_check([*selected, *reserve])
    return manifest_bytes, manifest, pool_counts, selected, reserve


def _v3_legacy_identity(items: Sequence[UnitCandidate]) -> list[tuple]:
    return [
        (
            item.unit_id,
            item.lane,
            item.subtype,
            item.document,
            item.source_file,
            item.source_start,
            item.source_end,
            item.target_start,
            item.target_end,
            item.normalized_hash,
        )
        for item in sorted(items, key=lambda value: value.unit_id)
    ]


def _v3_materialization_identity(items: Sequence[UnitCandidate]) -> list[dict]:
    records: list[dict] = []
    for item in sorted(items, key=lambda value: value.unit_id):
        suggestion = _gold(item)
        records.append(
            {
                "id": item.unit_id,
                "lane": item.lane,
                "subtype": item.subtype,
                "document": item.document,
                "source_file": item.source_file,
                "source_start": item.source_start,
                "source_end": item.source_end,
                "target_start": item.target_start,
                "target_end": item.target_end,
                "canonical_env": item.canonical_env,
                "focus_block": item.focus_block,
                "answer_end_block": item.answer_end_block,
                "known_structured_environments": list(item.known_structured_envs),
                "source_sha256": _sha256_text(item.original_source),
                "body_sha256": _sha256_text(item.original_body),
                "context_sha256": _sha256_text(item.display),
                "normalized_exact_sha256": item.normalized_hash,
                "gold_quad": [
                    suggestion[key]
                    for key in ("action", "env", "start_block", "end_block")
                ],
            }
        )
    return records


def _validate_v2_reserve_provenance(validation_path: Path) -> dict:
    allowed_names = {"release-validation.json", "release-v2-validation.json"}
    if validation_path.name not in allowed_names:
        raise ValueError(
            "v3 preflight only accepts the sealed v2 release validation filename"
        )
    raw = validation_path.read_bytes()
    actual_sha256 = _sha256_bytes(raw)
    if actual_sha256 != V2_VALIDATION_SHA256:
        raise ValueError(
            "sealed v2 validation hash changed: "
            f"expected {V2_VALIDATION_SHA256}, found {actual_sha256}"
        )
    validation = json.loads(raw.decode("utf-8"))
    reserve = validation.get("v3_reserve")
    if (
        validation.get("schema") != f"{SCHEMA}-validation"
        or validation.get("passed") is not True
        or validation.get("seed") != SEED
        or validation.get("unit_count") != sum(TARGETS.values())
        or not isinstance(reserve, dict)
        or reserve.get("targets") != TARGETS
        or reserve.get("actual") != TARGETS
        or reserve.get("pass") is not True
        or reserve.get("serialized") is not False
    ):
        raise ValueError("sealed v2 validation does not prove the expected v3 reserve")
    return validation


def _v3_preflight(
    manifest_path: Path,
    corpus_root: Path,
    validation_path: Path,
    *,
    return_internal: bool = False,
) -> tuple[dict, bool, dict | None]:
    """Materialize and audit frozen v3 source truth without writing it."""

    v2_validation = _validate_v2_reserve_provenance(validation_path)
    manifest_bytes, manifest, pool_counts, selected, reserve = (
        _materialize_v2_and_reserve(manifest_path, corpus_root)
    )
    reserve = sorted(reserve, key=lambda item: item.unit_id)
    reserve_counts = Counter(item.lane for item in reserve)
    if reserve_counts != Counter(TARGETS):
        raise ValueError(f"frozen v3 reserve count changed: {dict(reserve_counts)}")

    legacy_identity_sha256 = _sha256_bytes(
        _json_bytes(_v3_legacy_identity(reserve))
    )
    if legacy_identity_sha256 != V3_RESERVE_IDENTITY_SHA256:
        raise ValueError(
            "frozen v3 reserve identity changed; replacement selection is forbidden: "
            f"expected {V3_RESERVE_IDENTITY_SHA256}, found {legacy_identity_sha256}"
        )
    materialization_sha256 = _sha256_bytes(
        _json_bytes(_v3_materialization_identity(reserve))
    )
    if materialization_sha256 != V3_RESERVE_MATERIALIZATION_SHA256:
        raise ValueError(
            "frozen v3 labels/content/boundaries changed; relabeling is forbidden: "
            f"expected {V3_RESERVE_MATERIALIZATION_SHA256}, "
            f"found {materialization_sha256}"
        )

    expected_documents = sorted(source["id"] for source in manifest["sources"])
    actual_documents = sorted({item.document for item in reserve})
    if actual_documents != expected_documents:
        raise ValueError(
            f"frozen v3 reserve document coverage changed: {actual_documents}"
        )
    scope_counts = {
        document: sum(
            item.document == document
            and item.subtype == "scope-fix-synthetic-boundary-marker-real-body"
            for item in reserve
        )
        for document in expected_documents
    }
    if scope_counts != V3_FROZEN_SCOPE_FIX_COUNTS:
        raise ValueError(
            "frozen v3 move-boundary distribution changed; rebalancing is forbidden: "
            f"{scope_counts}"
        )

    # Reopen every selected source/body/context and re-prove v2/v3 isolation.
    source_hash_checks = _validate_source_hashes(reserve, manifest, corpus_root)
    _nonoverlap_check([*selected, *reserve])
    combined = SelectionState()
    for item in [*selected, *reserve]:
        if not combined.add(item):
            raise ValueError(
                f"frozen v2/v3 exact or 5-gram isolation changed at {item.unit_id}"
            )

    packet_units = [_packet_unit(item) for item in reserve]
    packets = {
        "schema": "latexstruct-external-release-v3-packets-v3",
        "seed": SEED,
        "instructions": {
            "allowed_environments": sorted(TITLE_BY_ENV),
            "task": (
                "Classify only each unit's focus_anchor. Existing custom environments "
                "are supplied per unit as non-answer structural context."
            ),
        },
        "units": packet_units,
    }
    leaked = sorted(set(_walk_keys(packets)) & FORBIDDEN_PACKET_KEYS)
    if leaked:
        raise ValueError(f"answer-bearing v3 preflight packet keys: {leaked}")
    gold = [_gold(item) for item in reserve]
    gate_envelope = production_apply_safety_gate(packets, [gold])
    gate_audit = gate_envelope["audit"]
    if gate_audit.get("raw_protocol_error_count") != 0:
        raise ValueError(f"v3 oracle had raw protocol errors: {gate_audit}")

    semantic = ("action", "env", "start_block", "end_block")
    mismatches: list[dict] = []
    for item, actual, suggestion in zip(
        reserve, gate_envelope["predictions"], gold
    ):
        if tuple(actual[key] for key in semantic) == tuple(
            suggestion[key] for key in semantic
        ):
            continue
        safety = actual.get("_safety_gate", {})
        mismatches.append(
            {
                "id": item.unit_id,
                "document": item.document,
                "frozen_subtype": item.subtype,
                "frozen_action": suggestion["action"],
                "production_action": actual["action"],
                "production_status": safety.get("status"),
                "production_reason": safety.get("reason"),
            }
        )

    document_checks = _document_checks(
        reserve, manifest, corpus_root, gate_audit
    )
    if len(document_checks) != len(expected_documents):
        raise ValueError("v3 preflight did not produce one check per document")
    checks_passed = all(
        item["content_preserved"]
        and item["resources_complete"]
        and item["environments_declared"]
        and item["compile_status"] == "not-required"
        for item in document_checks
    )
    if not checks_passed:
        raise ValueError("one or more v3 document checks failed")

    oracle_passed = not mismatches
    report = {
        "schema": "latexstruct-external-release-v3-preflight-v1",
        "generation": "v3",
        "mode": "source-truth-materialization-preflight-only",
        "passed": oracle_passed,
        "ready_to_write": oracle_passed,
        "write_performed": False,
        "unit_count": len(reserve),
        "counts": dict(sorted(reserve_counts.items())),
        "documents": _summary_by_document(reserve),
        "frozen_identity": {
            "legacy_identity_sha256": legacy_identity_sha256,
            "materialization_sha256": materialization_sha256,
            "matches_sealed_constants": True,
        },
        "v2_validation_provenance": {
            "sha256": V2_VALIDATION_SHA256,
            "reserve_proof": v2_validation["v3_reserve"],
        },
        "selection_isolation": {
            "source_body_context_hashes_reopened": source_hash_checks,
            "v2_interval_overlap": 0,
            "v2_normalized_exact_overlap": 0,
            "v2_five_gram_overlap_at_or_above_limit": 0,
            "five_gram_similarity_limit": FIVE_GRAM_SIMILARITY_LIMIT,
        },
        "move_boundary": {
            "total": sum(scope_counts.values()),
            "per_document": scope_counts,
            "classification": "synthetic-boundary-marker + real body",
            "published_source_body_changed": False,
            "frozen_selection_disclosure": (
                "The v2 builder enforced four scope fixes per document only for its v2 "
                "phase. Its already-selected v3-reserve phase did not cap or rebalance "
                "scope fixes. V3 faithfully preserves the resulting 116-unit distribution "
                "instead of retroactively replacing reserve units."
            ),
        },
        "production_oracle": {
            "checked": len(reserve),
            "exact_action_env_boundary": len(reserve) - len(mismatches),
            "mismatch_count": len(mismatches),
            "raw_protocol_error_count": gate_audit["raw_protocol_error_count"],
            "outcome_counts": gate_audit["outcome_counts"],
            "status_counts": gate_audit["status_counts"],
            "mismatches_without_source_context": mismatches,
        },
        "document_checks": {
            "count": len(document_checks),
            "all_passed": checks_passed,
            "sha256": _sha256_bytes(_json_bytes(document_checks)),
            "per_document_evidence_sha256": {
                item["document"]: item["evidence_sha256"]
                for item in document_checks
            },
        },
        "write_block": (
            "Formal v3 packet/gold output is disabled in preflight mode. Production "
            "oracle mismatches must be fixed in production code; reserve samples may "
            "not be changed, removed, or relabeled."
        ),
        "exclusions": [
            "No v2 or v3 prediction file was read.",
            "No score or error-analysis file was read.",
            "No v3 packet or gold file was written.",
            "No AI prediction was run.",
        ],
    }
    internal = None
    if return_internal:
        internal = {
            "manifest_bytes": manifest_bytes,
            "manifest": manifest,
            "pool_counts": pool_counts,
            "v2_selected": selected,
            "reserve": reserve,
            "reserve_counts": reserve_counts,
            "scope_counts": scope_counts,
            "legacy_identity_sha256": legacy_identity_sha256,
            "materialization_sha256": materialization_sha256,
            "packets": packets,
            "gold": gold,
            "gate_audit": gate_audit,
            "document_checks": document_checks,
            "source_hash_checks": source_hash_checks,
            "v2_validation": v2_validation,
            "mismatches": mismatches,
        }
    return report, oracle_passed, internal


def _build_v3_once(
    manifest_path: Path,
    corpus_root: Path,
    validation_path: Path,
) -> tuple[dict, dict, dict, dict, dict]:
    report, oracle_passed, state = _v3_preflight(
        manifest_path,
        corpus_root,
        validation_path,
        return_internal=True,
    )
    if not oracle_passed or state is None:
        raise ValueError("formal v3 build is blocked by production oracle mismatches")

    packets = state["packets"]
    gold_units = state["gold"]
    gold_payload = {
        "schema": "latexstruct-external-release-v3-gold-v3",
        "generation": "v3",
        "selection_seed": SEED,
        "units": gold_units,
    }
    document_checks = state["document_checks"]
    document_checks_payload = {
        "schema": f"{V3_SCHEMA}-document-checks",
        "generation": "v3",
        "unit_count": len(state["reserve"]),
        "document_checks": document_checks,
    }
    ledger = _ledger(state["reserve"], schema_root=V3_SCHEMA)

    packet_ids = [item["id"] for item in packets["units"]]
    gold_ids = [item["id"] for item in gold_units]
    if packet_ids != gold_ids or len(set(packet_ids)) != len(packet_ids):
        raise ValueError("v3 packet/gold ordered IDs are not unique and identical")
    packet_ids_sha256 = _sha256_bytes(_json_bytes(packet_ids))
    gold_ids_sha256 = _sha256_bytes(_json_bytes(gold_ids))
    fixture_hashes = {
        "packets_sha256": _sha256_bytes(_json_bytes(packets)),
        "gold_sha256": _sha256_bytes(_json_bytes(gold_payload)),
        "document_checks_sha256": _sha256_bytes(
            _json_bytes(document_checks_payload)
        ),
        "document_checks_array_sha256": _sha256_bytes(
            _json_bytes(document_checks)
        ),
        "spent_ledger_sha256": _sha256_bytes(_json_bytes(ledger)),
        "packet_ids_sha256": packet_ids_sha256,
        "gold_ids_sha256": gold_ids_sha256,
    }
    frozen_actions = dict(
        sorted(Counter(item["action"] for item in gold_units).items())
    )
    document_summary = _summary_by_document(state["reserve"])
    document_ids = sorted(document_summary)
    if document_ids != sorted(V3_FROZEN_SCOPE_FIX_COUNTS):
        raise ValueError(f"v3 document IDs changed: {document_ids}")

    validation = {
        "schema": f"{V3_SCHEMA}-validation",
        "generation": "v3",
        "passed": True,
        "selection_seed": SEED,
        "manifest_sha256": _sha256_bytes(state["manifest_bytes"]),
        "targets": TARGETS,
        "actual": dict(sorted(state["reserve_counts"].items())),
        "unit_count": len(state["reserve"]),
        "total": len(state["reserve"]),
        "document_ids": document_ids,
        "documents": document_summary,
        "document_checks": document_checks,
        "document_checks_artifact": {
            "schema": document_checks_payload["schema"],
            "sha256": fixture_hashes["document_checks_sha256"],
            "array_sha256": fixture_hashes["document_checks_array_sha256"],
            "count": len(document_checks),
            "all_passed": True,
        },
        "id_binding": {
            "packet_ids_sha256": packet_ids_sha256,
            "gold_ids_sha256": gold_ids_sha256,
            "ordered_ids_match": True,
            "unique_id_count": len(set(packet_ids)),
        },
        "frozen_v2_reserve": {
            "v2_validation_sha256": V2_VALIDATION_SHA256,
            "legacy_identity_sha256": state["legacy_identity_sha256"],
            "materialization_sha256": state["materialization_sha256"],
            "identity_and_labels_unchanged": True,
            "replacement_or_relabeling_permitted": False,
            "source_truth_selected_before_v3_scanner_or_gate": True,
            "scanner_or_gate_failures_abort_instead_of_reselecting": True,
            "v2_interval_overlap": 0,
            "v2_normalized_exact_overlap": 0,
            "v2_five_gram_overlap_at_or_above_limit": 0,
            "five_gram_similarity_limit": FIVE_GRAM_SIMILARITY_LIMIT,
            "selection_disclosure": report["move_boundary"][
                "frozen_selection_disclosure"
            ],
        },
        "move_boundary": report["move_boundary"],
        "production_oracle": {
            **report["production_oracle"],
            "passed": True,
            "frozen_action_counts": frozen_actions,
            "pipeline": (
                "tools.apply_external_safety_gate.apply_safety_gate -> production "
                "parse/scan/legalize/context/build_ops"
            ),
        },
        "integrity": {
            "packet_answer_key_fields_absent": True,
            "unique_ids": True,
            "displayed_source_contexts_nonoverlapping": True,
            "source_and_body_hashes_revalidated": state["source_hash_checks"],
            "spent_ledger_entries": ledger["entry_count"],
            "normalized_exact_hashes_unique": True,
            "five_gram_deduplication_pass": True,
            "all_six_documents_front_middle_back_covered": all(
                item["front_middle_back_covered"]
                for item in document_summary.values()
            ),
        },
        "fixture_hashes": fixture_hashes,
        "hashes": fixture_hashes,
        "determinism": {
            "fixed_selection_seed": True,
            "double_build_required": True,
        },
        "exclusions": [
            "No v2 or v3 prediction file was read.",
            "No score or error-analysis file was read.",
            "No AI prediction was run by this builder.",
            "Frozen v3 units were not replaced, removed, or relabeled.",
        ],
    }
    return packets, gold_payload, validation, ledger, document_checks_payload


def _build_once(manifest_path: Path, corpus_root: Path) -> tuple[dict, dict, dict, dict]:
    manifest_bytes, manifest, pool_counts, selected, reserve = (
        _materialize_v2_and_reserve(manifest_path, corpus_root)
    )
    reserve_counts = Counter(item.lane for item in reserve)
    source_hash_checks = _validate_source_hashes(selected, manifest, corpus_root)

    packet_units = [_packet_unit(item) for item in selected]
    packets = {
        "schema": "latexstruct-external-release-v2-packets-v2",
        "seed": SEED,
        "instructions": {
            "allowed_environments": sorted(TITLE_BY_ENV),
            "task": (
                "Classify only each unit's focus_anchor. Existing custom environments "
                "are supplied per unit as non-answer structural context."
            ),
        },
        "units": packet_units,
    }
    gold = [_gold(item) for item in selected]
    if len({item["id"] for item in packet_units}) != len(packet_units):
        raise ValueError("duplicate packet IDs")
    packet_keys = set(_walk_keys(packets))
    leaked = sorted(packet_keys & FORBIDDEN_PACKET_KEYS)
    if leaked:
        raise ValueError(f"answer-bearing packet keys: {leaked}")

    gate_envelope = production_apply_safety_gate(packets, [gold])
    gate_audit = gate_envelope["audit"]
    if gate_audit.get("raw_protocol_error_count") != 0:
        raise ValueError(f"gold oracle had raw protocol errors: {gate_audit}")
    gated = gate_envelope["predictions"]
    if len(gated) != len(gold):
        raise ValueError("production safety gate did not return every gold suggestion")
    oracle_exact = 0
    oracle_mismatches: list[dict] = []
    for candidate, actual, suggestion in zip(selected, gated, gold):
        semantic = ("action", "env", "start_block", "end_block")
        if tuple(actual[key] for key in semantic) != tuple(
            suggestion[key] for key in semantic
        ):
            oracle_mismatches.append(
                {
                    "id": candidate.unit_id,
                    "document": candidate.document,
                    "source_file": candidate.source_file,
                    "source_line": candidate.source_start_line,
                    "subtype": candidate.subtype,
                    "gold": {key: suggestion[key] for key in semantic},
                    "actual": {key: actual[key] for key in semantic},
                    "status": actual.get("_safety_gate", {}).get("status"),
                    "reason": actual.get("_safety_gate", {}).get("reason"),
                    "blocks": [
                        {
                            "index": index,
                            "lines": value.count("\n") + 1,
                            "preview": value[:1200],
                        }
                        for index, value in enumerate(candidate.blocks)
                    ],
                }
            )
            continue
        oracle_exact += 1
    if oracle_mismatches:
        raise ValueError(
            "production safety gate changed source-truth gold suggestions: "
            + json.dumps(oracle_mismatches[:20], ensure_ascii=False)
        )

    document_checks = _document_checks(
        selected, manifest, corpus_root, gate_audit
    )
    if len(document_checks) != 6:
        raise ValueError(
            f"validation requires exactly six document checks, got {len(document_checks)}"
        )
    gold_payload = {
        "schema": "latexstruct-external-release-v2-gold-v2",
        "seed": SEED,
        "units": gold,
    }
    ledger = _ledger(selected)
    packet_ids = [item["id"] for item in packet_units]
    gold_ids = [item["id"] for item in gold]
    if packet_ids != gold_ids:
        raise ValueError("ordered packet and gold IDs do not match")
    packet_ids_sha256 = _sha256_bytes(_json_bytes(packet_ids))
    gold_ids_sha256 = _sha256_bytes(_json_bytes(gold_ids))
    fixture_hashes = {
        "packets_sha256": _sha256_bytes(_json_bytes(packets)),
        "gold_sha256": _sha256_bytes(_json_bytes(gold_payload)),
        "spent_ledger_sha256": _sha256_bytes(_json_bytes(ledger)),
        "packet_ids_sha256": packet_ids_sha256,
        "gold_ids_sha256": gold_ids_sha256,
        "document_checks_sha256": _sha256_bytes(_json_bytes(document_checks)),
    }
    document_summary = _summary_by_document(selected)
    if not all(
        item["front_middle_back_covered"]
        and item["every_lane_front_middle_back_covered"]
        for item in document_summary.values()
    ):
        raise ValueError("one or more documents lack front/middle/back coverage")
    if not any(item.qed_followed_by_math_closer for item in selected):
        raise ValueError("selected v2 set lacks a QED-plus-math-closer proof")

    validation = {
        "schema": f"{SCHEMA}-validation",
        "passed": True,
        "seed": SEED,
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "targets": TARGETS,
        "actual": dict(sorted(Counter(item.lane for item in selected).items())),
        "unit_count": len(selected),
        "total": len(selected),
        "documents": document_summary,
        "document_checks": document_checks,
        "id_binding": {
            "packet_ids_sha256": packet_ids_sha256,
            "gold_ids_sha256": gold_ids_sha256,
            "ordered_ids_match": True,
            "unique_id_count": len(set(packet_ids)),
        },
        "source_truth_pool_before_scanner_or_gate": dict(sorted(pool_counts.items())),
        "sampling_independence": {
            "selected_before_scanner_validation": True,
            "scanner_or_gate_failures_are_build_failures": True,
            "scanner_or_gate_failures_never_delete_or_relabel_units": True,
        },
        "production_oracle": {
            "pipeline": (
                "tools.apply_external_safety_gate.apply_safety_gate -> production "
                "parse/scan/legalize/context/build_ops"
            ),
            "gold_suggestions_checked": oracle_exact,
            "exact_action_env_boundary": oracle_exact,
            "raw_protocol_error_count": gate_audit["raw_protocol_error_count"],
            "outcome_counts": gate_audit["outcome_counts"],
            "status_counts": gate_audit["status_counts"],
            "preserve_focus_zero_candidates": sum(
                item.lane == "preserve" for item in selected
            ),
            "manual_gold_fail_closed": sum(item.lane == "manual" for item in selected),
            "qed_followed_by_math_closer_units": sum(
                item.qed_followed_by_math_closer for item in selected
            ),
            "scope_fix_synthetic_boundary_marker_real_body": {
                "total": sum(
                    item.subtype
                    == "scope-fix-synthetic-boundary-marker-real-body"
                    for item in selected
                ),
                "per_document": {
                    document: sum(
                        item.document == document
                        and item.subtype
                        == "scope-fix-synthetic-boundary-marker-real-body"
                        for item in selected
                    )
                    for document in sorted({item.document for item in selected})
                },
                "marker": SYNTHETIC_SCOPE_MARKER,
                "published_source_body_changed": False,
            },
        },
        "integrity": {
            "packet_answer_key_fields_absent": True,
            "unique_ids": True,
            "displayed_source_contexts_nonoverlapping": True,
            "source_and_body_hashes_revalidated": source_hash_checks,
            "spent_ledger_entries": ledger["entry_count"],
            "normalized_exact_hashes_unique": True,
            "five_gram_similarity_limit": FIVE_GRAM_SIMILARITY_LIMIT,
            "five_gram_deduplication_pass": True,
        },
        "v3_reserve": {
            "serialized": False,
            "reason": "reserve contexts remain unspent and answer-free",
            "targets": TARGETS,
            "actual": dict(sorted(reserve_counts.items())),
            "pass": reserve_counts == Counter(TARGETS),
            "nonoverlap_with_v2_and_within_reserve": True,
            "exact_and_five_gram_deduplicated_against_v2": True,
        },
        "fixture_hashes": fixture_hashes,
        # Retained as a compatibility alias for the v1 scorer while the v2
        # schema consumes the more explicit fixture_hashes object above.
        "hashes": fixture_hashes,
        "determinism": {
            "fixed_seed": True,
            "double_build_required": True,
        },
        "exclusions": [
            "No earlier gold file was read.",
            "No earlier or current prediction file was read.",
            "No score or first-round error-analysis file was read.",
            "No AI prediction was run by this builder.",
        ],
    }
    return packets, gold_payload, validation, ledger


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--generation",
        choices=("v2", "v3"),
        default="v2",
        help=(
            "v2 writes the sealed fixture; v3 defaults to frozen-reserve preflight "
            "and requires --write-v3 for formal output"
        ),
    )
    parser.add_argument(
        "--write-v3",
        action="store_true",
        help="after two matching builds, write formal v3 artifacts to an isolated dir",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-corpus-v2" / "manifest.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-results-v2",
    )
    parser.add_argument(
        "--v2-validation",
        type=Path,
        default=(
            REPO_ROOT.parent
            / "work"
            / "external-results-v2"
            / "release-validation.json"
        ),
        help="sealed v2 validation used only to bind the preselected v3 reserve",
    )
    parser.add_argument(
        "--v3-output-dir",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-results-v3",
    )
    args = parser.parse_args()
    if args.write_v3 and args.generation != "v3":
        parser.error("--write-v3 requires --generation v3")

    manifest_path = args.manifest.resolve()
    corpus_root = manifest_path.parent
    if args.generation == "v3":
        validation_path = args.v2_validation.resolve()
        if not args.write_v3:
            report, oracle_passed, _internal = _v3_preflight(
                manifest_path,
                corpus_root,
                validation_path,
            )
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
            return 0 if oracle_passed else 2

        v2_dir = validation_path.parent
        v2_names = (
            "release-packets.json",
            "release-gold.json",
            "release-validation.json",
            "release-v2-packets.json",
            "release-v2-gold.json",
            "release-v2-validation.json",
            "spent-ledger.json",
        )
        v2_hashes_before = {
            name: _sha256_bytes((v2_dir / name).read_bytes()) for name in v2_names
        }
        first = _build_v3_once(manifest_path, corpus_root, validation_path)
        second = _build_v3_once(manifest_path, corpus_root, validation_path)
        first_hashes = tuple(_sha256_bytes(_json_bytes(item)) for item in first)
        second_hashes = tuple(_sha256_bytes(_json_bytes(item)) for item in second)
        if first_hashes != second_hashes:
            raise ValueError(
                "v3 determinism failure: independent in-memory builds differ"
            )
        packets, gold, validation, ledger, document_checks = first
        validation = dict(validation)
        validation["determinism"] = {
            **validation["determinism"],
            "two_independent_in_memory_builds_match": True,
            "prewrite_payload_sha256": {
                "packets": first_hashes[0],
                "gold": first_hashes[1],
                "validation_without_double_build_hash": first_hashes[2],
                "spent_ledger": first_hashes[3],
                "document_checks": first_hashes[4],
            },
        }
        validation["v2_artifact_guard"] = {
            "directory": str(v2_dir),
            "files_checked": len(v2_names),
            "unchanged": True,
        }

        output_dir = args.v3_output_dir.resolve()
        outputs = {
            "release-packets.json": packets,
            "release-gold.json": gold,
            "release-validation.json": validation,
            "release-v3-packets.json": packets,
            "release-v3-gold.json": gold,
            "release-v3-validation.json": validation,
            "document-checks.json": document_checks,
            "release-v3-document-checks.json": document_checks,
            "spent-ledger.json": ledger,
        }
        for name, value in outputs.items():
            _write(output_dir / name, value)

        v2_hashes_after = {
            name: _sha256_bytes((v2_dir / name).read_bytes()) for name in v2_names
        }
        if v2_hashes_after != v2_hashes_before:
            raise ValueError("formal v3 write unexpectedly changed a sealed v2 artifact")

        summary = {
            "schema": V3_SCHEMA,
            "output_dir": str(output_dir),
            "counts": validation["actual"],
            "total": validation["unit_count"],
            "documents": {
                key: {
                    "total": value["total"],
                    "regions": value["regions"],
                    "lanes": value["lanes"],
                }
                for key, value in validation["documents"].items()
            },
            "production_oracle": validation["production_oracle"],
            "frozen_identity": validation["frozen_v2_reserve"],
            "v2_artifacts_unchanged": True,
            "file_sha256": {
                "release-packets.json": _sha256_bytes(
                    _json_bytes(outputs["release-packets.json"])
                ),
                "release-validation.json": _sha256_bytes(
                    _json_bytes(outputs["release-validation.json"])
                ),
            },
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    first = _build_once(manifest_path, corpus_root)
    second = _build_once(manifest_path, corpus_root)
    first_hashes = tuple(_sha256_bytes(_json_bytes(item)) for item in first)
    second_hashes = tuple(_sha256_bytes(_json_bytes(item)) for item in second)
    if first_hashes != second_hashes:
        raise ValueError(
            f"determinism failure: first={first_hashes}, second={second_hashes}"
        )
    packets, gold, validation, ledger = first
    validation = dict(validation)
    validation["determinism"] = {
        **validation["determinism"],
        "two_independent_in_memory_builds_match": True,
        "prewrite_payload_sha256": {
            "packets": first_hashes[0],
            "gold": first_hashes[1],
            "validation_without_double_build_hash": first_hashes[2],
            "spent_ledger": first_hashes[3],
        },
    }

    output_dir = args.output_dir.resolve()
    outputs = {
        "release-packets.json": packets,
        "release-gold.json": gold,
        "release-validation.json": validation,
        "release-v2-packets.json": packets,
        "release-v2-gold.json": gold,
        "release-v2-validation.json": validation,
        "spent-ledger.json": ledger,
    }
    for name, value in outputs.items():
        _write(output_dir / name, value)

    summary = {
        "schema": SCHEMA,
        "output_dir": str(output_dir),
        "counts": validation["actual"],
        "total": validation["total"],
        "documents": {
            key: {
                "total": value["total"],
                "regions": value["regions"],
                "lanes": value["lanes"],
            }
            for key, value in validation["documents"].items()
        },
        "production_oracle": validation["production_oracle"],
        "v3_reserve": validation["v3_reserve"],
        "file_sha256": {
            name: _sha256_bytes(_json_bytes(value)) for name, value in outputs.items()
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
