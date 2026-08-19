#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the frozen 600-unit external release fixture.

This is the second-stage fixture for the accuracy release gate.  It reuses the
same six frozen public mathematical sources as ``build_external_blind_fixture``
but excludes every pilot source interval.  It creates exactly:

* 250 automatically recoverable OCR-style structures;
* 250 real top-level narrative/cross-reference preservation cases; and
* 100 real ambiguous structures whose only safe answer is ``manual``.

The packet and gold files are physically separate.  The packet contains a
focus anchor and context, but no per-unit action, environment, boundary, source
line, or evidence label.  No model is called and no predictions are read.

Default invocation (from the repository root)::

    python tools/build_external_release_fixture.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence, TypeVar


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from latexstruct.core.parser import Block, Document, offset_to_line, parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402
from tools import build_external_blind_fixture as pilot  # noqa: E402


EXPECTED_SOURCE_HASHES = {
    "D01": "f65d402904e17e7ab1d23f1fe07b90a42e7b1147d3b7998ae3d0037c6cf8beac",
    "D02": "6a995761cf43df0f6cf9beb3075693f77b28cdff23fae928e9d6beda5f9bf4f9",
    "D03": "d16c6945525497e24eca6714cc3bad6516d3efec18fb5deb03637a4ea2501ba2",
    "D04": "8adb2d1c6ad8def29d38d1187947b9cbad6284f4b8268780356e3c3978b9ed20",
    "D05": "8d092327d928fe0b6b7c54c3e9d2f4051c35b50d52f53c642c113ae02f0e49de",
    "D06": "ad701d260b4afbd3c7d5b04b614e6053158df68c63cdaddf1837ba6d2bc6ee53",
}

AUTO_TARGET = 250
PRESERVE_TARGET = 250
MANUAL_TARGET = 100
TOTAL_TARGET = AUTO_TARGET + PRESERVE_TARGET + MANUAL_TARGET
REGION_NAMES = pilot.REGION_NAMES
ALLOWED_ENVS = pilot.ALLOWED_ENVS

HARD_PROOF_END_RE = re.compile(
    r"(?:\\qed(?:here)?|\\(?:Box|square|blacksquare)|\u220e)"
    r"(?:\s|[}\])$.,;:])*\Z",
    re.I,
)
STRUCTURAL_SUCCESSOR_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection|paragraph)\*?\s*\{"
    r"|\\begin\s*\{(?P<env>[^{}]+)\}",
)
COMMENT_OR_BLANK_RE = re.compile(r"[ \t]*(?:%[^\n]*)?(?:\n|\Z)")


@dataclass(frozen=True)
class SourceState:
    spec: pilot.SourceSpec
    raw: bytes
    text: str
    encoding: str
    sha256: str
    total_lines: int
    doc: Document
    normal_items: tuple[pilot.NegativeItem, ...]
    pilot_intervals: tuple[tuple[int, int], ...]
    pilot_ids: frozenset[str]


@dataclass(frozen=True)
class StructureItem:
    state: SourceState
    raw_env: str
    env: str
    begin_start: int
    begin_end: int
    end_start: int
    end_end: int
    start_line: int
    end_line: int
    region: int
    body: str
    fragments: tuple[str, ...]
    paragraph_count: int
    nested_target: bool
    successor_kind: str
    successor_context: str
    hard_proof_end: bool
    disposition: str
    boundary_evidence: str

    @property
    def midpoint(self) -> float:
        return (self.start_line + self.end_line) / 2


@dataclass(frozen=True)
class PreserveItem:
    state: SourceState
    negative: pilot.NegativeItem

    @property
    def start_line(self) -> int:
        return self.negative.block.span.start_line

    @property
    def end_line(self) -> int:
        return self.negative.block.span.end_line

    @property
    def region(self) -> int:
        return self.negative.region

    @property
    def midpoint(self) -> float:
        return self.negative.midpoint


T = TypeVar("T")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _unit_id(source_sha256: str, start_line: int, end_line: int) -> str:
    return f"sha256:{source_sha256}:{start_line:06d}-{end_line:06d}"


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] <= right[1] and right[0] <= left[1]


def _overlaps_any(interval: tuple[int, int], others: Iterable[tuple[int, int]]) -> bool:
    return any(_overlaps(interval, other) for other in others)


def _split_atomic(body: str) -> list[str]:
    """Split a body losslessly at blank lines without imposing a hidden cap."""
    if not body:
        return []
    pieces: list[str] = []
    start = 0
    for match in re.finditer(r"\n[ \t]*\n", body):
        pieces.append(body[start : match.end()])
        start = match.end()
    pieces.append(body[start:])
    pieces = [piece for piece in pieces if piece]

    merged: list[str] = []
    prefix = ""
    for piece in pieces:
        if not piece.strip():
            prefix += piece
            continue
        merged.append(prefix + piece)
        prefix = ""
    if prefix:
        if merged:
            merged[-1] += prefix
        else:
            merged.append(prefix)
    return merged


def _packet_fragments(body: str, maximum: int = 16) -> tuple[str, ...]:
    fragments = _split_atomic(body)
    if len(fragments) <= maximum:
        return tuple(fragments)
    grouped: list[str] = []
    for index in range(maximum):
        left = index * len(fragments) // maximum
        right = (index + 1) * len(fragments) // maximum
        grouped.append("".join(fragments[left:right]))
    return tuple(grouped)


def _skip_comments_and_blank(text: str, start: int) -> int:
    cursor = start
    while cursor < len(text):
        match = COMMENT_OR_BLANK_RE.match(text, cursor)
        if match is None or match.end() == cursor:
            break
        cursor = match.end()
    return cursor


def _successor_evidence(
    state: SourceState,
    end_end: int,
) -> tuple[str, str]:
    """Return a visible structural stop and exact source context, if present."""
    cursor = _skip_comments_and_blank(state.text, end_end)
    match = STRUCTURAL_SUCCESSOR_RE.match(state.text, cursor)
    if match is None:
        return "", ""
    env = (match.groupdict().get("env") or "").strip()
    if env and env not in state.spec.env_map:
        return "", ""

    if env:
        matching_range = next(
            (
                item
                for item in state.doc.env_ranges
                if item[0] == env and item[1] == cursor
            ),
            None,
        )
        if matching_range is not None:
            context = state.text[matching_range[1] : matching_range[4]]
            if len(context) <= 6000:
                return f"next-environment:{state.spec.env_map[env]}", context
        line_end = state.text.find("\n", cursor)
        if line_end < 0:
            line_end = len(state.text)
        return f"next-environment:{state.spec.env_map[env]}", state.text[cursor:line_end]

    line_end = state.text.find("\n", cursor)
    if line_end < 0:
        line_end = len(state.text)
    command = match.group(0).split("{")[0].lstrip("\\")
    return f"next-section:{command}", state.text[cursor:line_end]


def _load_pilot_exclusions(pilot_gold_path: Path) -> tuple[dict[str, list[tuple[int, int]]], set[str]]:
    payload = json.loads(pilot_gold_path.read_text(encoding="utf-8"))
    if payload.get("schema") != "latexstruct-external-blind-gold-v1":
        raise ValueError(f"unexpected pilot schema in {pilot_gold_path}")
    intervals: dict[str, list[tuple[int, int]]] = defaultdict(list)
    ids: set[str] = set()
    for unit in payload.get("units", []):
        unit_id = unit.get("id")
        document = unit.get("document")
        start = unit.get("source_start_line")
        end = unit.get("source_end_line")
        if not isinstance(unit_id, str) or not isinstance(document, str):
            raise ValueError("pilot gold contains an invalid ID or document")
        if not isinstance(start, int) or not isinstance(end, int) or start > end:
            raise ValueError(f"pilot gold contains an invalid interval: {unit_id}")
        ids.add(unit_id)
        intervals[document].append((start, end))
    if len(ids) != 139:
        raise ValueError(f"expected 139 pilot IDs, found {len(ids)}")
    return intervals, ids


def _load_sources(
    corpus_root: Path,
    pilot_intervals: dict[str, list[tuple[int, int]]],
    pilot_ids: set[str],
) -> list[SourceState]:
    states: list[SourceState] = []
    for spec in pilot.SOURCES:
        source_path = corpus_root / spec.relative_path
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        raw, text, encoding = pilot._read_source(source_path)
        source_sha256 = _sha256_bytes(raw)
        expected = EXPECTED_SOURCE_HASHES[spec.document_id]
        if source_sha256 != expected:
            raise ValueError(
                f"{spec.document_id}: frozen source hash {source_sha256} != {expected}"
            )
        total_lines = len(text.splitlines())
        doc = parse_latex(text)
        normal_items = tuple(pilot._normal_paragraphs(doc, total_lines, 6000))
        states.append(
            SourceState(
                spec=spec,
                raw=raw,
                text=text,
                encoding=encoding,
                sha256=source_sha256,
                total_lines=total_lines,
                doc=doc,
                normal_items=normal_items,
                pilot_intervals=tuple(sorted(pilot_intervals.get(spec.document_id, []))),
                pilot_ids=frozenset(
                    unit_id
                    for unit_id in pilot_ids
                    if unit_id.startswith(f"sha256:{source_sha256}:")
                ),
            )
        )
    return states


def _enumerate_structures(state: SourceState) -> list[StructureItem]:
    raw_targets: list[tuple[str, str, int, int, int, int, int, int]] = []
    preamble_end = state.doc.preamble_span.end_line if state.doc.preamble_span else 0
    for raw_env, begin_start, begin_end, end_start, end_end in state.doc.env_ranges:
        if raw_env not in state.spec.env_map:
            continue
        start_line = offset_to_line(state.doc.line_starts, begin_start)
        end_line = offset_to_line(state.doc.line_starts, max(begin_start, end_end - 1))
        if start_line <= preamble_end:
            continue
        interval = (start_line, end_line)
        unit_id = _unit_id(state.sha256, start_line, end_line)
        if unit_id in state.pilot_ids or _overlaps_any(interval, state.pilot_intervals):
            continue
        raw_targets.append(
            (
                raw_env,
                state.spec.env_map[raw_env],
                begin_start,
                begin_end,
                end_start,
                end_end,
                start_line,
                end_line,
            )
        )

    result: list[StructureItem] = []
    for target in raw_targets:
        raw_env, env, begin_start, begin_end, end_start, end_end, start_line, end_line = target
        body = state.text[begin_end:end_start]
        if not body.strip():
            continue
        interval_offsets = (begin_start, end_end)
        nested_target = any(
            other is not target
            and (
                interval_offsets[0] < other[2] < other[5] <= interval_offsets[1]
                or other[2] < interval_offsets[0] < interval_offsets[1] <= other[5]
            )
            for other in raw_targets
        )
        atomic = _split_atomic(body)
        if not atomic:
            continue
        fragments = _packet_fragments(body)
        successor_kind, successor_context = _successor_evidence(state, end_end)
        hard_proof_end = bool(HARD_PROOF_END_RE.search(body.rstrip()))

        if nested_target:
            disposition = "manual"
            evidence = "nested-theorem-like-structure"
        elif len(body) > 8000 or len(atomic) > 12:
            disposition = "manual"
            evidence = "long-window-boundary"
        elif env == "proof":
            if hard_proof_end:
                disposition = "auto"
                evidence = "proof-hard-end-marker"
            elif successor_kind:
                disposition = "auto"
                evidence = "proof-explicit-structural-successor"
            else:
                disposition = "manual"
                evidence = "proof-boundary-ambiguous-no-hard-end"
        elif len(atomic) == 1:
            disposition = "auto"
            evidence = "single-atomic-statement"
        elif successor_kind:
            disposition = "auto"
            evidence = "explicit-structural-successor"
        else:
            disposition = "manual"
            evidence = "multiparagraph-boundary-ambiguous"

        result.append(
            StructureItem(
                state=state,
                raw_env=raw_env,
                env=env,
                begin_start=begin_start,
                begin_end=begin_end,
                end_start=end_start,
                end_end=end_end,
                start_line=start_line,
                end_line=end_line,
                region=pilot._region((start_line + end_line) / 2, state.total_lines),
                body=body,
                fragments=fragments,
                paragraph_count=len(atomic),
                nested_target=nested_target,
                successor_kind=successor_kind,
                successor_context=successor_context,
                hard_proof_end=hard_proof_end,
                disposition=disposition,
                boundary_evidence=evidence,
            )
        )
    return result


def _interleave(items: Sequence[T], key: Callable[[T], tuple]) -> list[T]:
    buckets: dict[tuple, deque[T]] = defaultdict(deque)
    for item in sorted(items, key=lambda value: (key(value), value.midpoint)):
        buckets[key(item)].append(item)
    ordered: list[T] = []
    bucket_keys = sorted(buckets)
    while bucket_keys:
        next_keys: list[tuple] = []
        for bucket_key in bucket_keys:
            bucket = buckets[bucket_key]
            if bucket:
                ordered.append(bucket.popleft())
            if bucket:
                next_keys.append(bucket_key)
        bucket_keys = next_keys
    return ordered


def _balanced_select(
    items: Sequence[T],
    target: int,
    used_intervals: dict[str, list[tuple[int, int]]],
    sequence_key: Callable[[T], tuple],
) -> list[T]:
    """Round-robin document thirds while enforcing line-disjoint units."""
    by_cell: dict[tuple[str, int], deque[T]] = {}
    for document_id in (spec.document_id for spec in pilot.SOURCES):
        for region in range(3):
            group = [
                item
                for item in items
                if item.state.spec.document_id == document_id and item.region == region
            ]
            if group:
                by_cell[(document_id, region)] = deque(_interleave(group, sequence_key))

    cell_order = [
        (spec.document_id, region)
        for region in range(3)
        for spec in pilot.SOURCES
        if (spec.document_id, region) in by_cell
    ]
    selected: list[T] = []
    while len(selected) < target and cell_order:
        next_cells: list[tuple[str, int]] = []
        progress = False
        for cell in cell_order:
            queue = by_cell[cell]
            chosen = None
            while queue:
                candidate = queue.popleft()
                document_id = candidate.state.spec.document_id
                interval = (candidate.start_line, candidate.end_line)
                if _overlaps_any(interval, used_intervals[document_id]):
                    continue
                chosen = candidate
                break
            if chosen is not None and len(selected) < target:
                selected.append(chosen)
                document_id = chosen.state.spec.document_id
                used_intervals[document_id].append((chosen.start_line, chosen.end_line))
                progress = True
            if queue:
                next_cells.append(cell)
        if not progress:
            break
        cell_order = next_cells
    if len(selected) != target:
        raise ValueError(f"could select only {len(selected)} of {target} requested units")
    return selected


def _append_block(blocks: list[dict], text: str) -> int:
    block_id = len(blocks)
    blocks.append({"id": block_id, "text": text})
    return block_id


def _nearest_contexts(
    state: SourceState,
    start_line: int,
    end_line: int,
    excluded_block_id: int | None = None,
) -> tuple[Block | None, Block | None]:
    return pilot._nearest_context(
        state.normal_items,
        start_line,
        end_line,
        excluded_block_id=excluded_block_id,
    )


def _structure_packet_and_gold(item: StructureItem) -> tuple[dict, dict]:
    before, normal_after = _nearest_contexts(
        item.state,
        item.start_line,
        item.end_line,
    )
    blocks: list[dict] = []
    if before is not None:
        _append_block(blocks, before.text)
    focus_anchor = _append_block(blocks, f"{pilot.CANONICAL_TITLES[item.env]}.")
    body_block_ids = [_append_block(blocks, fragment) for fragment in item.fragments]
    if item.successor_context:
        _append_block(blocks, item.successor_context)
    elif normal_after is not None:
        _append_block(blocks, normal_after.text)

    unit_id = _unit_id(item.state.sha256, item.start_line, item.end_line)
    packet = {
        "id": unit_id,
        "document_id": item.state.spec.document_id,
        "document_region": REGION_NAMES[item.region],
        "focus_anchor": focus_anchor,
        "blocks": blocks,
    }
    if item.disposition == "auto":
        action = "wrap"
        env = item.env
        start_block = focus_anchor
        end_block = body_block_ids[-1]
    else:
        action = "manual"
        env = ""
        start_block = focus_anchor
        end_block = focus_anchor
    gold = {
        "id": unit_id,
        "document": item.state.spec.document_id,
        "sample_kind": "ocr-bare-heading",
        "source_start_line": item.start_line,
        "source_end_line": item.end_line,
        "source_raw_env": item.raw_env,
        "source_canonical_env": item.env,
        "action": action,
        "env": env,
        "start_block": start_block,
        "end_block": end_block,
        "body_block_ids": body_block_ids,
        "source_body_sha256": _sha256_text(item.body),
        "source_body_chars": len(item.body),
        "source_body_paragraphs": item.paragraph_count,
        "boundary_evidence": item.boundary_evidence,
        "successor_kind": item.successor_kind,
        "numbering_conflict": False,
        "packet_blocks_sha256": _sha256_text(_canonical_json(blocks)),
    }
    return packet, gold


def _preserve_packet_and_gold(item: PreserveItem) -> tuple[dict, dict]:
    block = item.negative.block
    before, after = _nearest_contexts(
        item.state,
        item.start_line,
        item.end_line,
        excluded_block_id=block.id,
    )
    blocks: list[dict] = []
    if before is not None:
        _append_block(blocks, before.text)
    focus_anchor = _append_block(blocks, block.text)
    if after is not None:
        _append_block(blocks, after.text)
    unit_id = _unit_id(item.state.sha256, item.start_line, item.end_line)
    packet = {
        "id": unit_id,
        "document_id": item.state.spec.document_id,
        "document_region": REGION_NAMES[item.region],
        "focus_anchor": focus_anchor,
        "blocks": blocks,
    }
    gold = {
        "id": unit_id,
        "document": item.state.spec.document_id,
        "sample_kind": item.negative.class_name,
        "source_start_line": item.start_line,
        "source_end_line": item.end_line,
        "action": "preserve",
        "env": "",
        "start_block": focus_anchor,
        "end_block": focus_anchor,
        "source_text_sha256": _sha256_text(block.text),
        "source_text_chars": len(block.text),
        "boundary_evidence": "top-level-focus-paragraph",
        "packet_blocks_sha256": _sha256_text(_canonical_json(blocks)),
    }
    return packet, gold


def _render_for_scanner(packet: dict) -> tuple[str, tuple[int, int]]:
    pieces: list[str] = []
    spans: dict[int, tuple[int, int]] = {}
    cursor = 0
    for index, block in enumerate(packet["blocks"]):
        if index:
            pieces.append("\n\n")
            cursor += 2
        start = cursor
        text = block["text"]
        pieces.append(text)
        cursor += len(text)
        spans[block["id"]] = (start, cursor)
    rendered = "".join(pieces)
    start_off, end_off = spans[packet["focus_anchor"]]
    focus_start = rendered.count("\n", 0, start_off) + 1
    focus_end = rendered.count("\n", 0, max(start_off, end_off - 1)) + 1
    return rendered, (focus_start, focus_end)


def _scanner_focus_result(packet: dict) -> dict:
    rendered, (focus_start, focus_end) = _render_for_scanner(packet)
    scanned = scan(parse_latex(rendered))
    candidates = [
        candidate
        for candidate in scanned.candidates
        if candidate.span.start_line <= focus_end
        and focus_start <= candidate.span.end_line
    ]
    return {
        "focus_start_line": focus_start,
        "focus_end_line": focus_end,
        "candidate_count": len(candidates),
        "candidate_ids": [candidate.id for candidate in candidates],
        "candidate_kinds": [candidate.kind for candidate in candidates],
        "candidate_env_hints": [candidate.env_hint for candidate in candidates],
    }


def _eligible_preserves(
    states: Sequence[SourceState],
    used_intervals: dict[str, list[tuple[int, int]]],
) -> list[PreserveItem]:
    eligible: list[PreserveItem] = []
    for state in states:
        for negative in state.normal_items:
            item = PreserveItem(state=state, negative=negative)
            interval = (item.start_line, item.end_line)
            unit_id = _unit_id(state.sha256, item.start_line, item.end_line)
            if unit_id in state.pilot_ids:
                continue
            if _overlaps_any(interval, state.pilot_intervals):
                continue
            if _overlaps_any(interval, used_intervals[state.spec.document_id]):
                continue
            packet, _gold = _preserve_packet_and_gold(item)
            scanner_result = _scanner_focus_result(packet)
            if scanner_result["candidate_count"]:
                continue
            eligible.append(item)
    return eligible


def _document_metadata(state: SourceState) -> dict:
    return {
        "document_id": state.spec.document_id,
        "label": state.spec.label,
        "source_kind": state.spec.source_kind,
        "source_path": state.spec.relative_path,
        "source_url": state.spec.source_url,
        "version": state.spec.version,
        "license": state.spec.license,
        "encoding": state.encoding,
        "source_bytes": len(state.raw),
        "source_lines": state.total_lines,
        "source_sha256": state.sha256,
        "mapped_environments": state.spec.env_map,
        "pilot_interval_count": len(state.pilot_intervals),
    }


def _validate_fixture(
    packets: dict,
    gold: dict,
    states: Sequence[SourceState],
    pilot_ids: set[str],
) -> dict:
    errors: list[str] = []
    packet_units = packets.get("units", [])
    gold_units = gold.get("units", [])
    packet_ids = [unit.get("id") for unit in packet_units]
    gold_ids = [unit.get("id") for unit in gold_units]
    packet_by_id = {unit["id"]: unit for unit in packet_units}
    state_by_id = {state.spec.document_id: state for state in states}

    if len(packet_units) != TOTAL_TARGET or len(gold_units) != TOTAL_TARGET:
        errors.append("fixture does not contain exactly 600 packet/gold units")
    if len(packet_ids) != len(set(packet_ids)):
        errors.append("packet IDs are not unique")
    if len(gold_ids) != len(set(gold_ids)):
        errors.append("gold IDs are not unique")
    if set(packet_ids) != set(gold_ids):
        errors.append("packet/gold ID sets differ")
    if set(gold_ids) & pilot_ids:
        errors.append("release IDs overlap pilot IDs")

    action_counts = Counter(unit.get("action") for unit in gold_units)
    expected_counts = {
        "wrap": AUTO_TARGET,
        "preserve": PRESERVE_TARGET,
        "manual": MANUAL_TARGET,
    }
    if dict(action_counts) != expected_counts:
        errors.append(f"wrong action strata: {dict(action_counts)}")

    banned_unit_keys = {
        "action",
        "env",
        "start_block",
        "end_block",
        "sample_kind",
        "source_path",
        "source_start_line",
        "source_end_line",
        "source_raw_env",
        "source_canonical_env",
        "body_block_ids",
        "boundary_evidence",
        "successor_kind",
        "numbering_conflict",
    }
    leaked = sorted(
        {
            key
            for unit in packet_units
            for key in unit
            if key in banned_unit_keys
        }
    )
    if leaked:
        errors.append(f"answer-bearing unit keys leaked into packet: {leaked}")

    source_env_bodies: dict[str, dict[tuple[str, int, int], str]] = {}
    source_paragraphs: dict[str, dict[tuple[int, int], str]] = {}
    for state in states:
        env_bodies: dict[tuple[str, int, int], str] = {}
        for raw_env, begin_start, begin_end, end_start, end_end in state.doc.env_ranges:
            start_line = offset_to_line(state.doc.line_starts, begin_start)
            end_line = offset_to_line(
                state.doc.line_starts,
                max(begin_start, end_end - 1),
            )
            env_bodies[(raw_env, start_line, end_line)] = state.text[begin_end:end_start]
        source_env_bodies[state.spec.document_id] = env_bodies
        source_paragraphs[state.spec.document_id] = {
            (block.span.start_line, block.span.end_line): block.text
            for block in state.doc.blocks_of_kind("para")
            if not block.in_env
        }

    intervals_by_document: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    scanner_records: list[dict] = []
    conservation_checks = 0
    for answer in gold_units:
        unit_id = answer.get("id")
        packet = packet_by_id.get(unit_id)
        if packet is None:
            continue
        document_id = answer.get("document")
        state = state_by_id.get(document_id)
        if state is None:
            errors.append(f"{unit_id}: unknown gold document")
            continue
        start_line = answer.get("source_start_line")
        end_line = answer.get("source_end_line")
        if not isinstance(start_line, int) or not isinstance(end_line, int):
            errors.append(f"{unit_id}: invalid source interval")
            continue
        expected_id = _unit_id(state.sha256, start_line, end_line)
        if expected_id != unit_id:
            errors.append(f"{unit_id}: ID does not match frozen source interval")
        if _overlaps_any((start_line, end_line), state.pilot_intervals):
            errors.append(f"{unit_id}: source interval overlaps pilot")
        intervals_by_document[document_id].append((start_line, end_line, unit_id))

        env = answer.get("env")
        if not isinstance(env, str):
            errors.append(f"{unit_id}: env must be a string")
        action = answer.get("action")
        if action in {"preserve", "manual"} and env != "":
            errors.append(f"{unit_id}: preserve/manual env must be empty string")
        if action == "wrap" and env not in ALLOWED_ENVS:
            errors.append(f"{unit_id}: invalid automatic environment")

        blocks = packet.get("blocks", [])
        block_ids = [block.get("id") for block in blocks]
        if not block_ids or len(block_ids) != len(set(block_ids)):
            errors.append(f"{unit_id}: invalid packet blocks")
            continue
        if packet.get("focus_anchor") not in block_ids:
            errors.append(f"{unit_id}: focus anchor is absent")
            continue
        canonical_blocks = _canonical_json(blocks)
        if _sha256_text(canonical_blocks) != answer.get("packet_blocks_sha256"):
            errors.append(f"{unit_id}: packet block hash mismatch")
        by_id = {block["id"]: block["text"] for block in blocks}

        if action in {"wrap", "manual"}:
            source_body = source_env_bodies[document_id].get(
                (answer.get("source_raw_env"), start_line, end_line)
            )
            if source_body is None:
                errors.append(f"{unit_id}: source environment cannot be reopened")
            body_ids = answer.get("body_block_ids", [])
            try:
                packet_body = "".join(by_id[block_id] for block_id in body_ids)
            except KeyError:
                errors.append(f"{unit_id}: body block is absent")
                packet_body = ""
            if source_body is not None and packet_body != source_body:
                errors.append(f"{unit_id}: source body was not conserved")
            if _sha256_text(packet_body) != answer.get("source_body_sha256"):
                errors.append(f"{unit_id}: source body hash mismatch")
            if action == "wrap":
                if answer.get("start_block") != packet.get("focus_anchor"):
                    errors.append(f"{unit_id}: automatic start is not focus anchor")
                if answer.get("end_block") != body_ids[-1]:
                    errors.append(f"{unit_id}: automatic end is not complete body")
            else:
                if answer.get("start_block") != packet.get("focus_anchor"):
                    errors.append(f"{unit_id}: manual start is not focus anchor")
                if answer.get("end_block") != packet.get("focus_anchor"):
                    errors.append(f"{unit_id}: manual end is not focus anchor")
            conservation_checks += 1
        elif action == "preserve":
            focus = packet["focus_anchor"]
            source_text = source_paragraphs[document_id].get((start_line, end_line))
            if source_text is None:
                errors.append(f"{unit_id}: top-level source paragraph cannot be reopened")
            elif by_id[focus] != source_text:
                errors.append(f"{unit_id}: preserve focus differs from source")
            if _sha256_text(by_id[focus]) != answer.get("source_text_sha256"):
                errors.append(f"{unit_id}: preserve source hash mismatch")
            if answer.get("start_block") != focus or answer.get("end_block") != focus:
                errors.append(f"{unit_id}: preserve boundaries must equal focus anchor")
            conservation_checks += 1
        else:
            errors.append(f"{unit_id}: unsupported gold action")

        scanner_result = _scanner_focus_result(packet)
        if action == "preserve":
            scanner_passed = scanner_result["candidate_count"] == 0
        else:
            expected_env = answer.get("source_canonical_env")
            scanner_passed = (
                scanner_result["candidate_count"] >= 1
                and expected_env in scanner_result["candidate_env_hints"]
            )
        if not scanner_passed:
            errors.append(f"{unit_id}: production scanner focus validation failed")
        scanner_records.append(
            {
                "id": unit_id,
                "expected_focus_class": (
                    "no-candidate" if action == "preserve" else "candidate"
                ),
                **scanner_result,
                "passed": scanner_passed,
            }
        )

    for document_id, intervals in intervals_by_document.items():
        ordered = sorted(intervals)
        for left, right in zip(ordered, ordered[1:]):
            if _overlaps((left[0], left[1]), (right[0], right[1])):
                errors.append(
                    f"{document_id}: release source intervals overlap: {left[2]} / {right[2]}"
                )

    covered_documents = {unit.get("document") for unit in gold_units}
    if covered_documents != set(EXPECTED_SOURCE_HASHES):
        errors.append(f"document coverage mismatch: {sorted(covered_documents)}")
    for document_id in EXPECTED_SOURCE_HASHES:
        regions = {
            packet_by_id[unit["id"]]["document_region"]
            for unit in gold_units
            if unit.get("document") == document_id
        }
        if regions != set(REGION_NAMES):
            errors.append(f"{document_id}: not all document thirds are covered")

    return {
        "schema": "latexstruct-external-release-validation-v1",
        "passed": not errors,
        "unit_count": len(packet_units),
        "packet_gold_id_sets_equal": set(packet_ids) == set(gold_ids),
        "pilot_id_intersection_count": len(set(gold_ids) & pilot_ids),
        "source_text_hashes_checked": conservation_checks,
        "production_scanner_checks": len(scanner_records),
        "answer_keys_absent_from_packet_units": not leaked,
        "errors": errors,
        "scanner_units": scanner_records,
    }


def _distribution(gold_units: Sequence[dict], packets_by_id: dict[str, dict]) -> dict:
    return {
        "by_action": dict(sorted(Counter(unit["action"] for unit in gold_units).items())),
        "by_document": {
            document_id: dict(
                sorted(
                    Counter(
                        unit["action"]
                        for unit in gold_units
                        if unit["document"] == document_id
                    ).items()
                )
            )
            for document_id in EXPECTED_SOURCE_HASHES
        },
        "by_region": dict(
            sorted(
                Counter(
                    packets_by_id[unit["id"]]["document_region"]
                    for unit in gold_units
                ).items()
            )
        ),
        "by_document_region": {
            document_id: dict(
                sorted(
                    Counter(
                        packets_by_id[unit["id"]]["document_region"]
                        for unit in gold_units
                        if unit["document"] == document_id
                    ).items()
                )
            )
            for document_id in EXPECTED_SOURCE_HASHES
        },
        "automatic_by_environment": dict(
            sorted(
                Counter(
                    unit["env"] for unit in gold_units if unit["action"] == "wrap"
                ).items()
            )
        ),
        "manual_by_source_environment": dict(
            sorted(
                Counter(
                    unit["source_canonical_env"]
                    for unit in gold_units
                    if unit["action"] == "manual"
                ).items()
            )
        ),
        "preserve_by_class": dict(
            sorted(
                Counter(
                    unit["sample_kind"]
                    for unit in gold_units
                    if unit["action"] == "preserve"
                ).items()
            )
        ),
        "by_boundary_evidence": dict(
            sorted(Counter(unit["boundary_evidence"] for unit in gold_units).items())
        ),
    }


def build_fixture(
    corpus_root: Path,
    pilot_gold_path: Path,
) -> tuple[dict, dict, dict]:
    pilot_intervals, pilot_ids = _load_pilot_exclusions(pilot_gold_path)
    states = _load_sources(corpus_root, pilot_intervals, pilot_ids)

    all_structures = [
        item
        for state in states
        for item in _enumerate_structures(state)
    ]
    used_intervals: dict[str, list[tuple[int, int]]] = defaultdict(list)
    auto_pool = [item for item in all_structures if item.disposition == "auto"]
    manual_pool = [item for item in all_structures if item.disposition == "manual"]

    auto_units = _balanced_select(
        auto_pool,
        AUTO_TARGET,
        used_intervals,
        sequence_key=lambda item: (item.env, item.boundary_evidence),
    )
    manual_evidence_rank = {
        "nested-theorem-like-structure": 0,
        "long-window-boundary": 1,
        "proof-boundary-ambiguous-no-hard-end": 2,
        "multiparagraph-boundary-ambiguous": 3,
    }
    manual_units = _balanced_select(
        manual_pool,
        MANUAL_TARGET,
        used_intervals,
        sequence_key=lambda item: (
            manual_evidence_rank.get(item.boundary_evidence, 9),
            item.env,
        ),
    )

    preserve_pool = _eligible_preserves(states, used_intervals)
    preserve_units = _balanced_select(
        preserve_pool,
        PRESERVE_TARGET,
        used_intervals,
        sequence_key=lambda item: (item.negative.class_name,),
    )

    packet_units: list[dict] = []
    gold_units: list[dict] = []
    for item in [*auto_units, *manual_units]:
        packet, answer = _structure_packet_and_gold(item)
        packet_units.append(packet)
        gold_units.append(answer)
    for item in preserve_units:
        packet, answer = _preserve_packet_and_gold(item)
        packet_units.append(packet)
        gold_units.append(answer)

    packet_units.sort(key=lambda unit: (unit["document_id"], unit["id"]))
    gold_units.sort(
        key=lambda unit: (
            unit["document"],
            unit["source_start_line"],
            unit["source_end_line"],
        )
    )
    packet_documents = [
        {
            "document_id": state.spec.document_id,
            "source_kind": state.spec.source_kind,
            "source_sha256": state.sha256,
            "unit_count": sum(
                unit["document_id"] == state.spec.document_id for unit in packet_units
            ),
        }
        for state in states
    ]
    packets = {
        "schema": "latexstruct-external-release-packets-v1",
        "instructions": {
            "task": (
                "Judge only the unit's focus_anchor. Other blocks are source context; a title, "
                "environment, or narrative in context must never be assigned to this unit."
            ),
            "response": (
                "Return exactly one object per unit with id, action, env, start_block, and "
                "end_block. env is always a JSON string, never null."
            ),
            "allowed_actions": ["wrap", "preserve", "manual"],
            "allowed_environments": list(ALLOWED_ENVS),
            "automatic_rule": (
                "Use wrap only when visible evidence uniquely identifies both the environment "
                "and the complete boundary: a single atomic statement, an explicit structural "
                "successor, or (for a proof) a hard end marker/explicit structural successor."
            ),
            "preserve_rule": (
                "Use preserve when the focus is top-level narrative or cross-reference text, "
                "not a bare structure. Use env=\"\" and set both boundaries to focus_anchor."
            ),
            "manual_rule": (
                "Use manual when the focus is a structure candidate but visible evidence cannot "
                "uniquely recover its boundary, including ambiguous multi-paragraph or nested "
                "scope, long windows, and proofs without a hard end. Use env=\"\" and set both "
                "boundaries to focus_anchor."
            ),
            "wrap_boundary_rule": (
                "For wrap, start at focus_anchor and end at the last complete atomic body block; "
                "exclude every context block."
            ),
            "blindness_rule": (
                "Use only this packet. Do not open sources, gold, validation, prior pilot labels, "
                "or predictions."
            ),
        },
        "documents": packet_documents,
        "units": packet_units,
    }
    gold = {
        "schema": "latexstruct-external-release-gold-v1",
        "sampling": {
            "algorithm": "deterministic-document-third-round-robin-v1",
            "seed": 20260819,
            "unit_count": TOTAL_TARGET,
            "automatic_target": AUTO_TARGET,
            "preserve_target": PRESERVE_TARGET,
            "manual_target": MANUAL_TARGET,
            "regions": list(REGION_NAMES),
            "pilot_exclusion": (
                "All 139 pilot IDs and every source-line interval overlapping a pilot unit are "
                "excluded. New unit intervals are mutually line-disjoint within each document."
            ),
            "automatic_policy": (
                "Real mapped source environment; selected outer begin/end removed; canonical "
                "OCR heading added; body conserved exactly; visible boundary uniquely recoverable."
            ),
            "preserve_policy": (
                "Real top-level source narrative/cross-reference focus; exact source text; focus "
                "produces no production-scanner candidate."
            ),
            "manual_policy": (
                "Real mapped source environment with visible boundary ambiguity, nesting, or long "
                "window; no automatic modification is safe. Real ambiguous intervals exceeded "
                "the quota, so no numbering-conflict synthesis was used."
            ),
        },
        "documents": [_document_metadata(state) for state in states],
        "units": gold_units,
    }
    validation = _validate_fixture(packets, gold, states, pilot_ids)
    packets_by_id = {unit["id"]: unit for unit in packet_units}
    validation["pool_counts"] = {
        "automatic_eligible": len(auto_pool),
        "manual_eligible": len(manual_pool),
        "preserve_scanner_clean_eligible": len(preserve_pool),
    }
    validation["distribution"] = _distribution(gold_units, packets_by_id)
    validation["source_hashes"] = dict(EXPECTED_SOURCE_HASHES)
    return packets, gold, validation


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-corpus",
    )
    parser.add_argument(
        "--pilot-gold",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-results" / "blind-gold.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-results",
    )
    args = parser.parse_args()

    try:
        first = build_fixture(args.corpus_root.resolve(), args.pilot_gold.resolve())
        second = build_fixture(args.corpus_root.resolve(), args.pilot_gold.resolve())
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    deterministic = first == second
    packets, gold, validation = first
    validation["deterministic_rebuild_match"] = deterministic
    if not deterministic:
        validation["passed"] = False
        validation["errors"].append("two consecutive in-memory builds differ")

    output_dir = args.output_dir.resolve()
    paths = {
        "packets": output_dir / "release-packets.json",
        "gold": output_dir / "release-gold.json",
        "validation": output_dir / "release-validation.json",
    }
    _write_json(paths["packets"], packets)
    _write_json(paths["gold"], gold)
    _write_json(paths["validation"], validation)
    file_hashes = {
        name: _sha256_bytes(path.read_bytes()) for name, path in paths.items()
    }
    print(
        json.dumps(
            {
                "passed": validation["passed"],
                "unit_count": validation["unit_count"],
                "deterministic_rebuild_match": deterministic,
                "distribution": validation["distribution"],
                "file_sha256": file_hashes,
                "paths": {name: str(path) for name, path in paths.items()},
                "errors": validation["errors"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if validation["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
