#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a read-only structural scan against external LaTeX sources.

This tool deliberately does not assign subjective gold labels.  It records the
scanner's candidate packets, the environments already present in each source,
and an isolated preserve-source check.  The latter reuses the production
pipeline with an explicit empty decision list and the preserve template, so any
text change is a regression in the no-edit path rather than an AI judgement.

Examples
--------
python tools/external_accuracy_experiment.py book=path/to/chapter.tex
python tools/external_accuracy_experiment.py --output result.json a.tex b.tex
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from latexstruct.core.parser import normalize_newlines, parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.scanner import (  # noqa: E402
    THEOREM_LIKE_ENVS,
    _declared_theorem_envs,
    scan,
)
from latexstruct.core.template import build_template_ops  # noqa: E402


def _read_tex(path: Path) -> tuple[bytes, str, str]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw, raw.decode("utf-8-sig"), "utf-8-sig"
    try:
        return raw, raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        # Latin-1 is lossless for arbitrary bytes and keeps the experiment
        # usable for older TeX trees.  The reported encoding makes this visible.
        return raw, raw.decode("latin-1"), "latin-1-fallback"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text_sha256(text: str) -> str:
    return _sha256(text.encode("utf-8"))


def _git_provenance(path: Path) -> dict | None:
    """Read the nearest checkout's HEAD without invoking Git or the network."""
    for root in (path.parent, *path.parents):
        marker = root / ".git"
        if marker.is_dir():
            git_dir = marker
        elif marker.is_file():
            content = marker.read_text(encoding="utf-8", errors="replace").strip()
            if not content.startswith("gitdir:"):
                continue
            git_dir = (root / content.split(":", 1)[1].strip()).resolve()
        else:
            continue
        head_path = git_dir / "HEAD"
        if not head_path.is_file():
            continue
        head = head_path.read_text(encoding="ascii", errors="replace").strip()
        revision = head
        if head.startswith("ref:"):
            ref_name = head.split(":", 1)[1].strip()
            loose_ref = git_dir / ref_name
            if loose_ref.is_file():
                revision = loose_ref.read_text(encoding="ascii", errors="replace").strip()
            else:
                packed = git_dir / "packed-refs"
                if packed.is_file():
                    for line in packed.read_text(encoding="ascii", errors="replace").splitlines():
                        if line and not line.startswith(("#", "^")):
                            value, _, name = line.partition(" ")
                            if name == ref_name:
                                revision = value
                                break
        return {"root": str(root.resolve()), "revision": revision}
    return None


def _candidate_record(candidate) -> dict:
    payload = candidate.payload or {}
    excerpt = str(payload.get("text") or candidate.title_text or "")
    excerpt = " ".join(excerpt.split())[:280]
    return {
        "id": candidate.id,
        "kind": candidate.kind,
        "rule_id": candidate.rule_id,
        "start_line": candidate.span.start_line,
        "end_line": candidate.span.end_line,
        "block_id": candidate.block_id,
        "title_text": candidate.title_text,
        "env_hint": candidate.env_hint,
        "confidence": candidate.confidence,
        "excerpt": excerpt,
        "number": payload.get("number"),
        "section_path": list(payload.get("section_path") or ()),
    }


DEFTHM_CALL_RE = re.compile(r"\\defthm\s*\{([^{}]+)\}")


def _context_theorem_names(paths: Iterable[Path]) -> tuple[set[str], list[dict]]:
    names: set[str] = set()
    records: list[dict] = []
    for path in paths:
        _raw, text, encoding = _read_tex(path)
        masked = parse_latex(text).masked
        current = _declared_theorem_envs(masked)
        current.update(match.group(1).strip() for match in DEFTHM_CALL_RE.finditer(masked))
        current = {name for name in current if name and "\\" not in name and "#" not in name}
        names.update(current)
        records.append(
            {
                "path": str(path.resolve()),
                "encoding": encoding,
                "declared_theorem_names": sorted(current),
            }
        )
    return names, records


def _environment_statistics(doc, contextual_names: set[str]) -> dict:
    all_counts = Counter(item[0] for item in doc.env_ranges)
    declared = set(_declared_theorem_envs(doc.masked))
    theorem_names = (
        set(THEOREM_LIKE_ENVS)
        | {"proof", "solution"}
        | declared
        | contextual_names
    )
    theorem_counts = {
        name: count
        for name, count in sorted(all_counts.items())
        if name.rstrip("*") in theorem_names or name in theorem_names
    }
    return {
        "total": sum(all_counts.values()),
        "by_name": dict(sorted(all_counts.items())),
        "declared_theorem_names": sorted(declared),
        "context_declared_theorem_names": sorted(contextual_names),
        "theorem_like_total": sum(theorem_counts.values()),
        "theorem_like_by_name": theorem_counts,
        "unbalanced_begins": list(doc.unbalanced_begins),
        "unbalanced_ends": list(doc.unbalanced_ends),
    }


def inspect_source(label: str, path: Path, context_paths: Iterable[Path] = ()) -> dict:
    raw, text, encoding = _read_tex(path)
    doc = parse_latex(text)
    scan_result = scan(doc)
    contextual_names, context_records = _context_theorem_names(context_paths)

    template_ops, template_notes = build_template_ops(text, template="")
    preserved = run_pipeline(
        text,
        mode="rule",
        template="",
        decisions_override=[],
        ambiguous_override=[],
        ai_notes_override=[],
        compile_check=False,
    )
    exact_text_equal = preserved.export_text == text
    normalized_equal = normalize_newlines(preserved.export_text) == normalize_newlines(text)

    return {
        "label": label,
        "path": str(path.resolve()),
        "encoding": encoding,
        "source": {
            "bytes": len(raw),
            "lines": len(text.splitlines()),
            "sha256_bytes": _sha256(raw),
            "sha256_text_utf8": _text_sha256(text),
            "git": _git_provenance(path),
        },
        "document": {
            "blocks": len(doc.blocks),
            "paragraphs": len(doc.blocks_of_kind("para")),
            "sections": len(doc.sections),
            "display_spans": len(doc.display_spans),
            "has_preamble": doc.preamble_span is not None,
        },
        "theorem_context": context_records,
        "environments": _environment_statistics(doc, contextual_names),
        "scan": {
            "candidate_total": len(scan_result.candidates),
            "candidate_by_kind": dict(sorted(scan_result.stats.items())),
            "skipped_total": len(scan_result.skipped),
            "skipped": scan_result.skipped,
            "candidates": [_candidate_record(item) for item in scan_result.candidates],
        },
        "preserve_source": {
            "passed": bool(
                preserved.ok
                and not template_ops
                and not preserved.applied
                and exact_text_equal
            ),
            "pipeline_ok": preserved.ok,
            "template_operation_count": len(template_ops),
            "template_notes": template_notes,
            "applied_patch_count": len(preserved.applied),
            "rejected_patch_count": len(preserved.rejected),
            "exact_text_equal": exact_text_equal,
            "normalized_text_equal": normalized_equal,
            "result_sha256_text_utf8": _text_sha256(preserved.export_text),
            "error": preserved.error,
        },
    }


def _parse_inputs(values: Iterable[str]) -> list[tuple[str, Path]]:
    parsed: list[tuple[str, Path]] = []
    labels: set[str] = set()
    for value in values:
        if "=" in value:
            label, raw_path = value.split("=", 1)
            label = label.strip()
        else:
            raw_path = value
            label = Path(value).stem
        if not label:
            raise ValueError(f"empty label in input: {value!r}")
        if label in labels:
            raise ValueError(f"duplicate label: {label}")
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(path)
        labels.add(label)
        parsed.append((label, path))
    return parsed


def _parse_contexts(values: Iterable[str], labels: set[str]) -> dict[str, list[Path]]:
    contexts: dict[str, list[Path]] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"context must use LABEL=TEX syntax: {value!r}")
        label, raw_path = value.split("=", 1)
        label = label.strip()
        if label not in labels:
            raise ValueError(f"context refers to unknown source label: {label}")
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(path)
        contexts.setdefault(label, []).append(path)
    return contexts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "sources",
        nargs="+",
        metavar="[LABEL=]TEX",
        help="one or more TeX files, optionally prefixed with a stable label",
    )
    parser.add_argument("--output", type=Path, help="write combined JSON to this path")
    parser.add_argument(
        "--theorem-context",
        action="append",
        default=[],
        metavar="LABEL=TEX",
        help="optional preamble/macro file used only to classify existing custom environments",
    )
    args = parser.parse_args()

    try:
        sources = _parse_inputs(args.sources)
        contexts = _parse_contexts(args.theorem_context, {label for label, _path in sources})
        records = [
            inspect_source(label, path, contexts.get(label, ()))
            for label, path in sources
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))

    payload = {
        "schema": "latexstruct-external-accuracy-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": {
            "gold_labels": "none",
            "scanner": "production read-only scan",
            "preserve_source": (
                "production pipeline with preserve template and an explicit empty decision list"
            ),
        },
        "summary": {
            "source_count": len(records),
            "candidate_total": sum(item["scan"]["candidate_total"] for item in records),
            "existing_environment_total": sum(item["environments"]["total"] for item in records),
            "preserve_passed": sum(item["preserve_source"]["passed"] for item in records),
            "preserve_failed": sum(not item["preserve_source"]["passed"] for item in records),
        },
        "sources": records,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if payload["summary"]["preserve_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
