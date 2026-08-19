#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify and inventory the independent external corpus v2.

This tool deliberately stops before fixture or label generation.  It reads only
the six newly downloaded public sources under ``../work/external-corpus-v2``,
verifies their frozen provenance, inventories mapped TeX environments, and
writes a capacity/provenance manifest.

Default invocation (from the repository root)::

    python tools/preflight_external_corpus_v2.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from latexstruct.core.parser import normalize_newlines, offset_to_line, parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402


SCHEMA = "latexstruct-external-corpus-preflight-v2"
TREE_HASH_ALGORITHM = (
    "sha256 over b'latexstruct-tree-sha256-v1\\0', then for each sorted POSIX "
    "relative path: uint64be(path_bytes_len), path_bytes, uint64be(file_len), file_bytes"
)
CANONICAL_ENVIRONMENTS = (
    "theorem",
    "lemma",
    "definition",
    "proposition",
    "corollary",
    "remark",
    "example",
    "proof",
)
TARGETS = {"auto": 300, "preserve": 300, "manual": 120}
SECOND_ROUND_TARGETS = dict(TARGETS)
MAX_BODY_CHARS = 8_000
MAX_ATOMIC_BLOCKS = 12
MAX_PRESERVE_CHARS = 6_000

HARD_PROOF_END_RE = re.compile(
    r"(?:\\qed(?:here)?|\\(?:Box|square|blacksquare)|∎)"
    r"(?:\s|[}\])$.,;:])*\Z",
    re.I,
)
STRUCTURAL_SUCCESSOR_RE = re.compile(
    r"\\(?:part|chapter|section|subsection|subsubsection|paragraph)\*?\s*\{"
    r"|\\begin\s*\{(?P<env>[^{}]+)\}",
)
COMMENT_OR_BLANK_RE = re.compile(r"[ \t]*(?:%[^\n]*)?(?:\n|\Z)")
STRUCTURAL_START_RE = re.compile(
    r"^\\(?:part|chapter|section|subsection|subsubsection|paragraph|"
    r"begin|end|bibliography|printbibliography|maketitle|tableofcontents)\b"
)
XREF_RE = re.compile(
    r"\\(?:[Cc]ref|ref|autoref|eqref|pageref|cite\w*)\b"
    r"|\b(?:Theorem|Lemma|Definition|Proposition|Corollary|Remark|Example|Proof)\b"
)
BEGIN_RE = re.compile(r"\\begin\s*\{([^{}]+)\}")


SOURCES: tuple[dict, ...] = (
    {
        "id": "V2B01",
        "slug": "openlogic",
        "kind": "book",
        "title": "The Open Logic Text (complete build)",
        "authors": ["The Open Logic Project"],
        "root": "books/openlogic",
        "official_landing_url": "https://github.com/OpenLogicProject/OpenLogic",
        "retrieval_url": "https://github.com/OpenLogicProject/OpenLogic.git",
        "pin": {
            "type": "git-commit",
            "commit": "1e960beff9ed7835bf3e3f1335e21af3439cd107",
        },
        "license": {
            "spdx": "CC-BY-4.0",
            "file": "LICENSE.md",
            "url": "https://creativecommons.org/licenses/by/4.0/",
            "evidence": "Repository LICENSE.md and README.md",
        },
        "entrypoints": ["open-logic-complete.tex", "content/content.tex"],
        "tex_globs": ["content/**/*.tex"],
        "environment_map": {
            "thm": "theorem",
            "lem": "lemma",
            "defn": "definition",
            "prop": "proposition",
            "cor": "corollary",
            "rem": "remark",
            "ex": "example",
            "proof": "proof",
        },
    },
    {
        "id": "V2B02",
        "slug": "basic-analysis",
        "kind": "book",
        "title": "Basic Analysis: Introduction to Real Analysis, Volumes I and II",
        "authors": ["Jiří Lebl"],
        "root": "books/basic-analysis",
        "official_landing_url": "https://github.com/jirilebl/ra",
        "retrieval_url": "https://github.com/jirilebl/ra.git",
        "pin": {
            "type": "git-commit",
            "commit": "e21ec524ca7d54f800c693b948020c188d21d01f",
        },
        "license": {
            "spdx": "CC-BY-SA-4.0",
            "file": "LICENSE.md",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "evidence": (
                "Repository LICENSE.md is dual CC-BY-NC-SA-4.0 / CC-BY-SA-4.0; "
                "this corpus elects the CC-BY-SA-4.0 option"
            ),
        },
        "entrypoints": ["realanal.tex", "realanal2.tex", "realanal12.tex"],
        "tex_globs": [
            "realanal12.tex",
            "frag-vol2-intro.tex",
            "ch-vol1-intro.tex",
            "ch-*.tex",
        ],
        "environment_map": {
            "thm": "theorem",
            "lemma": "lemma",
            "defn": "definition",
            "prop": "proposition",
            "cor": "corollary",
            "remark": "remark",
            "example": "example",
            "proof": "proof",
        },
    },
    {
        "id": "V2B03",
        "slug": "linear-algebra",
        "kind": "book",
        "title": "Linear Algebra",
        "authors": ["Jim Siefken and contributors"],
        "root": "books/linear-algebra",
        "official_landing_url": "https://github.com/siefkenj/LinearAlgebra",
        "retrieval_url": "https://github.com/siefkenj/LinearAlgebra.git",
        "pin": {
            "type": "git-commit",
            "commit": "297f680f6d1b199ff5a664b9a43a080f09ed92e9",
        },
        "license": {
            "spdx": "CC-BY-SA-4.0",
            "file": "LICENSE",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "evidence": "Repository LICENSE",
        },
        "entrypoints": ["src/LinearAlgebra.tex"],
        "tex_globs": ["src/LinearAlgebra.tex", "src/chapters/**/*.tex"],
        "environment_map": {
            "theorem": "theorem",
            "definition": "definition",
            "numberlessdefinition": "definition",
            "example": "example",
            "proof": "proof",
        },
    },
    {
        "id": "V2P01",
        "slug": "2003.01491v5",
        "kind": "paper",
        "title": "A Cubical Language for Bishop Sets",
        "authors": ["Jonathan Sterling", "Carlo Angiuli", "Daniel Gratzer"],
        "root": "papers/2003.01491v5",
        "official_landing_url": "https://arxiv.org/abs/2003.01491v5",
        "retrieval_url": "https://arxiv.org/e-print/2003.01491v5",
        "pin": {
            "type": "arxiv-version",
            "version": "2003.01491v5",
            "archive": "source.tar",
            "archive_sha256": "1abc19d0a56b2a8e85050b9f184a7f5fb29b171717a64a4195a4f94c0a355c9e",
        },
        "license": {
            "spdx": "CC-BY-4.0",
            "url": "https://creativecommons.org/licenses/by/4.0/",
            "evidence": "Versioned arXiv abstract page license link",
        },
        "entrypoints": ["src/main.tex"],
        "tex_globs": ["src/main.tex"],
        "environment_map": {
            "thm": "theorem",
            "thmC": "theorem",
            "lem": "lemma",
            "lemC": "lemma",
            "defi": "definition",
            "defiC": "definition",
            "prop": "proposition",
            "propC": "proposition",
            "cor": "corollary",
            "rem": "remark",
            "exa": "example",
            "proof": "proof",
        },
    },
    {
        "id": "V2P02",
        "slug": "2305.18519v2",
        "kind": "paper",
        "title": "Quantum chi-squared tomography and mutual information testing",
        "authors": ["Steven T. Flammia", "Ryan O'Donnell"],
        "root": "papers/2305.18519v2",
        "official_landing_url": "https://arxiv.org/abs/2305.18519v2",
        "retrieval_url": "https://arxiv.org/e-print/2305.18519v2",
        "pin": {
            "type": "arxiv-version",
            "version": "2305.18519v2",
            "archive": "source.tar",
            "archive_sha256": "70808ca533d192884666e3de9f62d7a554e2ec77b90db196d450df257dcf7199",
        },
        "license": {
            "spdx": "CC-BY-SA-4.0",
            "url": "https://creativecommons.org/licenses/by-sa/4.0/",
            "evidence": "Versioned arXiv abstract page license link",
        },
        "entrypoints": ["src/main.tex"],
        "tex_globs": ["src/main.tex"],
        "environment_map": {
            "theorem": "theorem",
            "lemma": "lemma",
            "definition": "definition",
            "proposition": "proposition",
            "corollary": "corollary",
            "remark": "remark",
            "example": "example",
            "proof": "proof",
        },
    },
    {
        "id": "V2P03",
        "slug": "2104.14445v5",
        "kind": "paper",
        "title": "Trakhtenbrot's Theorem in Coq: Finite Model Theory through the Constructive Lens",
        "authors": ["Dominik Kirst", "Dominique Larchey-Wendling"],
        "root": "papers/2104.14445v5",
        "official_landing_url": "https://arxiv.org/abs/2104.14445v5",
        "retrieval_url": "https://arxiv.org/e-print/2104.14445v5",
        "pin": {
            "type": "arxiv-version",
            "version": "2104.14445v5",
            "archive": "source.tar",
            "archive_sha256": "dc89f9e9438de9f3dd0e51b6bb50bea97d5c89cc89c449abeeb5cfa9f337eb74",
        },
        "license": {
            "spdx": "CC-BY-4.0",
            "url": "https://creativecommons.org/licenses/by/4.0/",
            "evidence": "Versioned arXiv abstract page license link",
        },
        "entrypoints": ["src/paper.tex"],
        "tex_globs": ["src/paper.tex"],
        "environment_map": {
            "theorem": "theorem",
            "lemma": "lemma",
            "definition": "definition",
            "corollary": "corollary",
            "proof": "proof",
        },
    },
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path, files: Iterable[Path]) -> str:
    digest = hashlib.sha256(b"latexstruct-tree-sha256-v1\0")
    unique = sorted({path.resolve() for path in files}, key=lambda p: p.relative_to(root).as_posix())
    for path in unique:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _run_git(root: Path, *args: str, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
    )
    return completed.stdout if binary else completed.stdout.strip()


def _decode_source(path: Path) -> tuple[bytes, str, str]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw, normalize_newlines(raw.decode("utf-8-sig")), "utf-8-sig"
    try:
        return raw, normalize_newlines(raw.decode("utf-8")), "utf-8"
    except UnicodeDecodeError:
        return raw, normalize_newlines(raw.decode("latin-1")), "latin-1-fallback"


def _resolve_tex_scope(root: Path, patterns: Sequence[str]) -> list[Path]:
    files: set[Path] = set()
    for pattern in patterns:
        files.update(path.resolve() for path in root.glob(pattern) if path.is_file())
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _verify_git_source(spec: dict, root: Path) -> dict:
    expected = spec["pin"]["commit"]
    commit = str(_run_git(root, "rev-parse", "HEAD"))
    if commit != expected:
        raise ValueError(f"{spec['id']}: git HEAD {commit} != frozen commit {expected}")
    status = str(_run_git(root, "status", "--porcelain=v1", "--untracked-files=all"))
    if status:
        raise ValueError(f"{spec['id']}: source clone is not clean")
    remote = str(_run_git(root, "remote", "get-url", "origin"))
    expected_remote = spec["retrieval_url"]
    if remote.rstrip("/") != expected_remote.rstrip("/"):
        raise ValueError(f"{spec['id']}: origin {remote!r} != {expected_remote!r}")
    tracked_raw = bytes(_run_git(root, "ls-files", "-z", binary=True))
    tracked_relpaths = [item.decode("utf-8") for item in tracked_raw.split(b"\0") if item]
    tracked_paths = [root / PurePosixPath(item) for item in tracked_relpaths]
    # A Gitlink (mode 160000) appears in ``git ls-files`` as a path but is a
    # directory in the checkout.  The frozen superproject tree/archive already
    # authenticates the Gitlink OID; only regular tracked files participate in
    # the checked-out byte-tree digest.
    tracked_files = [path for path in tracked_paths if path.is_file()]
    gitlink_paths = [
        path.relative_to(root).as_posix() for path in tracked_paths if path.is_dir()
    ]
    missing = [path for path in tracked_paths if not path.exists()]
    if missing:
        raise ValueError(f"{spec['id']}: tracked files missing from checkout: {missing[:3]}")
    archive = bytes(_run_git(root, "archive", "--format=tar", "HEAD", binary=True))
    branch = str(_run_git(root, "branch", "--show-current"))
    if branch:
        raise ValueError(f"{spec['id']}: checkout must be detached at the frozen commit")
    return {
        "verified": True,
        "origin": remote,
        "commit": commit,
        "commit_date": str(_run_git(root, "show", "-s", "--format=%cI", "HEAD")),
        "git_tree_oid": str(_run_git(root, "rev-parse", "HEAD^{tree}")),
        "git_archive_sha256": _sha256_bytes(archive),
        "working_tree_sha256": _tree_sha256(root, tracked_files),
        "tracked_entry_count": len(tracked_paths),
        "tracked_file_count": len(tracked_files),
        "tracked_bytes": sum(path.stat().st_size for path in tracked_files),
        "gitlink_paths": gitlink_paths,
        "branch": branch,
        "detached_head": not branch,
        "clean_checkout": True,
    }


def _safe_tar_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive member path: {name!r}")
    return path


def _verify_arxiv_source(spec: dict, root: Path) -> dict:
    pin = spec["pin"]
    archive_path = root / pin["archive"]
    actual_archive_sha = _sha256_file(archive_path)
    if actual_archive_sha != pin["archive_sha256"]:
        raise ValueError(
            f"{spec['id']}: archive SHA256 {actual_archive_sha} != {pin['archive_sha256']}"
        )
    extracted_root = root / "src"
    expected_files: dict[str, tuple[int, str]] = {}
    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        for member in members:
            relative = _safe_tar_member_path(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"{spec['id']}: unsupported non-file tar member {member.name!r}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError(f"{spec['id']}: cannot read tar member {member.name!r}")
            data = handle.read()
            expected_files[relative.as_posix()] = (len(data), _sha256_bytes(data))
    extracted_files = sorted(path for path in extracted_root.rglob("*") if path.is_file())
    actual_names = {path.relative_to(extracted_root).as_posix() for path in extracted_files}
    if actual_names != set(expected_files):
        missing = sorted(set(expected_files) - actual_names)
        extra = sorted(actual_names - set(expected_files))
        raise ValueError(
            f"{spec['id']}: extracted tree differs from archive; missing={missing[:3]}, extra={extra[:3]}"
        )
    for path in extracted_files:
        relative = path.relative_to(extracted_root).as_posix()
        expected_size, expected_sha = expected_files[relative]
        if path.stat().st_size != expected_size or _sha256_file(path) != expected_sha:
            raise ValueError(f"{spec['id']}: extracted member mismatch: {relative}")
    return {
        "verified": True,
        "version": pin["version"],
        "archive_path": pin["archive"],
        "archive_sha256": actual_archive_sha,
        "archive_bytes": archive_path.stat().st_size,
        "archive_member_count": len(expected_files),
        "extracted_tree_sha256": _tree_sha256(extracted_root, extracted_files),
        "extracted_file_count": len(extracted_files),
        "extracted_bytes": sum(path.stat().st_size for path in extracted_files),
        "safe_paths_verified": True,
        "extraction_matches_archive": True,
    }


def _atomic_count(body: str) -> int:
    return sum(1 for piece in re.split(r"\n[ \t]*\n", body) if piece.strip())


def _skip_comments_and_blank(text: str, start: int) -> int:
    cursor = start
    while cursor < len(text):
        match = COMMENT_OR_BLANK_RE.match(text, cursor)
        if match is None or match.end() == cursor:
            break
        cursor = match.end()
    return cursor


def _has_structural_successor(text: str, end_end: int, env_map: dict[str, str]) -> bool:
    cursor = _skip_comments_and_blank(text, end_end)
    match = STRUCTURAL_SUCCESSOR_RE.match(text, cursor)
    if match is None:
        return False
    successor_env = (match.groupdict().get("env") or "").strip()
    return not successor_env or successor_env in env_map


def _maximum_nonoverlap(candidates: Sequence[dict]) -> int:
    by_file: dict[str, list[dict]] = defaultdict(list)
    for item in candidates:
        by_file[item["file"]].append(item)
    selected = 0
    for items in by_file.values():
        last_end = -1
        for item in sorted(items, key=lambda value: (value["offset_end"], value["offset_start"])):
            if item["offset_start"] >= last_end:
                selected += 1
                last_end = item["offset_end"]
    return selected


def _overlaps_span(start_line: int, end_line: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(start_line <= right and left <= end_line for left, right in spans)


def _scan_tex_source(spec: dict, root: Path, tex_files: Sequence[Path]) -> dict:
    env_map = spec["environment_map"]
    if not set(env_map.values()).issubset(CANONICAL_ENVIRONMENTS):
        raise ValueError(f"{spec['id']}: environment map contains a non-canonical target")

    raw_environment_counts: Counter[str] = Counter()
    mapped_raw_counts: Counter[str] = Counter()
    canonical_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()
    evidence_counts: Counter[str] = Counter()
    preserve_class_counts: Counter[str] = Counter()
    encoding_counts: Counter[str] = Counter()
    auto_candidates: list[dict] = []
    manual_candidates: list[dict] = []
    preserve_candidates: list[dict] = []
    parse_failures: list[dict] = []
    total_lines = 0

    for path in tex_files:
        relative = path.relative_to(root).as_posix()
        _raw, text, encoding = _decode_source(path)
        encoding_counts[encoding] += 1
        total_lines += text.count("\n") + 1
        raw_environment_counts.update(match.group(1).strip() for match in BEGIN_RE.finditer(text))
        try:
            doc = parse_latex(text)
            scanned = scan(doc)
        except Exception as exc:  # pragma: no cover - reports third-party source failures
            parse_failures.append({"file": relative, "error": f"{type(exc).__name__}: {exc}"})
            continue

        preamble_end = doc.preamble_span.end_line if doc.preamble_span else 0
        targets: list[tuple[str, str, int, int, int, int, int, int]] = []
        for raw_env, begin_start, begin_end, end_start, end_end in doc.env_ranges:
            if raw_env not in env_map:
                continue
            start_line = offset_to_line(doc.line_starts, begin_start)
            end_line = offset_to_line(doc.line_starts, max(begin_start, end_end - 1))
            if start_line <= preamble_end:
                continue
            targets.append(
                (
                    raw_env,
                    env_map[raw_env],
                    begin_start,
                    begin_end,
                    end_start,
                    end_end,
                    start_line,
                    end_line,
                )
            )

        for index, target in enumerate(targets):
            raw_env, canonical, begin_start, begin_end, end_start, end_end, start_line, end_line = target
            body = text[begin_end:end_start]
            if not body.strip():
                continue
            nested_target = any(
                index != other_index
                and (
                    begin_start < other[2] < other[5] <= end_end
                    or other[2] < begin_start < end_end <= other[5]
                )
                for other_index, other in enumerate(targets)
            )
            atomic_count = _atomic_count(body)
            successor = _has_structural_successor(text, end_end, env_map)
            hard_proof_end = bool(HARD_PROOF_END_RE.search(body.rstrip()))
            if nested_target:
                disposition, evidence = "manual", "nested-mapped-structure"
            elif len(body) > MAX_BODY_CHARS or atomic_count > MAX_ATOMIC_BLOCKS:
                disposition, evidence = "manual", "long-window-boundary"
            elif canonical == "proof":
                if hard_proof_end:
                    disposition, evidence = "auto", "proof-hard-end-marker"
                elif successor:
                    disposition, evidence = "auto", "proof-explicit-structural-successor"
                else:
                    disposition, evidence = "manual", "proof-boundary-ambiguous-no-hard-end"
            elif atomic_count == 1:
                disposition, evidence = "auto", "single-atomic-statement"
            elif successor:
                disposition, evidence = "auto", "explicit-structural-successor"
            else:
                disposition, evidence = "manual", "multiparagraph-boundary-ambiguous"

            mapped_raw_counts[raw_env] += 1
            canonical_counts[canonical] += 1
            disposition_counts[disposition] += 1
            evidence_counts[evidence] += 1
            candidate = {
                "file": relative,
                "offset_start": begin_start,
                "offset_end": end_end,
                "start_line": start_line,
                "end_line": end_line,
                "raw_env": raw_env,
                "canonical_env": canonical,
            }
            (auto_candidates if disposition == "auto" else manual_candidates).append(candidate)

        scanner_spans = [
            (candidate.span.start_line, candidate.span.end_line) for candidate in scanned.candidates
        ]
        for block in doc.blocks_of_kind("para"):
            stripped = block.text.strip()
            if block.in_env or block.span.start_line <= preamble_end:
                continue
            if len(stripped) < 50 or len(block.text) > MAX_PRESERVE_CHARS:
                continue
            if "\\begin{" in block.text or "\\end{" in block.text:
                continue
            if STRUCTURAL_START_RE.match(stripped):
                continue
            if stripped.startswith(("%", "\\[", "$$", "\\item", "\\label")):
                continue
            if _overlaps_span(block.span.start_line, block.span.end_line, scanner_spans):
                continue
            class_name = "cross-reference" if XREF_RE.search(block.text) else "narrative"
            preserve_class_counts[class_name] += 1
            preserve_candidates.append(
                {
                    "file": relative,
                    "offset_start": block.span.start_off,
                    "offset_end": block.span.end_off,
                    "start_line": block.span.start_line,
                    "end_line": block.span.end_line,
                    "class": class_name,
                }
            )

    if parse_failures:
        raise ValueError(f"{spec['id']}: TeX parse failures: {parse_failures[:3]}")

    auto_nonoverlap = _maximum_nonoverlap(auto_candidates)
    manual_nonoverlap = _maximum_nonoverlap(manual_candidates)
    preserve_nonoverlap = _maximum_nonoverlap(preserve_candidates)
    return {
        "tex_file_count": len(tex_files),
        "tex_bytes": sum(path.stat().st_size for path in tex_files),
        "tex_lines": total_lines,
        "tex_scope_sha256": _tree_sha256(root, tex_files),
        "encodings": dict(sorted(encoding_counts.items())),
        "environment_map": dict(sorted(env_map.items())),
        "raw_environment_counts": dict(raw_environment_counts.most_common()),
        "mapped_raw_environment_counts": dict(mapped_raw_counts.most_common()),
        "canonical_environment_counts": dict(canonical_counts.most_common()),
        "classification_evidence_counts": dict(evidence_counts.most_common()),
        "preserve_class_counts": dict(preserve_class_counts.most_common()),
        "capacity": {
            "auto_raw": disposition_counts["auto"],
            "auto_nonoverlap": auto_nonoverlap,
            "preserve_raw": len(preserve_candidates),
            "preserve_nonoverlap": preserve_nonoverlap,
            "manual_raw": disposition_counts["manual"],
            "manual_nonoverlap": manual_nonoverlap,
        },
        "preflight_policy": {
            "auto": (
                "Mapped real environment with non-empty body and production-style visible "
                "boundary evidence; nested/long/ambiguous structures excluded."
            ),
            "preserve": (
                "Top-level 50-6000 character narrative/cross-reference paragraph that does not "
                "overlap a production-scanner candidate."
            ),
            "manual": (
                "Mapped real environment with nesting, long window, multi-paragraph ambiguity, "
                "or proof lacking a hard end/explicit mapped successor."
            ),
            "warning": (
                "Capacity inventory only. No interval has been sampled or labeled, and final "
                "packet-level eligibility still requires blind fixture validation."
            ),
        },
    }


def _entrypoint_manifest(root: Path, entrypoints: Sequence[str]) -> list[dict]:
    result: list[dict] = []
    for relative in entrypoints:
        path = root / PurePosixPath(relative)
        if not path.is_file():
            raise ValueError(f"missing TeX entrypoint: {path}")
        result.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return result


def _source_manifest(corpus_root: Path, spec: dict) -> dict:
    root = corpus_root / PurePosixPath(spec["root"])
    if not root.is_dir():
        raise ValueError(f"missing source root: {root}")
    provenance = (
        _verify_git_source(spec, root)
        if spec["pin"]["type"] == "git-commit"
        else _verify_arxiv_source(spec, root)
    )
    license_payload = dict(spec["license"])
    license_file = license_payload.get("file")
    if license_file:
        path = root / PurePosixPath(license_file)
        if not path.is_file():
            raise ValueError(f"{spec['id']}: missing license file {license_file}")
        license_payload["file_sha256"] = _sha256_file(path)
        license_payload["file_bytes"] = path.stat().st_size
    tex_files = _resolve_tex_scope(root, spec["tex_globs"])
    if not tex_files:
        raise ValueError(f"{spec['id']}: empty TeX scope")
    return {
        "id": spec["id"],
        "slug": spec["slug"],
        "kind": spec["kind"],
        "title": spec["title"],
        "authors": spec["authors"],
        "local_root": spec["root"],
        "official_landing_url": spec["official_landing_url"],
        "retrieval_url": spec["retrieval_url"],
        "pin": spec["pin"],
        "provenance": provenance,
        "license": license_payload,
        "entrypoints": _entrypoint_manifest(root, spec["entrypoints"]),
        "tex_globs": spec["tex_globs"],
        "inventory": _scan_tex_source(spec, root, tex_files),
    }


def _capacity_summary(sources: Sequence[dict]) -> dict:
    pools = {
        lane: sum(source["inventory"]["capacity"][f"{lane}_nonoverlap"] for source in sources)
        for lane in TARGETS
    }
    v2_shortfall = {lane: max(0, TARGETS[lane] - pools[lane]) for lane in TARGETS}
    after_v2 = {lane: max(0, pools[lane] - TARGETS[lane]) for lane in TARGETS}
    v3_shortfall = {
        lane: max(0, SECOND_ROUND_TARGETS[lane] - after_v2[lane]) for lane in TARGETS
    }
    return {
        "nonoverlap_pools": pools,
        "v2_targets": TARGETS,
        "v2_shortfall": v2_shortfall,
        "v2_pass": not any(v2_shortfall.values()),
        "remaining_after_one_v2_round": after_v2,
        "independent_v3_reserve_targets": SECOND_ROUND_TARGETS,
        "independent_v3_reserve_shortfall": v3_shortfall,
        "independent_v3_reserve_pass": not any(v3_shortfall.values()),
        "two_round_targets": {lane: TARGETS[lane] + SECOND_ROUND_TARGETS[lane] for lane in TARGETS},
        "two_round_pass": not any(v2_shortfall.values()) and not any(v3_shortfall.values()),
        "interpretation": (
            "Counts use maximum non-overlapping intervals within each TeX file. The v3 reserve "
            "is the arithmetic remainder after withholding one full v2 quota; no units are "
            "selected and no labels are generated."
        ),
    }


def build_manifest(corpus_root: Path) -> dict:
    sources = [_source_manifest(corpus_root, spec) for spec in SOURCES]
    capacity = _capacity_summary(sources)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "retrieved_on": "2026-08-19",
        "corpus_root": str(corpus_root.resolve()),
        "purpose": (
            "Independent blind-test corpus v2 provenance, environment mapping, and capacity "
            "preflight only."
        ),
        "exclusions": [
            "No prior gold file was read.",
            "No prior prediction file was read.",
            "No prior error-analysis file was read.",
            "No final gold, packet, fixture, or per-unit label was generated.",
        ],
        "canonical_environments": list(CANONICAL_ENVIRONMENTS),
        "integrity": {
            "hash": "SHA-256",
            "tree_hash_algorithm": TREE_HASH_ALGORITHM,
            "git": (
                "Frozen full commit, clean checkout, origin URL, Git tree OID, deterministic "
                "git-archive SHA256, and checked-out tracked-tree SHA256."
            ),
            "arxiv": (
                "Versioned official e-print URL, raw archive SHA256, safe member paths, exact "
                "archive/extraction byte comparison, and extracted-tree SHA256."
            ),
        },
        "sources": sources,
        "capacity": capacity,
        "status": {
            "provenance_verified": all(source["provenance"]["verified"] for source in sources),
            "license_evidence_present": all(bool(source["license"]["evidence"]) for source in sources),
            "entrypoints_present": all(bool(source["entrypoints"]) for source in sources),
            "v2_capacity_pass": capacity["v2_pass"],
            "v3_reserve_pass": capacity["independent_v3_reserve_pass"],
            "ready_for_later_blind_sampling": capacity["v2_pass"],
            "gold_generated": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=REPO_ROOT.parent / "work" / "external-corpus-v2",
    )
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--no-write", action="store_true", help="verify and print summary only")
    args = parser.parse_args()

    corpus_root = args.corpus_root.resolve()
    manifest_path = (args.manifest or corpus_root / "manifest.json").resolve()
    manifest = build_manifest(corpus_root)
    if not args.no_write:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    summary = {
        "manifest": None if args.no_write else str(manifest_path),
        "sources": len(manifest["sources"]),
        "capacity": manifest["capacity"],
        "status": manifest["status"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if not manifest["status"]["ready_for_later_blind_sampling"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
