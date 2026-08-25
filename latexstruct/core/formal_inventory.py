# -*- coding: utf-8 -*-
"""Fail-closed, source-derived inventory of formal mathematical structure.

The ordinary scanner is intentionally precise and patch-oriented.  This module
has a different job: account for every strong formal heading and every existing
formal environment before the pipeline computes candidate coverage.  Inventory
items are immutable, have stable source-derived identities, and never contain a
model-generated span or environment name.

``inventory_document`` is the stable public entry point.  It reports naked
headings as ``missing`` findings and audits existing theorem/proof/custom
environments for high-confidence wrong-kind, over-wide, and duplicate evidence.
Ambiguous constructs are retained as findings for manual review; this module
does not manufacture an automatic repair.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Iterable, Optional

from .parser import Document, PROTECTED_ENVS


FORMAL_ENVIRONMENTS = frozenset({
    "theorem", "lemma", "proposition", "corollary", "definition",
    "remark", "example", "conjecture", "problem", "question", "claim",
    "fact", "observation", "note", "exercise", "proof", "solution",
})
BOX_ENVIRONMENTS = frozenset({
    "tcolorbox", "mdframed", "framed", "quote", "quotation", "lsframedinset",
})
_NON_PROSE_ENVIRONMENTS = frozenset({
    "math", "displaymath", "equation", "equation*", "align", "align*",
    "alignat", "alignat*", "flalign", "flalign*", "gather", "gather*",
    "multline", "multline*", "eqnarray", "eqnarray*", "split", "aligned",
    "alignedat", "gathered", "cases", "array", "matrix", "pmatrix",
    "bmatrix", "Bmatrix", "vmatrix", "Vmatrix", "smallmatrix", "tabular",
    "tabular*", "tabularx", "tabulary", "longtable", "longtabu", "tblr",
    "talltblr", "longtblr", "thebibliography", "figure", "table",
    "algorithm", "algorithmic",
})

_ENGLISH_ENV = {
    "definition": "definition",
    "theorem": "theorem",
    "lemma": "lemma",
    "proposition": "proposition",
    "corollary": "corollary",
    "remark": "remark",
    "example": "example",
    "conjecture": "conjecture",
    "problem": "problem",
    "question": "question",
    "claim": "claim",
    "fact": "fact",
    "observation": "observation",
    "note": "note",
    "exercise": "exercise",
    # Publishers often use ``Result`` as a generic theorem label.  It is safe to
    # inventory but not safe to rewrite automatically without a declared alias.
    "result": "theorem",
    "axiom": "theorem",
    "assertion": "theorem",
}
_CHINESE_ENV = {
    "定义": "definition",
    "定理": "theorem",
    "引理": "lemma",
    "命题": "proposition",
    "推论": "corollary",
    "注记": "remark",
    "注": "remark",
    "例": "example",
    "猜想": "conjecture",
    "问题": "problem",
    "断言": "claim",
    "事实": "fact",
    "观察": "observation",
    "练习": "exercise",
}
_ENGLISH_LABELS = "|".join(
    sorted((re.escape(label) for label in _ENGLISH_ENV), key=len, reverse=True)
)
_CHINESE_LABELS = "|".join(
    sorted((re.escape(label) for label in _CHINESE_ENV), key=len, reverse=True)
)
_ENGLISH_HEADING_RE = re.compile(
    rf"^(?P<label>{_ENGLISH_LABELS})\b"
    r"(?P<tail>.*)$",
    re.IGNORECASE,
)
_CHINESE_HEADING_RE = re.compile(
    rf"^(?P<label>{_CHINESE_LABELS})(?P<tail>.*)$"
)
_NUMBER_RE = re.compile(
    r"^\s*(?P<number>(?:\d+(?:\.\d+)*|[A-Z](?:\.\d+)*))"
    r"\s*(?P<punct>[.:：。]?)\s*(?P<rest>.*)$"
)
_UNNUMBERED_RE = re.compile(
    r"^\s*(?P<punct>[.:：。])\s*(?P<rest>.*)$"
)
_NAMED_RE = re.compile(r"^\s*[\[(](?P<name>[^\]\)\n]{1,200})[\])]\s*[.:：。]?\s*(?P<rest>.*)$")
_REFERENCE_TAIL_RE = re.compile(
    r"^(?:has|have|had|is|are|was|were|shows?|showed|implies?|implied|"
    r"gives?|gave|yields?|yielded|appears?|appeared|follows?|followed|"
    r"states?|stated|provides?|provided|can|may|will|would)\b",
    re.IGNORECASE,
)
_PROOF_RE = re.compile(
    r"^(?P<label>Proof|Sketch\s+of\s+(?:the\s+)?proof)"
    r"(?P<tail>.*)$",
    re.IGNORECASE,
)
_PROOF_OF_TYPED_RE = re.compile(
    r"^\s+of\s+"
    r"(?:(?:the\s+)?(?:upper|lower)\s+bound\s+(?:in|of|for)\s+)?"
    r"(?:the\s+)?"
    r"(?:Theorem|Lemma|Proposition|Corollary|Conjecture|Claim|Fact|"
    r"Observation|Definition|Result|Question|Problem|Exercise)\b",
    re.IGNORECASE,
)
_INLINE_ONE_ARGUMENT_WRAPPER_RE = re.compile(
    r"\\(?:textbf|textit|emph|textsc|textnormal|textrm|textsf|texttt|"
    r"underline|mbox|makebox|fbox)\s*\{([^{}]*)\}"
)
_INLINE_TEXTCOLOR_RE = re.compile(
    r"\\textcolor\s*\{[^{}]*\}\s*\{([^{}]*)\}"
)
_INLINE_HYPERREF_RE = re.compile(
    r"\\hyperref\s*\[[^\]]*\]\s*\{([^{}]*)\}"
)
_CHINESE_PROOF_RE = re.compile(r"^(?:证明|证)(?P<tail>\s*(?:如下)?\s*[:：.]?.*)$")

_LAYOUT_PREFIX_RE = re.compile(
    r"^\\(?:noindent|leavevmode|ignorespaces|relax|par)\b\s*"
)
_OLD_STYLE_RE = re.compile(
    r"^\{\s*\\(?:bfseries|itshape|slshape|scshape)\b\s*"
)
_COMMAND_RE = re.compile(r"^\\(?P<name>[A-Za-z@]+)\*?\s*")
_ONE_ARGUMENT_WRAPPERS = frozenset({
    "textbf", "textit", "emph", "textsc", "textnormal", "underline",
    "mbox", "makebox", "fbox", "formalheading", "formalhead", "resultheading",
    "theoremheading", "statementheading",
})
_TWO_ARGUMENT_WRAPPERS = frozenset({"textcolor"})
_BLOCKED_WRAPPERS = frozenset({
    "chapter", "section", "subsection", "subsubsection", "paragraph",
    "subparagraph", "caption", "footnote", "label", "ref", "pageref",
    "cref", "Cref", "cite", "url", "href", "hyperref", "includegraphics",
    "begin", "end", "item",
})
_QED_RE = re.compile(
    r"(?:\\qedhere\b|\\qed\b|\\hfill\s*\$?\s*\\(?:black)?square\b|"
    r"(?:^|\s)[□∎]\s*(?:[.!?。]?)\s*$)"
)
_IGNORABLE_ENV_LINE_RE = re.compile(
    r"^\s*(?:%.*|\\label\s*\{[^{}]*\}|\\hypertarget\s*\{[^{}]*\}\s*\{\s*\}|"
    r"\\(?:noindent|leavevmode|ignorespaces|relax|par)\b|"
    r"\\ifcsname\s+qedsymbol.*|\\let\\qedsymbol\\empty|\\fi)\s*$"
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, start_line: int, end_line: int, digest: str, *parts: str) -> str:
    suffix = ":".join(
        re.sub(r"[^a-z0-9*_-]+", "-", str(part).casefold()).strip("-") or "none"
        for part in parts
    )
    return f"{prefix}:{start_line}-{end_line}:{suffix}:{digest[:16]}"


@dataclass(frozen=True)
class FormalAnchor:
    id: str
    start_line: int
    end_line: int
    raw_text: str
    visible_text: str
    label: str
    number: str
    suggested_env: str
    original_env: str
    source_sha256: str
    block_id: Optional[int] = None
    in_env: tuple[str, ...] = ()
    in_box: bool = False
    wrapper: str = "plain"
    strong: bool = False

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "raw_text": self.raw_text,
            "visible_text": self.visible_text,
            "label": self.label,
            "number": self.number,
            "suggested_env": self.suggested_env,
            "original_env": self.original_env,
            "source_sha256": self.source_sha256,
            "block_id": self.block_id,
            "in_env": list(self.in_env),
            "in_box": self.in_box,
            "wrapper": self.wrapper,
            "strong": self.strong,
        }


@dataclass(frozen=True)
class FormalEnvironment:
    id: str
    start_line: int
    end_line: int
    original_env: str
    suggested_env: str
    optional_title: str
    source_sha256: str
    parent_env: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "original_env": self.original_env,
            "suggested_env": self.suggested_env,
            "optional_title": self.optional_title,
            "source_sha256": self.source_sha256,
            "parent_env": self.parent_env,
        }


@dataclass(frozen=True)
class FormalFinding:
    id: str
    kind: str
    start_line: int
    end_line: int
    original_env: str
    suggested_env: str
    source_sha256: str
    reason: str
    anchor_id: str = ""
    environment_id: str = ""
    related_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "original_env": self.original_env,
            "suggested_env": self.suggested_env,
            "source_sha256": self.source_sha256,
            "reason": self.reason,
            "anchor_id": self.anchor_id,
            "environment_id": self.environment_id,
            "related_ids": list(self.related_ids),
        }


@dataclass(frozen=True)
class FormalInventory:
    anchors: tuple[FormalAnchor, ...] = ()
    environments: tuple[FormalEnvironment, ...] = ()
    findings: tuple[FormalFinding, ...] = ()
    schema: str = "latexstruct-formal-inventory-v1"

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "anchors": [item.as_dict() for item in self.anchors],
            "environments": [item.as_dict() for item in self.environments],
            "findings": [item.as_dict() for item in self.findings],
            "counts": {
                "anchors": len(self.anchors),
                "environments": len(self.environments),
                "findings": len(self.findings),
                "missing": sum(item.kind == "missing" for item in self.findings),
                "wrong_env": sum(item.kind == "wrong-env" for item in self.findings),
                "overwide": sum(item.kind == "overwide" for item in self.findings),
                "duplicate": sum(item.kind == "duplicate" for item in self.findings),
            },
        }


def _balanced_group(value: str, opening: int) -> tuple[str, int] | None:
    if opening >= len(value) or value[opening] != "{":
        return None
    depth = 0
    escaped = False
    for index in range(opening, min(len(value), opening + 8192)):
        char = value[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return value[opening + 1:index], index + 1
    return None


def _visible_prefix(value: str) -> tuple[str, str]:
    """Expose bounded style/macro wrappers without interpreting arbitrary TeX."""
    current = str(value or "").lstrip()
    wrappers: list[str] = []
    for _ in range(10):
        layout = _LAYOUT_PREFIX_RE.match(current)
        if layout is not None:
            wrappers.append("layout")
            current = current[layout.end():].lstrip()
            continue
        old_style = _OLD_STYLE_RE.match(current)
        if old_style is not None:
            grouped = _balanced_group(current, 0)
            if grouped is None:
                break
            inner, end = grouped
            style = re.sub(
                r"^\s*\\(?:bfseries|itshape|slshape|scshape)\b\s*",
                "",
                inner,
                count=1,
            )
            current = (style + current[end:]).lstrip()
            wrappers.append("old-style")
            continue
        command = _COMMAND_RE.match(current)
        if command is None:
            break
        name = command.group("name")
        if name in _BLOCKED_WRAPPERS:
            break
        cursor = command.end()
        if name == "color":
            first = _balanced_group(current, cursor)
            if first is None:
                break
            _ignored, end = first
            current = current[end:].lstrip()
            wrappers.append("color")
            continue
        if name in _TWO_ARGUMENT_WRAPPERS:
            first = _balanced_group(current, cursor)
            if first is None:
                break
            _ignored, cursor = first
            while cursor < len(current) and current[cursor].isspace():
                cursor += 1
            second = _balanced_group(current, cursor)
            if second is None:
                break
            inner, end = second
            current = (inner + current[end:]).lstrip()
            wrappers.append(name)
            continue
        first = _balanced_group(current, cursor)
        # Known visual wrappers are accepted.  An otherwise unknown one-argument
        # macro is exposed only for inventory; scanner integration will keep it
        # as a manual blocker unless its exact source is patch-safe.
        if first is None:
            break
        inner, end = first
        if name not in _ONE_ARGUMENT_WRAPPERS and not re.match(
            r"^[A-Za-z@]*(?:head|heading|title|label)$", name, re.IGNORECASE
        ):
            # Still expose a single argument when that argument itself begins
            # with a formal label.  This is discovery only, never authorization
            # to strip the unknown macro.
            probe = inner.lstrip()
            if not (
                _ENGLISH_HEADING_RE.match(probe)
                or _CHINESE_HEADING_RE.match(probe)
                or _PROOF_RE.match(probe)
                or _CHINESE_PROOF_RE.match(probe)
            ):
                break
        current = (inner + current[end:]).lstrip()
        wrappers.append(name if name in _ONE_ARGUMENT_WRAPPERS else "macro")
    wrapper = "plain" if not wrappers else "+".join(wrappers)
    return current, wrapper


def _flatten_inline_presentation(value: str) -> str:
    """Expose bounded visual/link wrappers for discovery only."""
    current = str(value or "")
    for _ in range(12):
        updated = _INLINE_TEXTCOLOR_RE.sub(r"\1", current)
        updated = _INLINE_HYPERREF_RE.sub(r"\1", updated)
        updated = _INLINE_ONE_ARGUMENT_WRAPPER_RE.sub(r"\1", updated)
        if updated == current:
            break
        current = updated
    return current


def _detect_heading(value: str) -> tuple[str, str, str, bool] | None:
    visible, wrapper = _visible_prefix(value)
    classified_visible = _flatten_inline_presentation(visible)
    proof = _PROOF_RE.match(classified_visible)
    if proof is not None:
        tail = proof.group("tail")
        if tail and not re.match(r"^\s*[.:：。]", tail) and not _PROOF_OF_TYPED_RE.match(tail):
            return None
        return "proof", proof.group("label"), "", True
    chinese_proof = _CHINESE_PROOF_RE.match(classified_visible)
    if chinese_proof is not None:
        return "proof", visible[:2], "", True

    match = _ENGLISH_HEADING_RE.match(classified_visible)
    mapping = _ENGLISH_ENV
    if match is None:
        match = _CHINESE_HEADING_RE.match(classified_visible)
        mapping = _CHINESE_ENV
    if match is None:
        return None
    label = match.group("label")
    expected = mapping[label.casefold() if mapping is _ENGLISH_ENV else label]
    tail = match.group("tail")
    number_match = _NUMBER_RE.match(tail)
    if number_match is not None:
        number = number_match.group("number")
        rest = number_match.group("rest").lstrip()
        if rest and _REFERENCE_TAIL_RE.match(rest):
            return None
        return expected, label, number, True
    named_match = _NAMED_RE.match(tail)
    if named_match is not None:
        rest = named_match.group("rest").lstrip()
        if rest and _REFERENCE_TAIL_RE.match(rest):
            return None
        return expected, label, "", True
    unnumbered = _UNNUMBERED_RE.match(tail)
    if unnumbered is None:
        return None
    rest = unnumbered.group("rest").lstrip()
    if rest and _REFERENCE_TAIL_RE.match(rest):
        return None
    # A style/macro wrapper, or actual statement text after the punctuation,
    # makes an unnumbered Remark/Example/Note a strong inventory item.  A bare
    # ``Exercise.`` inside a proof remains too ambiguous to call wrong-env.
    strong = wrapper != "plain" or bool(rest) or expected in {"remark", "example"}
    return expected, label, "", strong


def _line_for_offset(doc: Document, offset: int) -> int:
    return bisect_right(doc.line_starts, offset)


def _source_lines(doc: Document, start_line: int, end_line: int) -> str:
    lines = doc.text.split("\n")
    return "\n".join(lines[start_line - 1:end_line])


def _canonical_env(name: str) -> str:
    base = str(name or "").removesuffix("*").casefold()
    if base == "solution":
        return "proof"
    return base if base in FORMAL_ENVIRONMENTS else ""


def _optional_title(line: str, env_name: str) -> str:
    match = re.search(
        rf"\\begin\s*\{{\s*{re.escape(env_name)}\s*\}}\s*\[([^\]\n]{{1,300}})\]",
        line,
    )
    return match.group(1).strip() if match is not None else ""


def _meaningful_line(line: str) -> bool:
    return bool(line.strip() and not _IGNORABLE_ENV_LINE_RE.match(line))


def _finding(
    kind: str,
    start_line: int,
    end_line: int,
    source: str,
    *,
    original_env: str,
    suggested_env: str,
    reason: str,
    anchor_id: str = "",
    environment_id: str = "",
    related_ids: Iterable[str] = (),
) -> FormalFinding:
    digest = _sha256(source)
    return FormalFinding(
        id=_stable_id(
            f"formal-{kind}", start_line, end_line, digest,
            original_env, suggested_env,
        ),
        kind=kind,
        start_line=start_line,
        end_line=end_line,
        original_env=original_env,
        suggested_env=suggested_env,
        source_sha256=digest,
        reason=reason,
        anchor_id=anchor_id,
        environment_id=environment_id,
        related_ids=tuple(related_ids),
    )


def inventory_document(
    doc: Document,
    structured_envs: Optional[Iterable[str]] = None,
) -> FormalInventory:
    """Inventory naked formal headings and audit existing formal environments.

    The result is deterministic for normalized source text.  Every item carries
    an exact source hash and one-based inclusive source line range.
    """
    supplied = {
        str(name).strip() for name in (structured_envs or ()) if str(name).strip()
    }
    structured = set(FORMAL_ENVIRONMENTS) | supplied
    structured |= {f"{name}*" for name in structured if not name.endswith("*")}
    lines = doc.text.split("\n")
    masked_lines = doc.masked.split("\n")

    anchors: list[FormalAnchor] = []
    for block in doc.blocks_of_kind("para"):
        envs = tuple(str(name) for name in block.in_env)
        if set(envs) & (PROTECTED_ENVS | _NON_PROSE_ENVIRONMENTS):
            continue
        original_env = next(
            (name for name in reversed(envs) if name in structured),
            "",
        )
        in_box = bool(set(envs) & BOX_ENVIRONMENTS)
        for line_no in range(block.span.start_line, block.span.end_line + 1):
            active = masked_lines[line_no - 1]
            detected = _detect_heading(active)
            if detected is None:
                continue
            suggested_env, label, number, strong = detected
            raw = lines[line_no - 1]
            visible, wrapper = _visible_prefix(active)
            digest = _sha256(raw)
            anchors.append(FormalAnchor(
                id=_stable_id(
                    "formal-anchor", line_no, line_no, digest,
                    suggested_env, number or label,
                ),
                start_line=line_no,
                end_line=line_no,
                raw_text=raw,
                visible_text=visible,
                label=label,
                number=number,
                suggested_env=suggested_env,
                original_env=original_env,
                source_sha256=digest,
                block_id=block.id,
                in_env=envs,
                in_box=in_box,
                wrapper=wrapper,
                strong=strong,
            ))

    environments: list[FormalEnvironment] = []
    env_ranges: list[tuple[str, int, int, FormalEnvironment]] = []
    for name, begin_start, _begin_end, end_start, _end_end in doc.env_ranges:
        if name not in structured:
            continue
        start_line = _line_for_offset(doc, begin_start)
        end_line = _line_for_offset(doc, end_start)
        source = _source_lines(doc, start_line, end_line)
        digest = _sha256(source)
        optional = _optional_title(lines[start_line - 1], name)
        parent = ""
        parent_start = -1
        for other_name, other_start, _other_begin_end, other_end, _other_end_end in doc.env_ranges:
            if (
                other_name in structured
                and other_start < begin_start
                and end_start < other_end
                and other_start > parent_start
            ):
                parent = other_name
                parent_start = other_start
        item = FormalEnvironment(
            id=_stable_id("formal-env", start_line, end_line, digest, name, optional),
            start_line=start_line,
            end_line=end_line,
            original_env=name,
            suggested_env=_canonical_env(name) or name,
            optional_title=optional,
            source_sha256=digest,
            parent_env=parent,
        )
        environments.append(item)
        env_ranges.append((name, begin_start, end_start, item))

    findings: list[FormalFinding] = []
    anchors_by_env: dict[str, list[FormalAnchor]] = {
        item.id: [] for item in environments
    }
    for anchor in anchors:
        containing = [
            item for _name, begin_start, end_start, item in env_ranges
            if begin_start < doc.line_starts[anchor.start_line - 1] < end_start
        ]
        environment = min(
            containing,
            key=lambda item: item.end_line - item.start_line,
        ) if containing else None
        if environment is None:
            source = _source_lines(doc, anchor.start_line, anchor.end_line)
            reason = "全文清点发现未处于定理/证明环境中的 formal 标题"
            if anchor.in_box:
                reason += "；标题位于版式盒内，只登记并交人工确认，不自动嵌套环境"
            findings.append(_finding(
                "missing",
                anchor.start_line,
                anchor.end_line,
                source,
                original_env="",
                suggested_env=anchor.suggested_env,
                reason=reason,
                anchor_id=anchor.id,
            ))
            continue
        anchors_by_env[environment.id].append(anchor)
        actual = _canonical_env(environment.original_env)
        if (
            actual
            and actual != anchor.suggested_env
            and (anchor.strong or bool(anchor.number))
        ):
            source = _source_lines(doc, environment.start_line, environment.end_line)
            findings.append(_finding(
                "wrong-env",
                environment.start_line,
                environment.end_line,
                source,
                original_env=environment.original_env,
                suggested_env=anchor.suggested_env,
                reason=(
                    f"环境 {environment.original_env} 内的显式标题表明其语义应为 "
                    f"{anchor.suggested_env}；未自动改写既有环境"
                ),
                anchor_id=anchor.id,
                environment_id=environment.id,
            ))

    # Audit optional titles such as ``\begin{lemma}[Theorem 2.1]`` even though
    # begin lines are not parser paragraph blocks.
    for environment in environments:
        if not environment.optional_title:
            continue
        detected = _detect_heading(environment.optional_title)
        actual = _canonical_env(environment.original_env)
        if detected is None or not actual:
            continue
        expected, _label, _number, strong = detected
        if expected == actual or not strong:
            continue
        source = _source_lines(doc, environment.start_line, environment.end_line)
        findings.append(_finding(
            "wrong-env",
            environment.start_line,
            environment.end_line,
            source,
            original_env=environment.original_env,
            suggested_env=expected,
            reason="环境可选标题与环境类型冲突；既有环境需人工确认",
            environment_id=environment.id,
        ))

    # An internal second formal title, a section command, or substantive prose
    # after an explicit QED is hard evidence that the existing environment has
    # swallowed a later structural unit.
    section_lines = {section.span.start_line for section in doc.sections}
    for environment in environments:
        source_lines = lines[environment.start_line:environment.end_line - 1]
        substantive = [
            environment.start_line + offset + 1
            for offset, line in enumerate(source_lines)
            if _meaningful_line(line)
        ]
        env_anchors = sorted(
            anchors_by_env.get(environment.id, []),
            key=lambda item: item.start_line,
        )
        overwide_reasons: list[str] = []
        strong_anchors = [
            anchor for anchor in env_anchors
            if anchor.strong or bool(anchor.number)
        ]
        if len(strong_anchors) >= 2:
            overwide_reasons.append("同一环境内出现多个强 formal 标题")
        elif strong_anchors and substantive:
            first = substantive[0]
            if strong_anchors[0].start_line > first:
                overwide_reasons.append("环境正文之后又出现新的强 formal 标题")
        if any(
            environment.start_line < line_no < environment.end_line
            for line_no in section_lines
        ):
            overwide_reasons.append("环境跨入章节标题")
        qed_line = next(
            (
                environment.start_line + offset + 1
                for offset, line in enumerate(source_lines)
                if _QED_RE.search(line)
            ),
            0,
        )
        if qed_line and any(line_no > qed_line for line_no in substantive):
            overwide_reasons.append("显式 QED 之后仍包含实质正文")
        if environment.parent_env:
            overwide_reasons.append("定理/证明环境嵌套在另一个 formal 环境中")
        if overwide_reasons:
            source = _source_lines(doc, environment.start_line, environment.end_line)
            findings.append(_finding(
                "overwide",
                environment.start_line,
                environment.end_line,
                source,
                original_env=environment.original_env,
                suggested_env=_canonical_env(environment.original_env) or environment.original_env,
                reason="；".join(dict.fromkeys(overwide_reasons)) + "；未猜测收缩边界",
                environment_id=environment.id,
                related_ids=(anchor.id for anchor in strong_anchors),
            ))

    signatures: dict[tuple[str, str], list[FormalEnvironment]] = {}
    for environment in environments:
        canonical = _canonical_env(environment.original_env)
        number = ""
        if re.fullmatch(r"\d+(?:\.\d+)*", environment.optional_title.strip()):
            number = environment.optional_title.strip()
        if not number:
            numbered = [
                anchor.number for anchor in anchors_by_env.get(environment.id, [])
                if anchor.number
            ]
            number = numbered[0] if len(set(numbered)) == 1 else ""
        if canonical and number:
            signatures.setdefault((canonical, number), []).append(environment)
    for (canonical, number), repeated in signatures.items():
        if len(repeated) < 2:
            continue
        related = tuple(item.id for item in repeated)
        for environment in repeated[1:]:
            source = _source_lines(doc, environment.start_line, environment.end_line)
            findings.append(_finding(
                "duplicate",
                environment.start_line,
                environment.end_line,
                source,
                original_env=environment.original_env,
                suggested_env=canonical,
                reason=f"同一 {canonical} 编号 {number} 出现于多个 formal 环境",
                environment_id=environment.id,
                related_ids=related,
            ))

    # Deduplicate findings whose independent detectors reached the same source
    # conclusion (for example an optional title and an interior retained title).
    unique: dict[tuple[str, int, int, str, str], FormalFinding] = {}
    for item in findings:
        key = (
            item.kind,
            item.start_line,
            item.end_line,
            item.original_env,
            item.suggested_env,
        )
        unique.setdefault(key, item)
    return FormalInventory(
        anchors=tuple(sorted(anchors, key=lambda item: (item.start_line, item.id))),
        environments=tuple(sorted(environments, key=lambda item: (item.start_line, item.end_line))),
        findings=tuple(sorted(unique.values(), key=lambda item: (item.start_line, item.kind, item.id))),
    )


__all__ = [
    "FormalAnchor",
    "FormalEnvironment",
    "FormalFinding",
    "FormalInventory",
    "inventory_document",
]
