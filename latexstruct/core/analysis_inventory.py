"""Host-only, full-document structural inventory for analysis verification.

The inventory is intentionally independent from model output.  It scans the
immutable OCR baseline and one candidate TeX source with the same deterministic
rules, binds every discovered item to the native source-page map when possible,
and compares stable semantic identities.  Missing, added/duplicated, renumbered,
relabelled, retyped, or moved items remain machine-readable residuals.

An empty category is never reported as a successful scan: it is explicitly
``NOT_APPLICABLE``.  Malformed relevant TeX is ``FAILED`` rather than silently
becoming an empty inventory.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Sequence

from .formal_inventory import FORMAL_ENVIRONMENTS, inventory_document
from .parser import Document, mask_comments, offset_to_line, parse_latex


ANALYSIS_INVENTORY_SCHEMA = "latexstruct-analysis-inventory-v1"
ANALYSIS_INVENTORY_CATEGORIES = (
    "heading",
    "formal",
    "proof",
    "equation",
    "reference",
    "citation",
    "footnote",
    "figure",
    "table",
    "caption",
    "bibliography",
    "frontmatter",
)


class InventoryStatus(str, Enum):
    PASS = "PASS"
    RESIDUAL = "RESIDUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"


class InventoryResidualKind(str, Enum):
    MISSING = "MISSING"
    ADDED = "ADDED"
    DUPLICATE = "DUPLICATE"
    NUMBER_CHANGED = "NUMBER_CHANGED"
    LABEL_CHANGED = "LABEL_CHANGED"
    KIND_CHANGED = "KIND_CHANGED"
    PAGE_CHANGED = "PAGE_CHANGED"
    UNSTRUCTURED = "UNSTRUCTURED"
    INVALID_STRUCTURE = "INVALID_STRUCTURE"
    SCAN_FAILED = "SCAN_FAILED"
    PAGE_MAP_MISMATCH = "PAGE_MAP_MISMATCH"
    REPRESENTATION_CHANGED = "REPRESENTATION_CHANGED"


class InventoryAuthorizationAction(str, Enum):
    STRUCTURE_WRAPPER = "STRUCTURE_WRAPPER"
    GENERATED_TOC = "GENERATED_TOC"


class AnalysisInventoryError(ValueError):
    """The requested inventory cannot be constructed safely."""


class AnalysisInventoryGateError(RuntimeError):
    """The aggregate inventory gate is not PASS."""


@dataclass(frozen=True, slots=True)
class AnalysisInventoryAuthorization:
    """One narrow host policy/decision admitted into inventory comparison."""

    authorization_id: str
    category: str
    action: InventoryAuthorizationAction
    evidence_id: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", self.authorization_id):
            raise AnalysisInventoryError("inventory authorization id is invalid")
        if self.category not in ANALYSIS_INVENTORY_CATEGORIES:
            raise AnalysisInventoryError("inventory authorization category is invalid")
        if not isinstance(self.action, InventoryAuthorizationAction):
            raise AnalysisInventoryError("inventory authorization action is invalid")
        if not str(self.evidence_id or "").strip():
            raise AnalysisInventoryError("inventory authorization requires host evidence")
        allowed = {
            InventoryAuthorizationAction.STRUCTURE_WRAPPER: {
                "heading", "formal", "proof", "footnote", "caption",
                "bibliography", "figure", "table",
            },
            InventoryAuthorizationAction.GENERATED_TOC: {"frontmatter"},
        }
        if self.category not in allowed[self.action]:
            raise AnalysisInventoryError(
                "inventory authorization action/category pair is unsupported"
            )

    def as_dict(self) -> dict[str, str]:
        return {
            "authorization_id": self.authorization_id,
            "category": self.category,
            "action": self.action.value,
            "evidence_id": self.evidence_id,
        }


def coerce_analysis_inventory_authorizations(
    values: Sequence[AnalysisInventoryAuthorization | Mapping[str, object]],
) -> tuple[AnalysisInventoryAuthorization, ...]:
    result: list[AnalysisInventoryAuthorization] = []
    for value in values:
        if isinstance(value, AnalysisInventoryAuthorization):
            item = value
        elif isinstance(value, Mapping) and set(value) == {
            "authorization_id", "category", "action", "evidence_id"
        }:
            try:
                item = AnalysisInventoryAuthorization(
                    authorization_id=str(value["authorization_id"]),
                    category=str(value["category"]),
                    action=InventoryAuthorizationAction(str(value["action"])),
                    evidence_id=str(value["evidence_id"]),
                )
            except (TypeError, ValueError) as exc:
                raise AnalysisInventoryError(
                    "inventory authorization is invalid"
                ) from exc
        else:
            raise AnalysisInventoryError("inventory authorization is not typed")
        result.append(item)
    ids = tuple(item.authorization_id for item in result)
    if len(ids) != len(set(ids)):
        raise AnalysisInventoryError("inventory authorization ids are duplicated")
    return tuple(sorted(result, key=lambda item: item.authorization_id))


@dataclass(frozen=True, slots=True)
class AnalysisNativeSourceBlock:
    """Host-owned OCR block identity used to seed source-side inventory."""

    page_id: str
    source_page: int
    block_id: str
    block_type: str
    plain_text: str
    source_sha256: str
    reading_order: int = 0
    bbox: tuple[float, float, float, float] | tuple[()] = ()
    object_path: str = ""

    def __post_init__(self) -> None:
        if not str(self.page_id or "").strip() or not str(self.block_id or "").strip():
            raise AnalysisInventoryError("native source block identity is missing")
        if type(self.source_page) is not int or self.source_page < 1:
            raise AnalysisInventoryError("native source block page is invalid")
        block_type = str(self.block_type or "").strip().upper()
        plain_text = str(self.plain_text or "")
        if not block_type:
            raise AnalysisInventoryError("native source block type is missing")
        if not plain_text.strip() and block_type not in {"FIGURE", "TABLE"}:
            raise AnalysisInventoryError("native source block content is missing")
        digest = str(self.source_sha256 or "").strip().lower()
        if _SHA256_RE.fullmatch(digest) is None:
            raise AnalysisInventoryError("native source block hash is invalid")
        reading_order = self.reading_order
        if (
            not isinstance(reading_order, int)
            or isinstance(reading_order, bool)
            or reading_order < 0
        ):
            raise AnalysisInventoryError("native source block reading order is invalid")
        raw_bbox = tuple(self.bbox)
        if raw_bbox:
            if len(raw_bbox) != 4 or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) < 0
                for value in raw_bbox
            ):
                raise AnalysisInventoryError("native source block bbox is invalid")
            bbox = tuple(float(value) for value in raw_bbox)
            if bbox[2] < bbox[0] or bbox[3] < bbox[1]:
                raise AnalysisInventoryError("native source block bbox is reversed")
        else:
            bbox = ()
        object_path = str(self.object_path or "").strip()
        if object_path:
            match = _NATIVE_OBJECT_PATH_RE.fullmatch(object_path)
            if match is None or int(match.group("page")) != self.source_page:
                raise AnalysisInventoryError("native source block object path is invalid")
        if not plain_text.strip():
            if reading_order < 1:
                raise AnalysisInventoryError(
                    "textless native object requires a positive reading order"
                )
            if not bbox or bbox[0] >= bbox[2] or bbox[1] >= bbox[3]:
                raise AnalysisInventoryError(
                    "textless native object requires a positive-area bbox"
                )
        object.__setattr__(self, "block_type", block_type)
        object.__setattr__(self, "plain_text", plain_text)
        object.__setattr__(self, "source_sha256", digest)
        object.__setattr__(self, "reading_order", reading_order)
        object.__setattr__(self, "bbox", bbox)
        object.__setattr__(self, "object_path", object_path)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "page_id": self.page_id,
            "source_page": self.source_page,
            "block_id": self.block_id,
            "block_type": self.block_type,
            "plain_text": self.plain_text,
            "source_sha256": self.source_sha256,
        }
        # Preserve the six-field legacy wire shape for old callers while
        # retaining every host-owned object fact in the expanded projection.
        if self.reading_order or self.bbox or self.object_path:
            payload.update({
                "reading_order": self.reading_order,
                "bbox": list(self.bbox),
                "object_path": self.object_path,
            })
        return payload


def coerce_analysis_native_source_blocks(
    values: Sequence[AnalysisNativeSourceBlock | Mapping[str, object]],
) -> tuple[AnalysisNativeSourceBlock, ...]:
    result: list[AnalysisNativeSourceBlock] = []
    legacy_fields = {
        "page_id", "source_page", "block_id", "block_type", "plain_text",
        "source_sha256",
    }
    expanded_fields = legacy_fields | {"reading_order", "bbox", "object_path"}
    for value in values:
        if isinstance(value, AnalysisNativeSourceBlock):
            item = value
        elif isinstance(value, Mapping) and frozenset(value) in {
            frozenset(legacy_fields), frozenset(expanded_fields)
        }:
            try:
                item = AnalysisNativeSourceBlock(
                    page_id=str(value["page_id"]),
                    source_page=value["source_page"],
                    block_id=str(value["block_id"]),
                    block_type=str(value["block_type"]),
                    plain_text=str(value["plain_text"]),
                    source_sha256=str(value["source_sha256"]),
                    reading_order=value.get("reading_order", 0),
                    bbox=tuple(value.get("bbox") or ()),
                    object_path=str(value.get("object_path") or ""),
                )
            except (TypeError, ValueError) as exc:
                raise AnalysisInventoryError("native source block is invalid") from exc
        else:
            raise AnalysisInventoryError("native source block is not typed")
        result.append(item)
    identities = tuple((item.page_id, item.block_id) for item in result)
    if len(identities) != len(set(identities)):
        raise AnalysisInventoryError("native source block identities are duplicated")
    object_paths = tuple(item.object_path for item in result if item.object_path)
    if len(object_paths) != len(set(object_paths)):
        raise AnalysisInventoryError("native source block object paths are duplicated")
    return tuple(sorted(
        result,
        key=lambda item: (
            item.source_page,
            item.reading_order if item.reading_order else 2**31,
            item.block_id,
        ),
    ))


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NATIVE_OBJECT_PATH_RE = re.compile(
    r"^figures/page_(?P<page>[0-9]{4,})_figure_[0-9]{2,}\.png$"
)
_COMMAND_NAME_RE = re.compile(r"[A-Za-z@]+")
_PAGE_COMMENT_RE = re.compile(
    r"^[ \t]*%[ \t]*LaTeXStruct-Page:[ \t]*"
    r"page_id=(ocr-page-[0-9]{6})[ \t]+source_page=([0-9]+)[ \t]*$",
    re.MULTILINE,
)
_PAGE_TARGET_RE = re.compile(
    r"\\hypertarget\s*\{(ocr-page-[0-9]{6})\}\s*\{\s*\}"
)
_LEGACY_PAGE_COMMENT_RE = re.compile(
    r"^[ \t]*%[ \t]*Page[ \t]+([1-9][0-9]*)[ \t]*$",
    re.MULTILINE,
)
_ENV_TOKEN_RE = re.compile(
    r"\\(?P<kind>begin|end)\s*\{(?P<name>[^{}\r\n]+)\}"
)
_LABEL_RE = re.compile(r"\\label\s*\{([^{}]+)\}")
_TAG_RE = re.compile(r"\\tag\*?\s*\{([^{}]+)\}")
_INCLUDEGRAPHICS_RE = re.compile(r"\\includegraphics(?![A-Za-z@])")
_NEW_THEOREM_RE = re.compile(
    r"\\(?:newtheorem|declaretheorem)\*?\s*(?:\[[^\]]*\]\s*)?\{([^{}]+)\}"
)
_PRESENTATION_ONE_ARG_RE = re.compile(
    r"\\(?:textbf|textit|emph|textsc|textnormal|textrm|textsf|texttt|"
    r"underline|mbox|makebox|fbox|texorpdfstring)\*?\s*\{([^{}]*)\}"
)
_PAGE_MARKER_COMMAND_RE = re.compile(
    r"\\hypertarget\s*\{ocr-page-[0-9]{6}\}\s*\{\s*\}"
)
_BEGIN_END_RE = re.compile(r"\\(?:begin|end)\s*\{[^{}]+\}(?:\s*\[[^\]]*\])?")
_STRUCTURAL_METADATA_RE = re.compile(
    r"\\(?:label|tag\*?)\s*\{[^{}]*\}|\\(?:qedhere|qed)\b"
)
_LEADING_NUMBER_RE = re.compile(
    r"^\s*(?:(?:chapter|section|part|figure|fig\.?|table|equation|eq\.?|"
    r"theorem|lemma|proposition|corollary|definition|remark|example|"
    r"conjecture|problem|question|claim|fact|observation|exercise)\s+)?"
    r"(?P<number>(?:[0-9]+(?:\.[0-9]+)*|[IVXLCDM]+|[A-Z]))"
    r"(?=\s|[.:：。]|$)"
    r"\s*[.:：。]?\s*(?P<rest>.*)$",
    re.IGNORECASE,
)
_FORMAL_PREFIX_RE = re.compile(
    r"^\s*(?:theorem|lemma|proposition|corollary|definition|remark|example|"
    r"conjecture|problem|question|claim|fact|observation|note|exercise|result|"
    r"proof|sketch\s+of\s+(?:the\s+)?proof|solution|"
    r"定理|引理|命题|推论|定义|注记|注|例|猜想|问题|断言|事实|观察|练习|证明)"
    r"(?:\s+(?:[0-9]+(?:\.[0-9]+)*|[IVXLCDM]+|[A-Z]))?\s*[.:：。]?\s*",
    re.IGNORECASE,
)
_PROOF_PREFIX_RE = re.compile(
    r"^\s*(?:(?:proof|sketch\s+of\s+(?:the\s+)?proof|solution)\b|"
    r"(?:证明|证)(?=\s|[:：。.]|$))",
    re.IGNORECASE,
)
_FORMAL_KIND_PREFIX_RE = re.compile(
    r"^\s*(?P<kind>theorem|lemma|proposition|corollary|definition|remark|"
    r"example|conjecture|problem|question|claim|fact|observation|note|"
    r"exercise|result|定理|引理|命题|推论|定义|注记|注|例|猜想|问题|断言|"
    r"事实|观察|练习)(?=\s|[0-9IVXLCDM]|[:：。.]|$)",
    re.IGNORECASE,
)
_FOOTNOTE_MARKER_RE = re.compile(
    r"^\s*(?:\[(?P<bracket>[0-9]+)\]|(?P<number>[0-9]+)|"
    r"(?P<symbol>[*†‡]))\s*[.)：:]?\s+(?P<body>.+)$",
    re.DOTALL,
)
_BIBLIOGRAPHY_MARKER_RE = re.compile(
    r"^\s*(?:\[(?P<bracket>[^\]]{1,80})\]|(?P<number>[0-9]+)\s*[.)])"
    r"\s*(?P<body>.+)$",
    re.DOTALL,
)
_CAPTION_PREFIX_RE = re.compile(
    r"^\s*(?P<kind>fig(?:ure)?\.?|table|图|表)\s*"
    r"(?P<number>[0-9]+(?:\.[0-9]+)*)?\s*[.:：。]?\s*(?P<body>.*)$",
    re.IGNORECASE | re.DOTALL,
)
_PLAIN_NUMBERED_HEADING_RE = re.compile(
    r"^\s*(?P<number>[0-9]+(?:\.[0-9]+)*)\s*[.)：:]?\s+"
    r"(?P<title>[^\n]{1,300}?)\s*$"
)
_PLAIN_UNNUMBERED_HEADINGS = frozenset({
    "abstract", "acknowledgements", "acknowledgments", "appendix",
    "bibliography", "conclusion", "conclusions", "contents",
    "introduction", "preface", "references",
})

_HEADING_COMMANDS = frozenset({
    "part", "chapter", "section", "subsection", "subsubsection",
    "paragraph", "subparagraph",
})
_REFERENCE_COMMANDS = frozenset({
    "ref", "pageref", "eqref", "autoref", "cref", "Cref", "vref",
    "Vref", "nameref",
})
_CITATION_COMMANDS = frozenset({
    "cite", "citep", "citet", "citealp", "citealt", "parencite",
    "textcite", "autocite", "footcite", "smartcite", "nocite",
    "citeauthor", "citeyear", "supercite",
})
_FOOTNOTE_COMMANDS = frozenset({"footnote", "footnotetext", "thanks"})
_MATH_ENVIRONMENTS = frozenset({
    "math", "displaymath", "equation", "equation*", "align", "align*",
    "alignat", "alignat*", "flalign", "flalign*", "gather", "gather*",
    "multline", "multline*", "eqnarray", "eqnarray*", "split", "aligned",
    "alignedat", "gathered", "cases",
})
_NATIVE_DISPLAY_MATH_KIND = "display-math"
_TRAILING_DISPLAY_NUMBER_RE = re.compile(
    r"(?P<prefix>(?:\r?\n|[ \t]{2,}))"
    r"\((?P<number>[0-9]+(?:\.[0-9]+)*|[IVXLCDM]+|[A-Z])\)\s*$"
)
_MATH_COMMAND_ALIASES = MappingProxyType({
    "\\le": "≤",
    "\\leq": "≤",
    "\\leqslant": "≤",
    "\\ge": "≥",
    "\\geq": "≥",
    "\\geqslant": "≥",
    "\\neq": "≠",
    "\\ne": "≠",
    "\\to": "→",
    "\\rightarrow": "→",
    "\\leftarrow": "←",
    "\\leftrightarrow": "↔",
    "\\infty": "∞",
    "\\ell": "ℓ",
    "\\epsilon": "ε",
    "\\varepsilon": "ε",
    "\\delta": "δ",
    "\\Delta": "Δ",
    "\\lambda": "λ",
    "\\Lambda": "Λ",
    "\\mu": "μ",
    "\\pi": "π",
    "\\Pi": "Π",
    "\\sigma": "σ",
    "\\Sigma": "Σ",
    "\\theta": "θ",
    "\\Theta": "Θ",
    "\\alpha": "α",
    "\\beta": "β",
    "\\gamma": "γ",
    "\\Gamma": "Γ",
    "\\omega": "ω",
    "\\Omega": "Ω",
    "\\approx": "≈",
    "\\sim": "∼",
    "\\in": "∈",
    "\\notin": "∉",
    "\\times": "×",
    "\\cdot": "·",
    "\\pm": "±",
    "\\mp": "∓",
})
_MATH_INVISIBLE_COMMAND_RE = re.compile(
    r"\\(?:left|right|displaystyle|textstyle|scriptstyle|scriptscriptstyle)\b"
    r"|\\(?:quad|qquad|enspace|thinspace|medspace|thickspace)\b"
    r"|\\(?:,|!|;|:)"
)
_MATH_ATOMIC_SCRIPT_RE = re.compile(r"([_^])\{([^{}\s])\}")
_UNICODE_SUPERSCRIPT_RE = re.compile(r"[⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾]+")
_UNICODE_SUBSCRIPT_RE = re.compile(r"[₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎]+")
_UNICODE_SUPERSCRIPT_TRANSLATION = str.maketrans(
    "⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾", "0123456789+-=()"
)
_UNICODE_SUBSCRIPT_TRANSLATION = str.maketrans(
    "₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎", "0123456789+-=()"
)
_TABLE_ENVIRONMENTS = frozenset({
    "table", "table*", "longtable", "longtabu", "tabular", "tabular*",
    "tabularx", "tabulary", "tblr", "talltblr", "longtblr",
})
_BIBLIOGRAPHY_ENVIRONMENTS = frozenset({"thebibliography"})
_FRONTMATTER_ENVIRONMENTS = frozenset({"abstract", "titlepage", "dedication"})
_FRONTMATTER_REQUIRED_COMMANDS = frozenset({
    "title", "subtitle", "author", "date", "publisher", "dedication",
})
_FRONTMATTER_MARKER_COMMANDS = frozenset({
    "maketitle", "tableofcontents", "listoffigures", "listoftables",
    "frontmatter", "mainmatter", "backmatter", "appendix",
})


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(str(value).encode("utf-8"))


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _bounded(value: object, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _balanced_end(text: str, opening: int, open_char: str, close_char: str) -> int | None:
    if opening >= len(text) or text[opening] != open_char:
        return None
    depth = 1
    index = opening + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _is_escaped_command(text: str, offset: int) -> bool:
    """Return whether the command slash at ``offset`` is itself escaped.

    Regex searches can otherwise start at the second slash in ``\\\\section``
    and incorrectly treat displayed/sample source as an active command.
    """
    preceding = 0
    cursor = int(offset) - 1
    while cursor >= 0 and text[cursor] == "\\":
        preceding += 1
        cursor -= 1
    return bool(preceding % 2)


def _environment_scan(
    doc: Document,
) -> tuple[tuple[tuple[str, int, int, int, int], ...], tuple[str, ...]]:
    """Pair active environments independently of the legacy parser regex.

    ``Document.masked`` keeps offsets stable while removing comments, protected
    bodies and inline verbatim.  The extra slash-parity check prevents literal
    examples from corrupting the environment stack.
    """
    stack: list[tuple[str, int, int]] = []
    ranges: list[tuple[str, int, int, int, int]] = []
    broken: list[str] = []
    for match in _ENV_TOKEN_RE.finditer(doc.masked):
        if _is_escaped_command(doc.masked, match.start()):
            continue
        name = match.group("name").strip()
        if not name:
            continue
        if match.group("kind") == "begin":
            stack.append((name, match.start(), match.end()))
            continue
        if stack and stack[-1][0] == name:
            opened_name, begin_start, begin_end = stack.pop()
            ranges.append(
                (opened_name, begin_start, begin_end, match.start(), match.end())
            )
        else:
            broken.append(name)
    broken.extend(name for name, _start, _end in stack)
    ranges.sort(key=lambda item: (item[1], item[3]))
    return tuple(ranges), tuple(sorted(set(broken)))


@dataclass(frozen=True, slots=True)
class _CommandOccurrence:
    name: str
    starred: bool
    optional: tuple[str, ...]
    required: tuple[str, ...]
    start: int
    end: int


def _command_pattern(names: Iterable[str]) -> re.Pattern[str]:
    alternatives = "|".join(sorted((re.escape(name) for name in names), key=len, reverse=True))
    return re.compile(rf"\\(?P<name>{alternatives})(?![A-Za-z@])")


def _scan_commands(
    doc: Document,
    names: Iterable[str],
    *,
    minimum_required: int,
    maximum_required: int | None = None,
    bounds: tuple[int, int] | None = None,
) -> tuple[tuple[_CommandOccurrence, ...], tuple[str, ...]]:
    pattern = _command_pattern(names)
    lower, upper = bounds or (0, len(doc.masked))
    found: list[_CommandOccurrence] = []
    errors: list[str] = []
    for match in pattern.finditer(doc.masked, lower, upper):
        if _is_escaped_command(doc.masked, match.start()):
            continue
        cursor = match.end()
        while cursor < upper and doc.masked[cursor].isspace():
            cursor += 1
        starred = cursor < upper and doc.masked[cursor] == "*"
        if starred:
            cursor += 1
        optional: list[str] = []
        while True:
            while cursor < upper and doc.masked[cursor].isspace():
                cursor += 1
            if cursor >= upper or doc.masked[cursor] != "[":
                break
            end = _balanced_end(doc.masked, cursor, "[", "]")
            if end is None or end > upper:
                errors.append(f"malformed \\{match.group('name')} optional argument")
                cursor = -1
                break
            optional.append(doc.text[cursor + 1:end - 1])
            cursor = end
        if cursor < 0:
            continue
        required: list[str] = []
        while maximum_required is None or len(required) < maximum_required:
            while cursor < upper and doc.masked[cursor].isspace():
                cursor += 1
            if cursor >= upper or doc.masked[cursor] != "{":
                break
            end = _balanced_end(doc.masked, cursor, "{", "}")
            if end is None or end > upper:
                errors.append(f"malformed \\{match.group('name')} required argument")
                cursor = -1
                break
            required.append(doc.text[cursor + 1:end - 1])
            cursor = end
        if cursor < 0:
            continue
        if len(required) < minimum_required:
            errors.append(f"\\{match.group('name')} lacks a required argument")
            continue
        found.append(_CommandOccurrence(
            name=match.group("name"),
            starred=starred,
            optional=tuple(optional),
            required=tuple(required),
            start=match.start(),
            end=cursor,
        ))
    return tuple(found), tuple(dict.fromkeys(errors))


def _body_bounds(doc: Document) -> tuple[int, int]:
    ranges, _broken = _environment_scan(doc)
    document = next((item for item in ranges if item[0] == "document"), None)
    return (document[2], document[3]) if document is not None else (0, len(doc.masked))


def _source(doc: Document, start: int, end: int) -> str:
    return doc.text[max(0, start):max(start, end)]


def _line_range(doc: Document, start: int, end: int) -> tuple[int, int]:
    return (
        offset_to_line(doc.line_starts, start),
        offset_to_line(doc.line_starts, max(start, end - 1)),
    )


def _normalize_tex(value: str) -> str:
    text = mask_comments(str(value or ""))
    text = _PAGE_MARKER_COMMAND_RE.sub(" ", text)
    text = _BEGIN_END_RE.sub(" ", text)
    text = _STRUCTURAL_METADATA_RE.sub(" ", text)
    for _ in range(12):
        updated = _PRESENTATION_ONE_ARG_RE.sub(r"\1", text)
        if updated == text:
            break
        text = updated
    text = re.sub(r"\\([{}%_&#$])", r"\1", text)
    text = text.replace("~", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text.casefold()


def _math_visible_identity(value: str) -> tuple[str, str]:
    """Return an exact, non-algebraic visible projection and printed number.

    The projection removes only TeX display wrappers, structural metadata,
    sizing/spacing controls and a small set of glyph aliases.  It deliberately
    preserves token order, grouping, case and operators: this is an inventory
    identity, not an equivalence checker and never authorizes a model to
    rewrite mathematical content.
    """
    text = mask_comments(str(value or ""))
    number = _first_tag(text)
    text = _PAGE_MARKER_COMMAND_RE.sub(" ", text)
    text = _BEGIN_END_RE.sub(" ", text)
    text = _STRUCTURAL_METADATA_RE.sub(" ", text)
    text = re.sub(r"\\(?:\[|\]|\(|\))", " ", text)
    text = text.replace("$$", " ")
    if not number:
        trailing = _TRAILING_DISPLAY_NUMBER_RE.search(text)
        if trailing is not None:
            number = trailing.group("number")
            text = text[:trailing.start()] + trailing.group("prefix")
    text = _MATH_INVISIBLE_COMMAND_RE.sub("", text)
    for command, glyph in sorted(
        _MATH_COMMAND_ALIASES.items(), key=lambda item: len(item[0]), reverse=True
    ):
        text = re.sub(
            re.escape(command) + r"(?![A-Za-z@])",
            lambda _match, replacement=glyph: replacement,
            text,
        )
    text = text.translate(str.maketrans({
        "−": "-",
        "–": "-",
        "—": "-",
        "⩽": "≤",
        "⩾": "≥",
        "ϵ": "ε",
    }))
    text = _UNICODE_SUPERSCRIPT_RE.sub(
        lambda match: "^" + match.group(0).translate(
            _UNICODE_SUPERSCRIPT_TRANSLATION
        ),
        text,
    )
    text = _UNICODE_SUBSCRIPT_RE.sub(
        lambda match: "_" + match.group(0).translate(
            _UNICODE_SUBSCRIPT_TRANSLATION
        ),
        text,
    )
    for _ in range(8):
        updated = _MATH_ATOMIC_SCRIPT_RE.sub(r"\1\2", text)
        if updated == text:
            break
        text = updated
    text = re.sub(r"\\([{}%_&#$])", r"\1", text)
    text = text.replace("~", " ")
    text = re.sub(r"\s+", "", text)
    return _bounded(number, 200), text.strip()


def _number_and_rest(value: str, *, strip_formal_prefix: bool = False) -> tuple[str, str]:
    text = _normalize_tex(value)
    if strip_formal_prefix:
        text = _FORMAL_PREFIX_RE.sub("", text, count=1)
    match = _LEADING_NUMBER_RE.match(text)
    if match is None:
        return "", text
    return match.group("number"), match.group("rest").strip() or text


def _first_label(value: str) -> str:
    match = _LABEL_RE.search(str(value or ""))
    return _bounded(match.group(1)) if match is not None else ""


def _first_tag(value: str) -> str:
    match = _TAG_RE.search(str(value or ""))
    return _bounded(match.group(1)) if match is not None else ""


def _declared_formal_environments(doc: Document) -> set[str]:
    return {
        match.group(1).strip()
        for match in _NEW_THEOREM_RE.finditer(doc.masked)
        if match.group(1).strip()
        and not _is_escaped_command(doc.masked, match.start())
    }


def _normalized_page_map(
    value: Mapping[int, Sequence[int]],
) -> Mapping[int, tuple[int, ...]]:
    if not isinstance(value, Mapping) or not value:
        raise AnalysisInventoryError("native source page map must be a non-empty mapping")
    normalized: dict[int, tuple[int, ...]] = {}
    for source_page, pdf_pages in value.items():
        if (
            not isinstance(source_page, int)
            or isinstance(source_page, bool)
            or source_page < 1
            or isinstance(pdf_pages, (str, bytes, bytearray))
            or not isinstance(pdf_pages, Sequence)
        ):
            raise AnalysisInventoryError("native source page map contains an invalid entry")
        pages = tuple(pdf_pages)
        if (
            not pages
            or tuple(sorted(set(pages))) != pages
            or any(
                not isinstance(page, int) or isinstance(page, bool) or page < 1
                for page in pages
            )
        ):
            raise AnalysisInventoryError("native source page map PDF pages are invalid")
        normalized[source_page] = pages
    if tuple(normalized) != tuple(sorted(normalized)):
        raise AnalysisInventoryError("native source page map keys must be strictly increasing")
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class _PageLocator:
    offsets: tuple[int, ...]
    pages: tuple[int, ...]
    source_page_map: Mapping[int, tuple[int, ...]]

    def locate(self, offset: int) -> tuple[int, tuple[int, ...]]:
        index = bisect_right(self.offsets, int(offset)) - 1
        if index < 0:
            return 0, ()
        page = self.pages[index]
        return page, self.source_page_map.get(page, ())


@dataclass(frozen=True, slots=True)
class _PageObservation:
    locator: _PageLocator
    page_sequence: tuple[int, ...]
    errors: tuple[str, ...]


def _page_observation(
    tex: str,
    source_page_map: Mapping[int, tuple[int, ...]],
) -> _PageObservation:
    expected_pages = tuple(source_page_map)
    expected_ids = {
        f"ocr-page-{index:06d}": page
        for index, page in enumerate(expected_pages, start=1)
    }
    anchors: list[tuple[int, int]] = []
    errors: list[str] = []
    for match in _PAGE_COMMENT_RE.finditer(tex):
        page_id = match.group(1)
        page = int(match.group(2))
        if expected_ids.get(page_id) != page or page not in source_page_map:
            errors.append(f"page marker {page_id}/{page} differs from native page map")
            continue
        anchors.append((match.start(), page))
    # The production v2 bridge historically froze ``% Page N`` markers.  The
    # native map remains authoritative; these markers only provide offsets and
    # are accepted when N is one of its exact selected source pages.
    for match in _LEGACY_PAGE_COMMENT_RE.finditer(tex):
        page = int(match.group(1))
        if page not in source_page_map:
            errors.append(f"legacy page marker {page} differs from native page map")
            continue
        anchors.append((match.start(), page))
    masked = mask_comments(tex)
    for match in _PAGE_TARGET_RE.finditer(masked):
        if _is_escaped_command(masked, match.start()):
            continue
        page_id = match.group(1)
        page = expected_ids.get(page_id)
        if page is None:
            errors.append(f"page target {page_id} differs from native page map")
            continue
        anchors.append((match.start(), page))
    anchors.sort()
    sequence: list[int] = []
    for _offset, page in anchors:
        if not sequence or sequence[-1] != page:
            sequence.append(page)
    if tuple(sequence) != expected_pages:
        errors.append(
            "page anchors do not cover the native selected pages in exact order"
        )
    return _PageObservation(
        locator=_PageLocator(
            offsets=tuple(offset for offset, _page in anchors),
            pages=tuple(page for _offset, page in anchors),
            source_page_map=source_page_map,
        ),
        page_sequence=tuple(sequence),
        errors=tuple(dict.fromkeys(errors)),
    )


@dataclass(frozen=True, slots=True)
class _RawItem:
    kind: str
    start: int
    end: int
    source: str
    match_text: str
    number: str = ""
    label: str = ""
    title: str = ""
    representation: str = "syntax"
    source_sha256_override: str = ""


@dataclass(frozen=True, slots=True)
class _RawFinding:
    kind: InventoryResidualKind
    line: int
    detail: str


@dataclass(frozen=True, slots=True)
class _ScanOutput:
    items: tuple[_RawItem, ...] = ()
    findings: tuple[_RawFinding, ...] = ()
    errors: tuple[str, ...] = ()
    scanner_executed: bool = True


@dataclass(frozen=True, slots=True)
class AnalysisInventoryItem:
    stable_id: str
    category: str
    kind: str
    ordinal: int
    start_line: int
    end_line: int
    source_page: int
    baseline_pdf_pages: tuple[int, ...]
    number: str
    label: str
    title: str
    representation: str
    semantic_sha256: str
    source_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "stable_id": self.stable_id,
            "category": self.category,
            "kind": self.kind,
            "ordinal": self.ordinal,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "source_page": self.source_page or None,
            "baseline_pdf_pages": list(self.baseline_pdf_pages),
            "number": self.number or None,
            "label": self.label or None,
            "title": self.title or None,
            "representation": self.representation,
            "semantic_sha256": self.semantic_sha256,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True, slots=True)
class AnalysisInventoryResidual:
    residual_id: str
    category: str
    kind: InventoryResidualKind
    baseline_item_id: str = ""
    current_item_id: str = ""
    baseline_value: str = ""
    current_value: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "residual_id": self.residual_id,
            "category": self.category,
            "kind": self.kind.value,
            "baseline_item_id": self.baseline_item_id or None,
            "current_item_id": self.current_item_id or None,
            "baseline_value": self.baseline_value or None,
            "current_value": self.current_value or None,
            "detail": self.detail,
        }


def _residual(
    category: str,
    kind: InventoryResidualKind,
    *,
    baseline_item: AnalysisInventoryItem | None = None,
    current_item: AnalysisInventoryItem | None = None,
    baseline_value: object = "",
    current_value: object = "",
    detail: str,
) -> AnalysisInventoryResidual:
    payload = {
        "category": category,
        "kind": kind.value,
        "baseline_item_id": baseline_item.stable_id if baseline_item else "",
        "current_item_id": current_item.stable_id if current_item else "",
        "baseline_value": str(baseline_value or ""),
        "current_value": str(current_value or ""),
        "detail": str(detail or ""),
    }
    digest = _sha256_bytes(_canonical_json_bytes(payload))
    return AnalysisInventoryResidual(
        residual_id=f"inventory-residual:{category}:{kind.value.casefold()}:{digest[:20]}",
        category=category,
        kind=kind,
        baseline_item_id=payload["baseline_item_id"],
        current_item_id=payload["current_item_id"],
        baseline_value=payload["baseline_value"],
        current_value=payload["current_value"],
        detail=_bounded(detail, 1000),
    )


def _stable_items(
    category: str,
    doc: Document,
    locator: _PageLocator,
    raw_items: Sequence[_RawItem],
) -> tuple[AnalysisInventoryItem, ...]:
    occurrences: Counter[str] = Counter()
    result: list[AnalysisInventoryItem] = []
    for raw in sorted(raw_items, key=lambda item: (item.start, item.end, item.kind)):
        if category == "equation":
            _number, semantic = _math_visible_identity(
                raw.match_text or raw.source
            )
        else:
            semantic = (
                _normalize_tex(raw.match_text)
                or _normalize_tex(raw.source)
            )
        semantic = semantic or raw.kind
        semantic_sha = _sha256_text(semantic)
        occurrences[semantic_sha] += 1
        ordinal = occurrences[semantic_sha]
        start_line, end_line = _line_range(doc, raw.start, raw.end)
        source_page, pdf_pages = locator.locate(raw.start)
        result.append(AnalysisInventoryItem(
            stable_id=(
                f"inventory:{category}:{semantic_sha[:20]}:{ordinal:04d}"
            ),
            category=category,
            kind=str(raw.kind),
            ordinal=ordinal,
            start_line=start_line,
            end_line=end_line,
            source_page=source_page,
            baseline_pdf_pages=tuple(pdf_pages),
            number=_bounded(raw.number, 200),
            label=_bounded(raw.label, 300),
            title=_bounded(raw.title, 500),
            representation=_bounded(raw.representation, 100),
            semantic_sha256=semantic_sha,
            source_sha256=(raw.source_sha256_override or _sha256_text(raw.source)),
        ))
    return tuple(result)


def _unbalanced_error(doc: Document, relevant: set[str]) -> tuple[str, ...]:
    _ranges, unbalanced = _environment_scan(doc)
    broken = [name for name in unbalanced if name in relevant]
    return (
        (f"unbalanced relevant environments: {', '.join(sorted(set(broken)))}",)
        if broken else ()
    )


def _native_heading_kind(doc: Document, number: str) -> str:
    del doc  # Native OCR blocks currently carry depth, not a chapter flag.
    depth = number.count(".") + 1 if number else 1
    levels = ("section", "subsection", "subsubsection", "paragraph")
    return levels[min(depth - 1, len(levels) - 1)]


_FORMAL_KIND_MAP = MappingProxyType({
    "theorem": "theorem",
    "lemma": "lemma",
    "proposition": "proposition",
    "corollary": "corollary",
    "definition": "definition",
    "remark": "remark",
    "example": "example",
    "conjecture": "conjecture",
    "problem": "problem",
    "question": "question",
    "claim": "claim",
    "fact": "fact",
    "observation": "observation",
    "note": "remark",
    "exercise": "exercise",
    "result": "theorem",
    "定理": "theorem",
    "引理": "lemma",
    "命题": "proposition",
    "推论": "corollary",
    "定义": "definition",
    "注记": "remark",
    "注": "remark",
    "例": "example",
    "猜想": "conjecture",
    "问题": "problem",
    "断言": "claim",
    "事实": "fact",
    "观察": "observation",
    "练习": "exercise",
})


def _native_formal_kind(value: str) -> str:
    match = _FORMAL_KIND_PREFIX_RE.match(_normalize_tex(value))
    if match is None:
        return "theorem"
    return _FORMAL_KIND_MAP.get(match.group("kind").casefold(), "theorem")


def _native_block_category(block: AnalysisNativeSourceBlock) -> str:
    block_type = block.block_type.strip().upper()
    if block_type == "HEADING_TEXT":
        normalized = _normalize_tex(block.plain_text)
        if _PROOF_PREFIX_RE.match(normalized):
            return "proof"
        if _FORMAL_PREFIX_RE.match(normalized):
            return "formal"
        return "heading"
    return {
        "DISPLAY_MATH": "equation",
        "FOOTNOTE": "footnote",
        "CAPTION": "caption",
        "BIBLIOGRAPHY_ITEM": "bibliography",
        "FIGURE": "figure",
        "TABLE": "table",
    }.get(block_type, "")


def _native_plain_identity(
    category: str,
    block: AnalysisNativeSourceBlock,
) -> tuple[str, str, str, str]:
    """Return ``kind, number, semantic, title`` for one native plain block."""
    text = block.plain_text.strip()
    normalized = _normalize_tex(text)
    if category == "formal":
        number, rest = _number_and_rest(text)
        semantic = _FORMAL_PREFIX_RE.sub("", normalized, count=1)
        return _native_formal_kind(text), number, semantic or rest or normalized, text
    if category == "proof":
        semantic = _FORMAL_PREFIX_RE.sub("", normalized, count=1)
        return "proof", "", semantic or normalized, text
    if category == "footnote":
        match = _FOOTNOTE_MARKER_RE.match(text)
        if match is None:
            return "footnote", "", normalized, text
        marker = match.group("bracket") or match.group("number") or match.group("symbol")
        return "footnote", marker, _normalize_tex(match.group("body")), match.group("body").strip()
    if category == "bibliography":
        match = _BIBLIOGRAPHY_MARKER_RE.match(text)
        if match is None:
            return "bibitem", "", normalized, text
        marker = match.group("bracket") or match.group("number") or ""
        return "bibitem", marker, _normalize_tex(match.group("body")), match.group("body").strip()
    if category == "caption":
        match = _CAPTION_PREFIX_RE.match(text)
        if match is None:
            return "caption", "", normalized, text
        prefix = match.group("kind").casefold().rstrip(".")
        kind = "table:caption" if prefix in {"table", "表"} else "figure:caption"
        body = match.group("body").strip()
        return kind, match.group("number") or "", _normalize_tex(body) or normalized, body or text
    if category == "equation":
        number, semantic = _math_visible_identity(text)
        return (
            _NATIVE_DISPLAY_MATH_KIND,
            number,
            semantic or text,
            text,
        )
    if category in {"figure", "table"}:
        return category, "", normalized, text
    raise AnalysisInventoryError(f"native block category {category!r} is unsupported")


def _native_footnote_fragment_errors(
    blocks: Sequence[AnalysisNativeSourceBlock],
) -> tuple[str, ...]:
    """Reject ambiguous PDF footnote fragments instead of over-counting them.

    Multiple blocks on one source page are admitted only when each begins with
    a distinct, explicit printed marker.  Without geometry/group identifiers,
    treating unmarked continuation fragments as separate footnotes would be an
    unsafe false PASS.
    """
    by_page: defaultdict[int, list[AnalysisNativeSourceBlock]] = defaultdict(list)
    for block in blocks:
        by_page[block.source_page].append(block)
    errors: list[str] = []
    for source_page, page_blocks in sorted(by_page.items()):
        if len(page_blocks) < 2:
            continue
        markers: list[str] = []
        for block in page_blocks:
            match = _FOOTNOTE_MARKER_RE.match(block.plain_text)
            if match is None:
                markers = []
                break
            markers.append(
                match.group("bracket") or match.group("number")
                or match.group("symbol") or ""
            )
        if not markers or len(markers) != len(set(markers)):
            errors.append(
                "native FOOTNOTE blocks on source page "
                f"{source_page} lack authoritative fragment grouping"
            )
    return tuple(errors)


def build_host_inventory_authorizations(
    native_source_blocks: Sequence[
        AnalysisNativeSourceBlock | Mapping[str, object]
    ],
    *,
    ocr_manifest_sha256: str,
    generated_toc_required: bool = True,
) -> tuple[AnalysisInventoryAuthorization, ...]:
    """Freeze the minimum application-owned structural policy.

    The policy is derived only from the immutable native OCR block types and a
    host requirement for a generated table of contents.  No model response can
    add authorizations.  Content categories such as equations/references never
    receive an authorization from this builder.
    """
    if type(generated_toc_required) is not bool:
        raise AnalysisInventoryError("generated_toc_required must be a boolean")
    manifest_hash = str(ocr_manifest_sha256 or "").strip().lower()
    if _SHA256_RE.fullmatch(manifest_hash) is None:
        raise AnalysisInventoryError("host inventory policy OCR manifest hash is invalid")
    blocks = coerce_analysis_native_source_blocks(native_source_blocks)
    policy_payload = {
        "schema": "latexstruct-host-inventory-policy-v1",
        "native_source_blocks_digest": _sha256_bytes(_canonical_json_bytes([
            block.as_dict() for block in blocks
        ])),
        "ocr_manifest_sha256": manifest_hash,
        "generated_toc_required": generated_toc_required,
    }
    evidence_id = (
        "host-policy:analysis-v2-required-structure:"
        + _sha256_bytes(_canonical_json_bytes(policy_payload))
    )
    categories = {
        _native_block_category(block) for block in blocks
    } & {
        "heading", "formal", "proof", "footnote", "caption",
        "bibliography", "figure", "table",
    }
    result = [
        AnalysisInventoryAuthorization(
            authorization_id=f"host-required-structure:{category}",
            category=category,
            action=InventoryAuthorizationAction.STRUCTURE_WRAPPER,
            evidence_id=evidence_id,
        )
        for category in sorted(categories)
    ]
    if generated_toc_required:
        result.append(AnalysisInventoryAuthorization(
            authorization_id="host-required-structure:generated-toc",
            category="frontmatter",
            action=InventoryAuthorizationAction.GENERATED_TOC,
            evidence_id=evidence_id,
        ))
    return coerce_analysis_inventory_authorizations(result)


def _native_block_text_offset(
    doc: Document,
    block: AnalysisNativeSourceBlock,
    source_page_map: Mapping[int, tuple[int, ...]],
) -> tuple[int, int] | None:
    observation = _page_observation(doc.text, source_page_map)
    cursor = 0
    while True:
        start = doc.text.find(block.plain_text, cursor)
        if start < 0:
            return None
        if observation.locator.locate(start)[0] == block.source_page:
            return start, start + len(block.plain_text)
        cursor = start + 1

    # Unreachable above, retained as a structural guard for type checkers.
    return None


def _tex_visible_projection(value: str) -> tuple[str, tuple[int, ...], tuple[int, ...]]:
    """Project deterministic TeX literal escapes to visible text with offsets."""
    visible: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    index = 0
    escaped_visible = frozenset("{}%_&#$~")
    while index < len(value):
        char = value[index]
        source_start = index
        source_end = index + 1
        if value.startswith(r"\textbackslash{}", index):
            char = "\\"
            source_end = index + len(r"\textbackslash{}")
            index = source_end
        elif char == "\\" and index + 1 < len(value):
            following = value[index + 1]
            if following in escaped_visible:
                char = " " if following == "~" else following
                source_end = index + 2
                index += 2
            elif following == "\\":
                char = " "
                source_end = index + 2
                index += 2
            else:
                index += 1
        else:
            if char == "~":
                char = " "
            index += 1
        folded = char.casefold()
        for emitted in folded:
            if emitted.isspace():
                if visible and visible[-1] != " ":
                    visible.append(" ")
                    starts.append(source_start)
                    ends.append(source_end)
                continue
            visible.append(emitted)
            starts.append(source_start)
            ends.append(source_end)
    while visible and visible[0] == " ":
        visible.pop(0)
        starts.pop(0)
        ends.pop(0)
    while visible and visible[-1] == " ":
        visible.pop()
        starts.pop()
        ends.pop()
    return "".join(visible), tuple(starts), tuple(ends)


def _native_visible_block_text_offset(
    doc: Document,
    block: AnalysisNativeSourceBlock,
    source_page_map: Mapping[int, tuple[int, ...]],
) -> tuple[int, int] | None:
    """Find a native block through TeX literal escaping, restricted by page."""
    direct = _native_block_text_offset(doc, block, source_page_map)
    if direct is not None:
        return direct
    projected, starts, ends = _tex_visible_projection(doc.text)
    target, _target_starts, _target_ends = _tex_visible_projection(block.plain_text)
    if not target:
        return None
    observation = _page_observation(doc.text, source_page_map)
    cursor = 0
    while True:
        found = projected.find(target, cursor)
        if found < 0:
            return None
        source_start = starts[found]
        source_end = ends[found + len(target) - 1]
        if observation.locator.locate(source_start)[0] == block.source_page:
            return source_start, source_end
        cursor = found + 1


def _scan_with_native_plain_blocks(
    doc: Document,
    scan: _ScanOutput,
    *,
    category: str,
    native_blocks: Sequence[AnalysisNativeSourceBlock],
    source_page_map: Mapping[int, tuple[int, ...]] | None,
    source_side: bool,
) -> _ScanOutput:
    """Merge authoritative plain OCR blocks into one syntax scanner.

    The native block type selects the category.  Exact semantic matches consume
    an existing command/environment item; otherwise the source-side plain text
    becomes an inventory item, while an unchanged current-side plain block is
    an explicit ``UNSTRUCTURED`` residual.  A missing source block is a scanner
    failure, never an empty/NOT_APPLICABLE category.
    """
    routed = tuple(
        block for block in native_blocks
        if _native_block_category(block) == category
    )
    if not routed:
        return scan
    errors = list(scan.errors)
    if source_page_map is None:
        errors.append(f"native {category} inventory lacks a page map")
        return replace(scan, errors=tuple(dict.fromkeys(errors)))
    if category == "footnote":
        errors.extend(_native_footnote_fragment_errors(routed))
    items = list(scan.items)
    if category in {"formal", "proof"}:
        # Plain parser anchors may span several adjacent OCR blocks.  Once the
        # native typed inventory is present it is the sole authority for plain
        # formal/proof boundaries on both sides; keep only environments.
        items = [item for item in items if item.representation != "plain"]
    findings = (
        [] if category in {"formal", "proof"} else list(scan.findings)
    )
    used_indices: set[int] = set()
    for block in routed:
        kind, number, semantic, title = _native_plain_identity(category, block)
        location = _native_visible_block_text_offset(doc, block, source_page_map)

        if source_side and location is not None:
            containing = next((
                index for index, item in enumerate(items)
                if index not in used_indices
                and item.start <= location[0] < location[1] <= item.end
            ), None)
            if containing is not None:
                used_indices.add(containing)
                item = items[containing]
                if _normalize_tex(item.source) == _normalize_tex(block.plain_text):
                    items[containing] = replace(
                        item,
                        source_sha256_override=block.source_sha256,
                    )
                continue

        matching = next((
            index for index, item in enumerate(items)
            if index not in used_indices
            and _normalize_tex(item.match_text) == semantic
        ), None)
        if matching is not None:
            used_indices.add(matching)
            if source_side:
                item = items[matching]
                if _normalize_tex(item.source) == _normalize_tex(block.plain_text):
                    items[matching] = replace(
                        item,
                        source_sha256_override=block.source_sha256,
                    )
            continue

        if location is None:
            if source_side:
                errors.append(
                    f"native {category} block {block.block_id} is absent from baseline TeX"
                )
            continue
        start, end = location
        items.append(_RawItem(
            kind=kind,
            start=start,
            end=end,
            source=block.plain_text,
            match_text=semantic,
            number=number,
            title=title,
            representation="plain",
            source_sha256_override=block.source_sha256,
        ))
        if not source_side:
            line = offset_to_line(doc.line_starts, start)
            if not any(
                finding.kind is InventoryResidualKind.UNSTRUCTURED
                and finding.line == line
                for finding in findings
            ):
                findings.append(_RawFinding(
                    InventoryResidualKind.UNSTRUCTURED,
                    line,
                    f"native {category} block {block.block_id} remains unstructured",
                ))
    return _ScanOutput(
        tuple(items),
        tuple(findings),
        tuple(dict.fromkeys(errors)),
        scan.scanner_executed,
    )


def _scan_with_native_equation_blocks(
    doc: Document,
    scan: _ScanOutput,
    *,
    native_blocks: Sequence[AnalysisNativeSourceBlock],
    source_page_map: Mapping[int, tuple[int, ...]] | None,
    source_side: bool,
) -> _ScanOutput:
    """Bind every native DISPLAY_MATH block to exactly one equation item.

    Source-side items retain the immutable OCR object hash and a ``plain``
    representation even when the verified OCR baseline already contains a
    display wrapper.  Candidate-side items may use a display environment or
    delimiter, but their exact non-algebraic visible projection remains the
    stable identity.  Same-page ordinal binding is only a provenance bridge
    for PDF text layers whose extraction order cannot reproduce TeX layout;
    baseline/candidate projection comparison still detects every content
    change.
    """
    routed = tuple(
        block for block in native_blocks
        if _native_block_category(block) == "equation"
    )
    if not routed:
        return scan
    errors = list(scan.errors)
    if source_page_map is None:
        errors.append("native equation inventory lacks a page map")
        return replace(scan, errors=tuple(dict.fromkeys(errors)))
    observation = _page_observation(doc.text, source_page_map)
    items = list(scan.items)
    syntax_item_count = len(items)
    findings = list(scan.findings)
    used_indices: set[int] = set()

    def item_page(index: int) -> int:
        return observation.locator.locate(items[index].start)[0]

    def item_identity(index: int) -> str:
        _number, semantic = _math_visible_identity(
            items[index].match_text or items[index].source
        )
        return semantic

    for block in routed:
        kind, native_number, native_semantic, title = _native_plain_identity(
            "equation", block
        )
        location = _native_visible_block_text_offset(doc, block, source_page_map)
        page_indices = sorted(
            (
                index for index in range(syntax_item_count)
                if index not in used_indices
                and item_page(index) == block.source_page
            ),
            key=lambda index: (items[index].start, items[index].end, index),
        )
        matching: int | None = None
        if location is not None:
            matching = next((
                index for index in page_indices
                if items[index].start <= location[0] < location[1] <= items[index].end
            ), None)
        if matching is None:
            matching = next((
                index for index in page_indices
                if item_identity(index) == native_semantic
            ), None)

        # Exact plain text on the candidate side must remain visibly
        # unstructured.  Do not let an unrelated same-page equation consume it.
        if matching is None and location is not None:
            start, end = location
            items.append(_RawItem(
                kind=kind,
                start=start,
                end=end,
                source=block.plain_text,
                match_text=native_semantic,
                number=native_number,
                title=title,
                representation="plain",
                source_sha256_override=block.source_sha256,
            ))
            if not source_side:
                findings.append(_RawFinding(
                    InventoryResidualKind.UNSTRUCTURED,
                    offset_to_line(doc.line_starts, start),
                    f"native equation block {block.block_id} remains unstructured",
                ))
            continue

        # A verified OCR baseline can contain TeX recovered from visual block
        # evidence while the immutable PDF text-layer block remains non-TeX.
        # Pair these by exact source page/read order.  This does not make them
        # semantically equal: the resulting projection is compared to the
        # independently scanned candidate and any rewrite remains residual.
        if matching is None and page_indices:
            matching = page_indices[0]

        if matching is None:
            if source_side:
                errors.append(
                    f"native equation block {block.block_id} is absent from baseline TeX"
                )
            continue

        used_indices.add(matching)
        matched = items[matching]
        matched_number, matched_semantic = _math_visible_identity(
            matched.match_text or matched.source
        )
        if source_side:
            items[matching] = _RawItem(
                kind=_NATIVE_DISPLAY_MATH_KIND,
                start=matched.start,
                end=matched.end,
                source=block.plain_text,
                match_text=matched_semantic,
                number=matched.number or matched_number or native_number,
                label=matched.label,
                title=title,
                representation="plain",
                source_sha256_override=block.source_sha256,
            )
        else:
            items[matching] = replace(
                matched,
                kind=_NATIVE_DISPLAY_MATH_KIND,
                match_text=matched_semantic,
                number=matched.number or matched_number,
                representation="syntax",
                source_sha256_override="",
            )
    return _ScanOutput(
        tuple(items),
        tuple(findings),
        tuple(dict.fromkeys(errors)),
        scan.scanner_executed,
    )


def _scan_with_native_object_coverage(
    doc: Document,
    scan: _ScanOutput,
    *,
    category: str,
    native_blocks: Sequence[AnalysisNativeSourceBlock],
    source_page_map: Mapping[int, tuple[int, ...]] | None,
    source_side: bool,
) -> _ScanOutput:
    """Bind textless native objects to concrete, exact TeX syntax.

    Page-level counts are insufficient evidence: an unrelated image on the
    same page could otherwise make a missing native drawing appear present.
    Host-materialized objects therefore bind one-to-one to their canonical
    path.  Their immutable object hash seeds only the source-side item; no
    visible body text is fabricated.  Legacy text-bearing object blocks keep
    the older conservative page-coverage check.
    """
    routed = tuple(
        block for block in native_blocks
        if _native_block_category(block) == category
    )
    if not routed:
        return scan
    errors = list(scan.errors)
    if source_page_map is None:
        errors.append(f"native {category} inventory lacks a page map")
        return replace(scan, errors=tuple(dict.fromkeys(errors)))
    observation = _page_observation(doc.text, source_page_map)
    original_items = list(scan.items)
    item_counts = Counter(
        observation.locator.locate(item.start)[0] for item in original_items
    )
    text_blocks = tuple(block for block in routed if block.plain_text.strip())
    block_counts = Counter(block.source_page for block in text_blocks)
    for source_page, expected in sorted(block_counts.items()):
        observed = item_counts[source_page]
        if observed < expected:
            errors.append(
                f"native {category} object coverage on source page {source_page} "
                f"is {observed}/{expected}"
            )

    object_blocks = tuple(block for block in routed if not block.plain_text.strip())
    if not object_blocks:
        return replace(scan, errors=tuple(dict.fromkeys(errors)))
    graphics, graphic_errors = _scan_commands(
        doc,
        {"includegraphics"},
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    errors.extend(graphic_errors)
    matched_commands: dict[str, _CommandOccurrence] = {}
    for block in object_blocks:
        if not block.object_path:
            errors.append(
                f"textless native {category} block {block.block_id} "
                "lacks a host object path"
            )
            continue
        matches = tuple(
            command for command in graphics
            if command.required[0].strip() == block.object_path
            and observation.locator.locate(command.start)[0] == block.source_page
        )
        if len(matches) != 1:
            errors.append(
                f"native {category} block {block.block_id} has "
                f"{len(matches)} exact TeX object references"
            )
            continue
        matched_commands[block.object_path] = matches[0]

    removed_indices: set[int] = set()
    additions: list[_RawItem] = []
    for block in object_blocks:
        command = matched_commands.get(block.object_path)
        if command is None:
            continue
        containing = next((
            index for index, item in enumerate(original_items)
            if item.start <= command.start < command.end <= item.end
        ), None)
        if containing is not None:
            removed_indices.add(containing)
            representation = (
                "environment"
                if original_items[containing].kind in {
                    "figure", "figure*", *_TABLE_ENVIRONMENTS,
                }
                else "command"
            )
        else:
            representation = "command"
        additions.append(_RawItem(
            kind=category,
            start=command.start,
            end=command.end,
            source=_source(doc, command.start, command.end),
            match_text=block.object_path,
            title=block.object_path,
            representation="plain" if source_side else representation,
            source_sha256_override=block.source_sha256 if source_side else "",
        ))

    # If one native object lived inside an environment that also contained an
    # unowned graphic, retain the latter as an ordinary scanner item so it is
    # reported as ADDED rather than hidden by replacing the environment item.
    matched_paths = frozenset(matched_commands)
    for command in graphics:
        if command.required[0].strip() in matched_paths:
            continue
        if any(
            original_items[index].start <= command.start < command.end
            <= original_items[index].end
            for index in removed_indices
        ):
            path = command.required[0].strip()
            additions.append(_RawItem(
                kind="includegraphics",
                start=command.start,
                end=command.end,
                source=_source(doc, command.start, command.end),
                match_text=path,
                title=path,
                representation="command",
            ))
    items = [
        item for index, item in enumerate(original_items)
        if index not in removed_indices
    ]
    items.extend(additions)
    return _ScanOutput(
        tuple(items),
        scan.findings,
        tuple(dict.fromkeys(errors)),
        scan.scanner_executed,
    )


def _scan_heading(
    doc: Document,
    *,
    native_blocks: Sequence[AnalysisNativeSourceBlock] = (),
    source_page_map: Mapping[int, tuple[int, ...]] | None = None,
    source_side: bool = False,
    require_native: bool = False,
    native_inventory_supplied: bool = False,
) -> _ScanOutput:
    commands, errors = _scan_commands(
        doc,
        _HEADING_COMMANDS,
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    items: list[_RawItem] = []
    for command in commands:
        title = command.required[0]
        number, rest = _number_and_rest(title)
        source = _source(doc, command.start, command.end)
        items.append(_RawItem(
            kind=command.name + ("*" if command.starred else ""),
            start=command.start,
            end=command.end,
            source=source,
            match_text=(rest or title).rstrip(".:：。 "),
            number=number,
            label=_first_label(source),
            title=title,
            representation="command",
        ))
    native_headings = tuple(
        block for block in native_blocks if _native_block_category(block) == "heading"
    )
    if require_native and not native_inventory_supplied:
        errors = (*errors, "native source block inventory is required")
    if native_headings and source_page_map is None:
        errors = (*errors, "native HEADING_TEXT inventory lacks a page map")
        return _ScanOutput(tuple(items), errors=tuple(dict.fromkeys(errors)))

    command_semantics = Counter(
        _normalize_tex(item.match_text) for item in items
    )
    findings: list[_RawFinding] = []
    for block in native_headings:
        number, rest = _number_and_rest(block.plain_text)
        semantic = _normalize_tex(rest or block.plain_text).rstrip(".:：。 ")
        if command_semantics[semantic] > 0:
            command_semantics[semantic] -= 1
            continue
        location = _native_visible_block_text_offset(
            doc, block, source_page_map or {}
        )
        if location is None:
            if source_side:
                errors = (
                    *errors,
                    f"native heading block {block.block_id} is absent from baseline TeX",
                )
            continue
        start, end = location
        items.append(_RawItem(
            kind=_native_heading_kind(doc, number),
            start=start,
            end=end,
            source=block.plain_text,
            match_text=semantic,
            number=number,
            title=block.plain_text,
            representation="plain",
            source_sha256_override=block.source_sha256,
        ))
        if not source_side:
            findings.append(_RawFinding(
                InventoryResidualKind.UNSTRUCTURED,
                offset_to_line(doc.line_starts, start),
                f"native heading block {block.block_id} remains outside a heading command",
            ))
    return _ScanOutput(
        tuple(items),
        tuple(findings),
        tuple(dict.fromkeys(errors)),
    )


def _formal_source_for_anchor(doc: Document, block_id: int | None, line: int) -> tuple[int, int, str]:
    block = next((item for item in doc.blocks if item.id == block_id), None)
    if block is not None:
        return block.span.start_off, block.span.end_off, block.text
    start = doc.line_starts[line - 1]
    end = doc.line_starts[line] if line < len(doc.line_starts) else len(doc.text)
    return start, end, _source(doc, start, end)


def _environment_optional_title(doc: Document, begin_end: int, limit: int) -> str:
    cursor = begin_end
    while cursor < limit and doc.masked[cursor].isspace():
        cursor += 1
    if cursor >= limit or doc.masked[cursor] != "[":
        return ""
    end = _balanced_end(doc.masked, cursor, "[", "]")
    return _source(doc, cursor + 1, end - 1).strip() if end is not None else ""


def _scan_formal_or_proof(
    doc: Document,
    *,
    proof: bool,
    native_blocks: Sequence[AnalysisNativeSourceBlock] = (),
    source_page_map: Mapping[int, tuple[int, ...]] | None = None,
    source_side: bool = False,
) -> _ScanOutput:
    declared = _declared_formal_environments(doc)
    structured = set(FORMAL_ENVIRONMENTS) | declared
    structured |= {f"{name}*" for name in structured if not name.endswith("*")}
    inventory = inventory_document(doc, structured_envs=declared)
    relevant = {
        name for name in structured
        if (name.removesuffix("*").casefold() in {"proof", "solution"}) is proof
    }
    errors = _unbalanced_error(doc, relevant | {f"{name}*" for name in relevant})
    lower, upper = _body_bounds(doc)
    scanned_ranges, _broken = _environment_scan(doc)
    valid_ranges = [
        item for item in scanned_ranges
        if item[0] in relevant and lower <= item[1] < item[4] <= upper
    ]
    anchors = [
        item for item in inventory.anchors
        if (item.suggested_env == "proof") is proof
        and lower <= doc.line_starts[item.start_line - 1] < upper
    ]
    items: list[_RawItem] = []
    used_anchor_ids: set[str] = set()
    for name, start, begin_end, end_start, end in valid_ranges:
        start_line, end_line = _line_range(doc, start, end)
        environment = next(
            (
                item for item in inventory.environments
                if item.original_env == name
                and item.start_line == start_line
                and item.end_line == offset_to_line(doc.line_starts, end_start)
            ),
            None,
        )
        source = _source(doc, start, end)
        inside = [
            anchor for anchor in anchors
            if start_line <= anchor.start_line <= end_line
        ]
        anchor = inside[0] if inside else None
        if anchor is not None:
            used_anchor_ids.add(anchor.id)
        optional_title = (
            environment.optional_title
            if environment is not None
            else _environment_optional_title(doc, begin_end, end_start)
        )
        title = anchor.visible_text if anchor else optional_title
        number = anchor.number if anchor else _number_and_rest(title)[0]
        semantic = _normalize_tex(source)
        semantic = _FORMAL_PREFIX_RE.sub("", semantic, count=1)
        if not semantic:
            _ignored, semantic = _number_and_rest(title, strip_formal_prefix=True)
        base_name = name.removesuffix("*").casefold()
        suggested = (
            "proof"
            if base_name in {"proof", "solution"}
            else environment.suggested_env
            if environment is not None
            else base_name
        )
        items.append(_RawItem(
            kind=("proof" if proof else suggested),
            start=start,
            end=end,
            source=source,
            match_text=semantic or title or name,
            number=number,
            label=_first_label(source),
            title=title,
            representation="environment",
        ))
    for anchor in anchors:
        if anchor.id in used_anchor_ids:
            continue
        start, end, source = _formal_source_for_anchor(doc, anchor.block_id, anchor.start_line)
        if not (lower <= start < upper):
            continue
        semantic = _normalize_tex(source)
        semantic = _FORMAL_PREFIX_RE.sub("", semantic, count=1)
        items.append(_RawItem(
            kind="proof" if proof else anchor.suggested_env,
            start=start,
            end=end,
            source=source,
            match_text=semantic or anchor.visible_text,
            number=anchor.number,
            label=_first_label(source),
            title=anchor.visible_text,
            representation="plain",
        ))
    findings: list[_RawFinding] = []
    for finding in inventory.findings:
        finding_offset = doc.line_starts[finding.start_line - 1]
        if not (lower <= finding_offset < upper):
            continue
        is_proof_finding = (
            finding.suggested_env == "proof"
            or finding.original_env.removesuffix("*").casefold() in {"proof", "solution"}
        )
        if is_proof_finding is not proof:
            continue
        kind = (
            InventoryResidualKind.UNSTRUCTURED
            if finding.kind == "missing"
            else InventoryResidualKind.DUPLICATE
            if finding.kind == "duplicate"
            else InventoryResidualKind.INVALID_STRUCTURE
        )
        findings.append(_RawFinding(kind, finding.start_line, finding.reason))
    return _scan_with_native_plain_blocks(
        doc,
        _ScanOutput(tuple(items), tuple(findings), errors),
        category="proof" if proof else "formal",
        native_blocks=native_blocks,
        source_page_map=source_page_map,
        source_side=source_side,
    )


def _top_level_environment_ranges(
    doc: Document,
    names: set[str] | frozenset[str],
) -> list[tuple[str, int, int, int, int]]:
    lower, upper = _body_bounds(doc)
    scanned, _broken = _environment_scan(doc)
    ranges = [
        item for item in scanned
        if item[0] in names and lower <= item[1] < item[4] <= upper
    ]
    result = []
    for item in ranges:
        _name, begin_start, _begin_end, end_start, _end_end = item
        if any(
            other[1] < begin_start and end_start < other[3]
            for other in ranges
        ):
            continue
        result.append(item)
    return result


def _scan_equation(doc: Document) -> _ScanOutput:
    errors = list(_unbalanced_error(doc, set(_MATH_ENVIRONMENTS)))
    items: list[_RawItem] = []
    lower, upper = _body_bounds(doc)
    environment_ranges = _top_level_environment_ranges(doc, _MATH_ENVIRONMENTS)
    for name, begin_start, _begin_end, _end_start, end_end in environment_ranges:
        source = _source(doc, begin_start, end_end)
        tag, semantic = _math_visible_identity(source)
        items.append(_RawItem(
            kind=name,
            start=begin_start,
            end=end_end,
            source=source,
            match_text=semantic,
            number=tag,
            label=_first_label(source),
            title=tag,
        ))
    for start, end in doc.display_spans:
        if not (lower <= start < end <= upper):
            continue
        if _is_escaped_command(doc.masked, start):
            continue
        if any(item[1] <= start < item[4] for item in environment_ranges):
            continue
        source = _source(doc, start, end)
        kind = "bracket-display" if source.lstrip().startswith("\\[") else "dollar-display"
        tag, semantic = _math_visible_identity(source)
        items.append(_RawItem(
            kind=kind,
            start=start,
            end=end,
            source=source,
            match_text=semantic,
            number=tag,
            label=_first_label(source),
        ))
    active_open = sum(
        not _is_escaped_command(doc.masked, match.start())
        for match in re.compile(r"\\\[").finditer(doc.masked, lower, upper)
    )
    active_close = sum(
        not _is_escaped_command(doc.masked, match.start())
        for match in re.compile(r"\\\]").finditer(doc.masked, lower, upper)
    )
    active_dollars = sum(
        not _is_escaped_command(doc.masked, match.start())
        for match in re.compile(r"\$\$").finditer(doc.masked, lower, upper)
    )
    if active_open != active_close or active_dollars % 2:
        errors.append("unbalanced display-math delimiters")
    return _ScanOutput(tuple(items), errors=tuple(dict.fromkeys(errors)))


def _split_keys(value: str) -> tuple[str, ...]:
    return tuple(key.strip() for key in str(value).split(",") if key.strip())


def _scan_key_commands(doc: Document, names: frozenset[str]) -> _ScanOutput:
    commands, errors = _scan_commands(
        doc,
        names,
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    items: list[_RawItem] = []
    for command in commands:
        source = _source(doc, command.start, command.end)
        for key in _split_keys(command.required[0]):
            items.append(_RawItem(
                kind=command.name,
                start=command.start,
                end=command.end,
                source=source,
                match_text=key,
                label=key,
                title=key,
            ))
    return _ScanOutput(tuple(items), errors=errors)


def _scan_reference(doc: Document) -> _ScanOutput:
    output = _scan_key_commands(doc, _REFERENCE_COMMANDS)
    hyperrefs, hyper_errors = _scan_commands(
        doc,
        {"hyperref"},
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    items = list(output.items)
    for command in hyperrefs:
        if not command.optional:
            continue
        key = command.optional[-1].strip()
        source = _source(doc, command.start, command.end)
        items.append(_RawItem(
            kind="hyperref",
            start=command.start,
            end=command.end,
            source=source,
            match_text=key,
            label=key,
            title=command.required[0],
        ))
    return _ScanOutput(tuple(items), errors=output.errors + hyper_errors)


def _scan_citation(doc: Document) -> _ScanOutput:
    return _scan_key_commands(doc, _CITATION_COMMANDS)


def _scan_footnote(doc: Document) -> _ScanOutput:
    commands, errors = _scan_commands(
        doc,
        _FOOTNOTE_COMMANDS,
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    marks, mark_errors = _scan_commands(
        doc,
        {"footnotemark"},
        minimum_required=0,
        maximum_required=0,
        bounds=_body_bounds(doc),
    )
    items: list[_RawItem] = []
    for command in commands:
        source = _source(doc, command.start, command.end)
        number = command.optional[-1].strip() if command.optional else ""
        content = command.required[0]
        items.append(_RawItem(
            kind=command.name,
            start=command.start,
            end=command.end,
            source=source,
            match_text=content,
            number=number,
            title=content,
            representation="command",
        ))
    for command in marks:
        source = _source(doc, command.start, command.end)
        number = command.optional[-1].strip() if command.optional else ""
        items.append(_RawItem(
            kind="footnotemark",
            start=command.start,
            end=command.end,
            source=source,
            match_text="footnotemark",
            number=number,
            representation="command",
        ))
    return _ScanOutput(tuple(items), errors=errors + mark_errors)


def _caption_commands(doc: Document) -> tuple[tuple[_CommandOccurrence, ...], tuple[str, ...]]:
    ordinary, ordinary_errors = _scan_commands(
        doc,
        {"caption", "subcaption"},
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    caption_of, caption_of_errors = _scan_commands(
        doc,
        {"captionof"},
        minimum_required=2,
        maximum_required=2,
        bounds=_body_bounds(doc),
    )
    return ordinary + caption_of, ordinary_errors + caption_of_errors


def _caption_title(command: _CommandOccurrence) -> str:
    return command.required[1] if command.name == "captionof" else command.required[0]


def _scan_caption(doc: Document) -> _ScanOutput:
    commands, errors = _caption_commands(doc)
    items: list[_RawItem] = []
    environment_ranges = _top_level_environment_ranges(
        doc, frozenset({"figure", "figure*"}) | _TABLE_ENVIRONMENTS
    )
    for command in commands:
        title = _caption_title(command)
        number, rest = _number_and_rest(title)
        source = _source(doc, command.start, command.end)
        parent = min(
            (
                item for item in environment_ranges
                if item[1] <= command.start < command.end <= item[4]
            ),
            key=lambda item: item[4] - item[1],
            default=None,
        )
        kind = (
            f"captionof:{command.required[0].strip()}"
            if command.name == "captionof"
            else f"{parent[0]}:{command.name}"
            if parent is not None
            else command.name
        )
        items.append(_RawItem(
            kind=kind + ("*" if command.starred else ""),
            start=command.start,
            end=command.end,
            source=source,
            match_text=rest or title,
            number=number,
            label=_first_label(source),
            title=title,
            representation="command",
        ))
    return _ScanOutput(tuple(items), errors=errors)


def _environment_caption(doc: Document, start: int, end: int) -> str:
    all_commands, _errors = _caption_commands(doc)
    commands = tuple(
        command for command in all_commands if start <= command.start < command.end <= end
    )
    return _caption_title(commands[0]) if commands else ""


def _environment_match_text(source: str, caption: str) -> str:
    semantic = _normalize_tex(source)
    if not caption:
        return semantic
    normalized_caption = _normalize_tex(caption)
    _number, rest = _number_and_rest(caption)
    normalized_rest = _normalize_tex(rest)
    if normalized_caption and normalized_rest:
        semantic = semantic.replace(normalized_caption, normalized_rest, 1)
    return semantic


def _scan_figure(doc: Document) -> _ScanOutput:
    relevant = {"figure", "figure*"}
    errors = list(_unbalanced_error(doc, relevant))
    items: list[_RawItem] = []
    ranges = _top_level_environment_ranges(doc, relevant)
    for name, begin_start, _begin_end, _end_start, end_end in ranges:
        source = _source(doc, begin_start, end_end)
        caption = _environment_caption(doc, begin_start, end_end)
        number, rest = _number_and_rest(caption)
        items.append(_RawItem(
            kind=name,
            start=begin_start,
            end=end_end,
            source=source,
            match_text=_environment_match_text(source, caption),
            number=number,
            label=_first_label(source),
            title=rest or caption,
        ))
    graphics, graphic_errors = _scan_commands(
        doc,
        {"includegraphics"},
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    for command in graphics:
        if any(item[1] <= command.start < item[4] for item in ranges):
            continue
        source = _source(doc, command.start, command.end)
        path = command.required[0].strip()
        items.append(_RawItem(
            kind="includegraphics",
            start=command.start,
            end=command.end,
            source=source,
            match_text=path,
            title=path,
        ))
    errors.extend(graphic_errors)
    return _ScanOutput(tuple(items), errors=tuple(dict.fromkeys(errors)))


def _scan_table(doc: Document) -> _ScanOutput:
    errors = list(_unbalanced_error(doc, set(_TABLE_ENVIRONMENTS)))
    items: list[_RawItem] = []
    ranges = _top_level_environment_ranges(doc, _TABLE_ENVIRONMENTS)
    for name, begin_start, _begin_end, _end_start, end_end in ranges:
        source = _source(doc, begin_start, end_end)
        caption = _environment_caption(doc, begin_start, end_end)
        number, rest = _number_and_rest(caption)
        items.append(_RawItem(
            kind=name,
            start=begin_start,
            end=end_end,
            source=source,
            match_text=_environment_match_text(source, caption),
            number=number,
            label=_first_label(source),
            title=rest or caption,
        ))
    return _ScanOutput(tuple(items), errors=tuple(errors))


def _scan_bibliography(doc: Document) -> _ScanOutput:
    errors = list(_unbalanced_error(doc, set(_BIBLIOGRAPHY_ENVIRONMENTS)))
    items: list[_RawItem] = []
    for name, begin_start, _begin_end, _end_start, end_end in _top_level_environment_ranges(
        doc, _BIBLIOGRAPHY_ENVIRONMENTS
    ):
        source = _source(doc, begin_start, end_end)
        items.append(_RawItem(
            kind=name,
            start=begin_start,
            end=end_end,
            source=source,
            match_text="bibliography-container",
            representation="environment",
        ))
    bibitems, bibitem_errors = _scan_commands(
        doc,
        {"bibitem"},
        minimum_required=1,
        maximum_required=1,
        bounds=_body_bounds(doc),
    )
    for index, command in enumerate(bibitems):
        containing_end = next(
            (
                item[3] for item in _environment_scan(doc)[0]
                if item[0] == "thebibliography" and item[1] < command.start < item[3]
            ),
            command.end,
        )
        next_start = (
            bibitems[index + 1].start
            if index + 1 < len(bibitems)
            else containing_end
        )
        end = max(command.end, min(next_start, containing_end))
        source = _source(doc, command.start, end)
        key = command.required[0].strip()
        body = _source(doc, command.end, end)
        items.append(_RawItem(
            kind="bibitem",
            start=command.start,
            end=end,
            source=source,
            match_text=_normalize_tex(body) or key,
            label=key,
            title=command.optional[-1] if command.optional else key,
            representation="command",
        ))
    errors.extend(bibitem_errors)
    resources, resource_errors = _scan_commands(
        doc,
        {"bibliography", "addbibresource", "bibliographystyle"},
        minimum_required=1,
        maximum_required=1,
    )
    for command in resources:
        source = _source(doc, command.start, command.end)
        for resource in _split_keys(command.required[0]):
            items.append(_RawItem(
                kind=command.name,
                start=command.start,
                end=command.end,
                source=source,
                match_text=resource,
                label=resource,
                title=resource,
            ))
    markers, marker_errors = _scan_commands(
        doc,
        {"printbibliography"},
        minimum_required=0,
        maximum_required=0,
        bounds=_body_bounds(doc),
    )
    for command in markers:
        source = _source(doc, command.start, command.end)
        items.append(_RawItem(
            kind="printbibliography",
            start=command.start,
            end=command.end,
            source=source,
            match_text="printbibliography",
        ))
    errors.extend(resource_errors)
    errors.extend(marker_errors)
    return _ScanOutput(tuple(items), errors=tuple(dict.fromkeys(errors)))


def _scan_frontmatter(doc: Document) -> _ScanOutput:
    errors = list(_unbalanced_error(doc, set(_FRONTMATTER_ENVIRONMENTS)))
    items: list[_RawItem] = []
    required, required_errors = _scan_commands(
        doc,
        _FRONTMATTER_REQUIRED_COMMANDS,
        minimum_required=1,
        maximum_required=1,
    )
    for command in required:
        content = command.required[0]
        source = _source(doc, command.start, command.end)
        items.append(_RawItem(
            kind=command.name,
            start=command.start,
            end=command.end,
            source=source,
            match_text=f"{command.name}:{_normalize_tex(content)}",
            title=content,
        ))
    markers, marker_errors = _scan_commands(
        doc,
        _FRONTMATTER_MARKER_COMMANDS,
        minimum_required=0,
        maximum_required=0,
        bounds=_body_bounds(doc),
    )
    for command in markers:
        source = _source(doc, command.start, command.end)
        items.append(_RawItem(
            kind=command.name,
            start=command.start,
            end=command.end,
            source=source,
            match_text=command.name,
        ))
    for name, begin_start, begin_end, end_start, end_end in _top_level_environment_ranges(
        doc, _FRONTMATTER_ENVIRONMENTS
    ):
        source = _source(doc, begin_start, end_end)
        body = _source(doc, begin_end, end_start)
        items.append(_RawItem(
            kind=name,
            start=begin_start,
            end=end_end,
            source=source,
            match_text=f"{name}:{_normalize_tex(body)}",
            title=_normalize_tex(body)[:500],
        ))
    errors.extend(required_errors)
    errors.extend(marker_errors)
    return _ScanOutput(tuple(items), errors=tuple(dict.fromkeys(errors)))


_CATEGORY_SCANNERS: Mapping[str, Callable[[Document], _ScanOutput]] = MappingProxyType({
    "heading": _scan_heading,
    "formal": lambda doc: _scan_formal_or_proof(doc, proof=False),
    "proof": lambda doc: _scan_formal_or_proof(doc, proof=True),
    "equation": _scan_equation,
    "reference": _scan_reference,
    "citation": _scan_citation,
    "footnote": _scan_footnote,
    "figure": _scan_figure,
    "table": _scan_table,
    "caption": _scan_caption,
    "bibliography": _scan_bibliography,
    "frontmatter": _scan_frontmatter,
})


def _finding_residuals(
    category: str,
    findings: Sequence[_RawFinding],
) -> list[AnalysisInventoryResidual]:
    return [
        _residual(
            category,
            finding.kind,
            current_value=f"line:{finding.line}",
            detail=finding.detail,
        )
        for finding in findings
    ]


def _compare_items(
    category: str,
    baseline: Sequence[AnalysisInventoryItem],
    current: Sequence[AnalysisInventoryItem],
    authorizations: Sequence[AnalysisInventoryAuthorization],
) -> tuple[list[AnalysisInventoryResidual], set[str]]:
    baseline_by_id = {item.stable_id: item for item in baseline}
    current_by_id = {item.stable_id: item for item in current}
    residuals: list[AnalysisInventoryResidual] = []
    applied: set[str] = set()
    structure_authorization = next((
        item for item in authorizations
        if item.category == category
        and item.action is InventoryAuthorizationAction.STRUCTURE_WRAPPER
    ), None)
    toc_authorization = next((
        item for item in authorizations
        if item.category == category
        and item.action is InventoryAuthorizationAction.GENERATED_TOC
    ), None)
    for stable_id, baseline_item in baseline_by_id.items():
        current_item = current_by_id.get(stable_id)
        if current_item is None:
            residuals.append(_residual(
                category,
                InventoryResidualKind.MISSING,
                baseline_item=baseline_item,
                baseline_value=baseline_item.semantic_sha256,
                detail="baseline inventory item is absent from the current candidate",
            ))
            continue
        if baseline_item.representation != current_item.representation:
            authorized_wrapper = bool(
                structure_authorization is not None
                and baseline_item.representation == "plain"
                and current_item.representation in {"command", "environment"}
            )
            exact_native_equation_wrapper = bool(
                category == "equation"
                and baseline_item.kind == _NATIVE_DISPLAY_MATH_KIND
                and current_item.kind == _NATIVE_DISPLAY_MATH_KIND
                and baseline_item.representation == "plain"
                and current_item.representation == "syntax"
                and baseline_item.semantic_sha256 == current_item.semantic_sha256
            )
            if authorized_wrapper:
                applied.add(structure_authorization.authorization_id)
            elif not exact_native_equation_wrapper:
                residuals.append(_residual(
                    category,
                    InventoryResidualKind.REPRESENTATION_CHANGED,
                    baseline_item=baseline_item,
                    current_item=current_item,
                    baseline_value=baseline_item.representation,
                    current_value=current_item.representation,
                    detail="inventory item representation changed without host authorization",
                ))
        for kind, baseline_value, current_value, detail in (
            (
                InventoryResidualKind.KIND_CHANGED,
                baseline_item.kind,
                current_item.kind,
                "inventory item kind changed",
            ),
            (
                InventoryResidualKind.NUMBER_CHANGED,
                baseline_item.number,
                current_item.number,
                "inventory item number changed",
            ),
            (
                InventoryResidualKind.LABEL_CHANGED,
                baseline_item.label,
                current_item.label,
                "inventory item label changed",
            ),
            (
                InventoryResidualKind.PAGE_CHANGED,
                baseline_item.source_page,
                current_item.source_page,
                "inventory item moved to a different native source page",
            ),
        ):
            automatic_numbering = bool(
                kind is InventoryResidualKind.NUMBER_CHANGED
                and category in {
                    "heading", "formal", "proof", "footnote", "caption",
                    "bibliography",
                }
                and baseline_value
                and not current_value
                and baseline_item.representation == "plain"
                and current_item.representation in {"command", "environment"}
                and structure_authorization is not None
            )
            automatic_structural_label = bool(
                kind is InventoryResidualKind.LABEL_CHANGED
                and category == "bibliography"
                and not baseline_value
                and bool(current_value)
                and baseline_item.representation == "plain"
                and current_item.representation == "command"
                and structure_authorization is not None
            )
            if (
                baseline_value != current_value
                and not automatic_numbering
                and not automatic_structural_label
            ):
                residuals.append(_residual(
                    category,
                    kind,
                    baseline_item=baseline_item,
                    current_item=current_item,
                    baseline_value=baseline_value,
                    current_value=current_value,
                    detail=detail,
                ))
    baseline_semantics = Counter(item.semantic_sha256 for item in baseline)
    for stable_id, current_item in current_by_id.items():
        if stable_id in baseline_by_id:
            continue
        if (
            toc_authorization is not None
            and category == "frontmatter"
            and current_item.kind == "tableofcontents"
        ):
            applied.add(toc_authorization.authorization_id)
            continue
        if (
            structure_authorization is not None
            and baseline
            and category in {"bibliography", "figure", "table"}
            and current_item.kind in {
                "thebibliography", "figure", "figure*", "table", "table*",
            }
            and current_item.representation == "environment"
        ):
            applied.add(structure_authorization.authorization_id)
            continue
        kind = (
            InventoryResidualKind.DUPLICATE
            if current_item.semantic_sha256 in baseline_semantics
            else InventoryResidualKind.ADDED
        )
        residuals.append(_residual(
            category,
            kind,
            current_item=current_item,
            current_value=current_item.semantic_sha256,
            detail=(
                "current candidate contains an extra duplicate inventory item"
                if kind is InventoryResidualKind.DUPLICATE
                else "current candidate contains an inventory item absent from baseline"
            ),
        ))
    return residuals, applied


def _duplicate_identifier_residuals(
    category: str,
    current: Sequence[AnalysisInventoryItem],
) -> list[AnalysisInventoryResidual]:
    if category in {"reference", "citation", "footnote", "frontmatter"}:
        return []
    residuals: list[AnalysisInventoryResidual] = []
    identifiers: defaultdict[tuple[str, str, str], list[AnalysisInventoryItem]] = defaultdict(list)
    for item in current:
        if item.label:
            identifiers[("label", item.kind, item.label)].append(item)
        if item.number and category in {"heading", "formal", "equation", "figure", "table", "caption"}:
            identifiers[("number", item.kind, item.number)].append(item)
    for (identifier_kind, item_kind, value), items in sorted(identifiers.items()):
        if len(items) < 2:
            continue
        for item in items[1:]:
            residuals.append(_residual(
                category,
                InventoryResidualKind.DUPLICATE,
                current_item=item,
                current_value=value,
                detail=f"duplicate {identifier_kind} {value!r} for {item_kind}",
            ))
    return residuals


@dataclass(frozen=True, slots=True)
class AnalysisInventoryCategory:
    category: str
    baseline_items: tuple[AnalysisInventoryItem, ...]
    current_items: tuple[AnalysisInventoryItem, ...]
    baseline_total: int
    current_total: int
    residual: tuple[AnalysisInventoryResidual, ...]
    status: InventoryStatus
    scanner_executed: bool
    scan_errors: tuple[str, ...] = ()
    applied_authorization_ids: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(self.as_dict(include_digest=False)))

    def as_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "category": self.category,
            "items": {
                "baseline": [item.as_dict() for item in self.baseline_items],
                "current": [item.as_dict() for item in self.current_items],
            },
            "baseline_total": self.baseline_total,
            "current_total": self.current_total,
            "residual": [item.as_dict() for item in self.residual],
            "residual_total": len(self.residual),
            "status": self.status.value,
            "scanner_executed": self.scanner_executed,
            "scan_errors": list(self.scan_errors),
            "applied_authorization_ids": list(self.applied_authorization_ids),
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


def _scan_inventory_category(
    category: str,
    doc: Document,
    *,
    native_blocks: Sequence[AnalysisNativeSourceBlock],
    source_page_map: Mapping[int, tuple[int, ...]],
    source_side: bool,
    require_native_inventory: bool,
    native_inventory_supplied: bool,
) -> _ScanOutput:
    if category == "heading":
        return _scan_heading(
            doc,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=source_side,
            require_native=require_native_inventory,
            native_inventory_supplied=native_inventory_supplied,
        )
    if category in {"formal", "proof"}:
        return _scan_formal_or_proof(
            doc,
            proof=category == "proof",
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=source_side,
        )
    scan = _CATEGORY_SCANNERS[category](doc)
    if category == "equation":
        return _scan_with_native_equation_blocks(
            doc,
            scan,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=source_side,
        )
    if category in {"footnote", "caption", "bibliography"}:
        return _scan_with_native_plain_blocks(
            doc,
            scan,
            category=category,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=source_side,
        )
    if category in {"figure", "table"}:
        return _scan_with_native_object_coverage(
            doc,
            scan,
            category=category,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=source_side,
        )
    return scan


def _category_inventory(
    category: str,
    baseline_doc: Document,
    current_doc: Document,
    baseline_locator: _PageLocator,
    current_locator: _PageLocator,
    native_blocks: Sequence[AnalysisNativeSourceBlock],
    source_page_map: Mapping[int, tuple[int, ...]],
    require_native_heading_inventory: bool,
    native_inventory_supplied: bool,
    authorizations: Sequence[AnalysisInventoryAuthorization],
) -> AnalysisInventoryCategory:
    try:
        baseline_scan = _scan_inventory_category(
            category,
            baseline_doc,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=True,
            require_native_inventory=require_native_heading_inventory,
            native_inventory_supplied=native_inventory_supplied,
        )
    except Exception as exc:  # noqa: BLE001 - convert scanner failure into evidence
        baseline_scan = _ScanOutput(
            errors=(f"baseline scanner exception: {type(exc).__name__}: {exc}",),
            scanner_executed=True,
        )
    try:
        current_scan = _scan_inventory_category(
            category,
            current_doc,
            native_blocks=native_blocks,
            source_page_map=source_page_map,
            source_side=False,
            require_native_inventory=require_native_heading_inventory,
            native_inventory_supplied=native_inventory_supplied,
        )
    except Exception as exc:  # noqa: BLE001 - convert scanner failure into evidence
        current_scan = _ScanOutput(
            errors=(f"current scanner exception: {type(exc).__name__}: {exc}",),
            scanner_executed=True,
        )
    baseline_items = _stable_items(
        category, baseline_doc, baseline_locator, baseline_scan.items
    )
    current_items = _stable_items(
        category, current_doc, current_locator, current_scan.items
    )
    errors = tuple(
        [f"baseline: {item}" for item in baseline_scan.errors]
        + [f"current: {item}" for item in current_scan.errors]
    )
    residuals, applied_authorizations = _compare_items(
        category, baseline_items, current_items, authorizations
    )
    residuals.extend(_finding_residuals(category, current_scan.findings))
    residuals.extend(_duplicate_identifier_residuals(category, current_items))
    if errors:
        for error in errors:
            residuals.append(_residual(
                category,
                InventoryResidualKind.SCAN_FAILED,
                detail=error,
            ))
        status = InventoryStatus.FAILED
    elif not baseline_items and not current_items:
        status = InventoryStatus.NOT_APPLICABLE
    elif residuals:
        status = InventoryStatus.RESIDUAL
    else:
        status = InventoryStatus.PASS
    unique = {item.residual_id: item for item in residuals}
    return AnalysisInventoryCategory(
        category=category,
        baseline_items=baseline_items,
        current_items=current_items,
        baseline_total=len(baseline_items),
        current_total=len(current_items),
        residual=tuple(sorted(unique.values(), key=lambda item: item.residual_id)),
        status=status,
        scanner_executed=(
            baseline_scan.scanner_executed and current_scan.scanner_executed
        ),
        scan_errors=errors,
        applied_authorization_ids=tuple(sorted(applied_authorizations)),
    )


@dataclass(frozen=True, slots=True)
class AnalysisInventoryGate:
    passed: bool
    status: InventoryStatus
    scanner_executed: bool
    residual_total: int
    blocked_categories: tuple[str, ...]
    bundle_digest: str

    @property
    def digest(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(self.as_dict(include_digest=False)))

    def as_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": "latexstruct-analysis-inventory-gate-v1",
            "passed": self.passed,
            "status": self.status.value,
            "scanner_executed": self.scanner_executed,
            "residual_total": self.residual_total,
            "blocked_categories": list(self.blocked_categories),
            "bundle_digest": self.bundle_digest,
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True, slots=True)
class AnalysisInventoryBundle:
    categories: tuple[AnalysisInventoryCategory, ...]
    source_page_map: Mapping[int, tuple[int, ...]]
    page_map_digest: str
    baseline_tex_sha256: str
    current_tex_sha256: str
    baseline_page_sequence: tuple[int, ...]
    current_page_sequence: tuple[int, ...]
    mapping_residual: tuple[AnalysisInventoryResidual, ...]
    mapping_status: InventoryStatus
    scanner_executed: bool
    native_source_blocks: tuple[AnalysisNativeSourceBlock, ...] = ()
    native_source_blocks_supplied: bool = False
    authorizations: tuple[AnalysisInventoryAuthorization, ...] = ()
    applied_authorization_ids: tuple[str, ...] = ()
    native_heading_inventory_required: bool = False
    schema: str = ANALYSIS_INVENTORY_SCHEMA

    def category(self, name: str) -> AnalysisInventoryCategory:
        for item in self.categories:
            if item.category == name:
                return item
        raise KeyError(name)

    @property
    def residual_total(self) -> int:
        return len(self.mapping_residual) + sum(
            len(item.residual) for item in self.categories
        )

    @property
    def digest(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(self.as_dict(include_digest=False)))

    def as_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": self.schema,
            "categories": [item.as_dict() for item in self.categories],
            "source_page_map": {
                str(page): list(pdf_pages)
                for page, pdf_pages in self.source_page_map.items()
            },
            "page_map_digest": self.page_map_digest,
            "baseline_tex_sha256": self.baseline_tex_sha256,
            "current_tex_sha256": self.current_tex_sha256,
            "baseline_page_sequence": list(self.baseline_page_sequence),
            "current_page_sequence": list(self.current_page_sequence),
            "mapping_residual": [item.as_dict() for item in self.mapping_residual],
            "mapping_status": self.mapping_status.value,
            "scanner_executed": self.scanner_executed,
            "native_source_blocks": [
                item.as_dict() for item in self.native_source_blocks
            ],
            "native_source_blocks_supplied": self.native_source_blocks_supplied,
            "native_source_blocks_digest": _sha256_bytes(_canonical_json_bytes([
                item.as_dict() for item in self.native_source_blocks
            ])),
            "authorizations": [item.as_dict() for item in self.authorizations],
            "applied_authorization_ids": list(self.applied_authorization_ids),
            "native_heading_inventory_required": self.native_heading_inventory_required,
            "residual_total": self.residual_total,
        }
        if include_digest:
            payload["digest"] = self.digest
        return payload

    def gate(self) -> AnalysisInventoryGate:
        return evaluate_analysis_inventory_gate(self)


def _mapping_residuals(
    baseline: _PageObservation,
    current: _PageObservation,
) -> tuple[AnalysisInventoryResidual, ...]:
    residuals: list[AnalysisInventoryResidual] = []
    for side, observation in (("baseline", baseline), ("current", current)):
        for error in observation.errors:
            residuals.append(_residual(
                "page_map",
                InventoryResidualKind.PAGE_MAP_MISMATCH,
                current_value=side,
                detail=f"{side}: {error}",
            ))
    return tuple(sorted(residuals, key=lambda item: item.residual_id))


def build_analysis_inventory_bundle(
    baseline_tex: str,
    candidate_tex: str,
    native_source_page_map: Mapping[int, Sequence[int]],
    *,
    native_source_blocks: Sequence[
        AnalysisNativeSourceBlock | Mapping[str, object]
    ] | None = None,
    authorizations: Sequence[
        AnalysisInventoryAuthorization | Mapping[str, object]
    ] = (),
    require_native_heading_inventory: bool = False,
) -> AnalysisInventoryBundle:
    """Scan and compare all required inventory categories.

    ``native_source_page_map`` is the verified OCR map from source page number
    to one or more baseline PDF pages.  It is never inferred from TeX comments.
    TeX page markers only bind item locations back to this independent map.
    """
    if not isinstance(baseline_tex, str) or not baseline_tex.strip():
        raise AnalysisInventoryError("baseline TeX must be non-empty text")
    if not isinstance(candidate_tex, str) or not candidate_tex.strip():
        raise AnalysisInventoryError("candidate TeX must be non-empty text")
    source_page_map = _normalized_page_map(native_source_page_map)
    native_inventory_supplied = native_source_blocks is not None
    typed_blocks = coerce_analysis_native_source_blocks(native_source_blocks or ())
    typed_authorizations = coerce_analysis_inventory_authorizations(authorizations)
    if type(require_native_heading_inventory) is not bool:
        raise AnalysisInventoryError(
            "require_native_heading_inventory must be a boolean"
        )
    if any(block.source_page not in source_page_map for block in typed_blocks):
        raise AnalysisInventoryError(
            "native source block lies outside the native source page map"
        )
    baseline_doc = parse_latex(baseline_tex)
    current_doc = parse_latex(candidate_tex)
    baseline_pages = _page_observation(baseline_doc.text, source_page_map)
    current_pages = _page_observation(current_doc.text, source_page_map)
    categories = tuple(
        _category_inventory(
            category,
            baseline_doc,
            current_doc,
            baseline_pages.locator,
            current_pages.locator,
            typed_blocks,
            source_page_map,
            require_native_heading_inventory,
            native_inventory_supplied,
            typed_authorizations,
        )
        for category in ANALYSIS_INVENTORY_CATEGORIES
    )
    mapping_residual = _mapping_residuals(baseline_pages, current_pages)
    page_map_payload = {
        str(page): list(pdf_pages) for page, pdf_pages in source_page_map.items()
    }
    return AnalysisInventoryBundle(
        categories=categories,
        source_page_map=source_page_map,
        page_map_digest=_sha256_bytes(_canonical_json_bytes(page_map_payload)),
        baseline_tex_sha256=_sha256_text(baseline_tex),
        current_tex_sha256=_sha256_text(candidate_tex),
        baseline_page_sequence=baseline_pages.page_sequence,
        current_page_sequence=current_pages.page_sequence,
        mapping_residual=mapping_residual,
        mapping_status=(
            InventoryStatus.RESIDUAL if mapping_residual else InventoryStatus.PASS
        ),
        scanner_executed=all(item.scanner_executed for item in categories),
        native_source_blocks=typed_blocks,
        native_source_blocks_supplied=native_inventory_supplied,
        authorizations=typed_authorizations,
        applied_authorization_ids=tuple(sorted({
            authorization_id
            for category in categories
            for authorization_id in category.applied_authorization_ids
        })),
        native_heading_inventory_required=require_native_heading_inventory,
    )


def evaluate_analysis_inventory_gate(
    bundle: AnalysisInventoryBundle,
) -> AnalysisInventoryGate:
    """Aggregate all category and native page-map evidence into one hard gate."""
    if not isinstance(bundle, AnalysisInventoryBundle):
        raise TypeError("bundle must be AnalysisInventoryBundle")
    failed = [
        item.category for item in bundle.categories
        if item.status is InventoryStatus.FAILED or not item.scanner_executed
    ]
    residual = [
        item.category for item in bundle.categories
        if item.status is InventoryStatus.RESIDUAL
    ]
    if bundle.mapping_status is not InventoryStatus.PASS:
        residual.append("page_map")
    blocked = tuple(dict.fromkeys(failed + residual))
    if failed or not bundle.scanner_executed:
        status = InventoryStatus.FAILED
    elif blocked:
        status = InventoryStatus.RESIDUAL
    else:
        status = InventoryStatus.PASS
    return AnalysisInventoryGate(
        passed=status is InventoryStatus.PASS,
        status=status,
        scanner_executed=bundle.scanner_executed,
        residual_total=bundle.residual_total,
        blocked_categories=blocked,
        bundle_digest=bundle.digest,
    )


def require_analysis_inventory_gate(
    bundle: AnalysisInventoryBundle,
) -> AnalysisInventoryGate:
    """Return the PASS gate or raise without weakening residual semantics."""
    gate = evaluate_analysis_inventory_gate(bundle)
    if not gate.passed:
        raise AnalysisInventoryGateError(
            f"analysis inventory gate is {gate.status.value}: "
            f"{', '.join(gate.blocked_categories) or 'unknown blocker'}"
        )
    return gate


__all__ = [
    "ANALYSIS_INVENTORY_CATEGORIES",
    "ANALYSIS_INVENTORY_SCHEMA",
    "AnalysisInventoryBundle",
    "AnalysisInventoryAuthorization",
    "AnalysisInventoryCategory",
    "AnalysisInventoryError",
    "AnalysisInventoryGate",
    "AnalysisInventoryGateError",
    "AnalysisInventoryItem",
    "AnalysisInventoryResidual",
    "AnalysisNativeSourceBlock",
    "InventoryAuthorizationAction",
    "InventoryResidualKind",
    "InventoryStatus",
    "build_analysis_inventory_bundle",
    "build_host_inventory_authorizations",
    "coerce_analysis_inventory_authorizations",
    "coerce_analysis_native_source_blocks",
    "evaluate_analysis_inventory_gate",
    "require_analysis_inventory_gate",
]
