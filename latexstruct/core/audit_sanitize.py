# -*- coding: utf-8 -*-
"""Context-aware privacy sanitizers for AI audit submission artifacts.

TeX is deliberately handled more conservatively than logs and ordinary text.
A drive letter followed by a TeX command (for example ``V:\\lvert``) is valid
mathematics, not sufficient evidence of a local path.  TeX redactions are
therefore limited to credentials, host-provided known paths, and absolute
paths inside commands whose arguments are explicitly path-shaped.

The public ``sanitize_*_text`` helpers return strings.  Packaging integrity
code can use :func:`sanitize_tex_text_with_spans` to obtain a non-secret audit
record of every authorized replacement.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

LOCAL_PATH_PLACEHOLDER = "<LOCAL_PATH>"
SECRET_PLACEHOLDER = "<REDACTED>"

_PATH_ARGUMENT_COMMANDS = frozenset({
    "includegraphics",
    "input",
    "include",
    "bibliography",
    "addbibresource",
    "lstinputlisting",
    "includepdf",
    "graphicspath",
})
_PATH_COMMAND_RE = re.compile(
    r"\\(?P<name>includegraphics|input|include|bibliography|addbibresource|"
    r"lstinputlisting|includepdf|graphicspath)\*?"
)

# These broad path expressions are intentionally used only for logs, JSON and
# plain text.  They must never be applied to an arbitrary TeX document.
_GENERAL_WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/][^\r\n\t\"'<>|{}\[\](),;]+|"
    r"\\\\[^\\\s{}\[\](),;]+\\[^\r\n\t\"'<>|{}\[\](),;]+)"
)
_GENERAL_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])/(?:Users|home|root|tmp|private(?:/tmp)?|var|"
    r"workspace(?:s)?|mnt|opt|data|srv|etc|usr|Applications|Volumes|Library|"
    r"System|media|run)(?:/[^\r\n\t\"'<> {}\[\](),;]*)?"
)

_RAW_OPENAI_KEY_RE = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{12,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{12,})")
_AUTHORIZATION_RE = re.compile(
    r"(?im)\bAuthorization[\"']?\s*[:=]\s*[\"']?"
    r"(?:(?:Bearer|Basic)\s+)?(?P<secret>[^\s,;\"'{}\[\]()\\]+)"
)
_NAMED_SECRET_RE = re.compile(
    r"(?im)\b(?:"
    r"(?:[A-Z][A-Z0-9]*[_ -])*API[_ -]?KEY|"
    r"ACCESS[_ -]?TOKEN|REFRESH[_ -]?TOKEN|ID[_ -]?TOKEN|"
    r"ACCOUNT[_ -]?ID|ACCOUNT[_ -]?EMAIL|EMAIL|"
    r"(?:CODEX|OPENAI|CHATGPT)(?:[_ -](?:TOKEN|ACCESS[_ -]?TOKEN|"
    r"REFRESH[_ -]?TOKEN|ID[_ -]?TOKEN|AUTH|LOGIN|SESSION|COOKIE|"
    r"PASSWORD|API[_ -]?KEY|EMAIL|ACCOUNT|ACCOUNT[_ -]?ID|"
    r"ACCOUNT[_ -]?EMAIL|LOGIN[_ -]?EMAIL|LOGIN[_ -]?TOKEN)){1,4}"
    r")[\"']?\s*[:=]\s*[\"']?(?P<secret>[^\s,;\"'{}\[\]()\\]+)"
)
_SENSITIVE_JSON_KEY_RE = re.compile(
    r"(?i)^(?:authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"id[_ -]?token|(?:codex|openai|chatgpt)[_ -]?"
    r"(?:token|auth|login|session|cookie|password|api[_ -]?key|account|"
    r"account[_ -]?id|account[_ -]?email|email|user[_ -]?id))$"
)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SanitizationSpan:
    """One authorized source-to-package replacement without the secret value."""

    source_start: int
    source_end: int
    packaged_start: int
    packaged_end: int
    original_sha256: str
    replacement: str
    category: str
    reason: str

    def __post_init__(self) -> None:
        if self.source_start < 0 or self.source_end <= self.source_start:
            raise ValueError("sanitization source span must be non-empty and ordered")
        if self.packaged_start < 0 or self.packaged_end < self.packaged_start:
            raise ValueError("sanitization packaged span must be ordered")
        if self.packaged_end - self.packaged_start != len(self.replacement):
            raise ValueError("packaged span length must equal replacement length")
        if not re.fullmatch(r"[0-9a-f]{64}", self.original_sha256):
            raise ValueError("original_sha256 must be a lowercase SHA-256 digest")
        if self.category not in {"credential", "known_path", "latex_path_argument"}:
            raise ValueError("unsupported TeX sanitization category")
        expected = SECRET_PLACEHOLDER if self.category == "credential" else LOCAL_PATH_PLACEHOLDER
        if self.replacement != expected:
            raise ValueError(f"{self.category} must use {expected}")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_start": self.source_start,
            "source_end": self.source_end,
            "packaged_start": self.packaged_start,
            "packaged_end": self.packaged_end,
            "original_sha256": self.original_sha256,
            "replacement": self.replacement,
            "category": self.category,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SanitizedText:
    text: str
    spans: tuple[SanitizationSpan, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.spans)


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    replacement: str
    category: str
    reason: str
    priority: int


def _credential_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    patterns = (
        (_AUTHORIZATION_RE, "authorization_header", 100),
        (_NAMED_SECRET_RE, "named_credential", 95),
        (_BEARER_RE, "bearer_token", 90),
    )
    for pattern, reason, priority in patterns:
        for match in pattern.finditer(text):
            start, end = match.span("secret")
            if start < end:
                candidates.append(_Candidate(
                    start,
                    end,
                    SECRET_PLACEHOLDER,
                    "credential",
                    reason,
                    priority,
                ))
    for match in _RAW_OPENAI_KEY_RE.finditer(text):
        candidates.append(_Candidate(
            match.start(),
            match.end(),
            SECRET_PLACEHOLDER,
            "credential",
            "openai_api_key",
            85,
        ))
    return candidates


def _split_absolute_path(value: object) -> tuple[str, tuple[str, ...], bool] | None:
    raw = str(value or "").strip().strip("\"'")
    if not raw:
        return None
    # A known path is evidence only if it is absolute.  Relative strings must
    # never authorize deletion of matching document prose.
    if re.match(r"(?i)^[A-Z]:[\\/]", raw):
        prefix = raw[:2]
        parts = tuple(part for part in re.split(r"[\\/]+", raw[3:]) if part)
        return prefix, parts, True
    if re.match(r"^[\\/]{2}[^\\/]", raw):
        parts = tuple(part for part in re.split(r"[\\/]+", raw.lstrip("\\/")) if part)
        if len(parts) >= 2:
            return "//", parts, True
        return None
    if raw.startswith("/"):
        parts = tuple(part for part in raw.split("/") if part)
        return "/", parts, False
    return None


def _known_path_candidates(text: str, known_paths: Iterable[object]) -> list[_Candidate]:
    compiled: list[tuple[int, re.Pattern[str]]] = []
    seen: set[tuple[str, tuple[str, ...], bool]] = set()
    for value in known_paths:
        parsed = _split_absolute_path(value)
        if parsed is None or parsed in seen:
            continue
        seen.add(parsed)
        prefix, parts, windows = parsed
        separator = r"[\\/]"
        if prefix == "//":
            expression = r"[\\/]{2}" + separator.join(re.escape(part) for part in parts)
        elif prefix == "/":
            expression = "/" + "/".join(re.escape(part) for part in parts)
        else:
            expression = re.escape(prefix) + separator
            expression += separator.join(re.escape(part) for part in parts)
        # Permit a following separator because roots are intentionally known
        # prefixes, while rejecting lookalikes such as C:\\math -> C:\\mathcal.
        expression = (
            r"(?<![A-Za-z0-9_])" + expression
            + r"(?=$|[\\/]|[\s\"'<>|{}\[\](),;])"
        )
        flags = re.IGNORECASE if windows else 0
        compiled.append((len(str(value)), re.compile(expression, flags)))

    candidates: list[_Candidate] = []
    # Longer roots win when project_root is nested below user_home.
    for _length, pattern in sorted(compiled, key=lambda item: item[0], reverse=True):
        for match in pattern.finditer(text):
            candidates.append(_Candidate(
                match.start(),
                match.end(),
                LOCAL_PATH_PLACEHOLDER,
                "known_path",
                "host_known_path",
                70,
            ))
    return candidates


def _balanced_end(text: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    cursor = opening
    while cursor < len(text):
        char = text[cursor]
        slash_count = 0
        before = cursor - 1
        while before >= 0 and text[before] == "\\":
            slash_count += 1
            before -= 1
        escaped = slash_count % 2 == 1
        if not escaped:
            if char == left:
                depth += 1
            elif char == right:
                depth -= 1
                if depth == 0:
                    return cursor + 1
        cursor += 1
    return None


def _argument_absolute_path_candidates(
    text: str,
    start: int,
    end: int,
    command: str,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    path_start_re = re.compile(
        r"(?i)(?:(?<![A-Za-z0-9_])[A-Z]:[\\/]|"
        r"(?<![A-Za-z0-9_.:-])[\\/]{2}|(?<![A-Za-z0-9_.:-])/)"
    )
    cursor = start
    while cursor < end:
        match = path_start_re.search(text, cursor, end)
        if match is None:
            break
        item_start = match.start()
        # URI schemes are not local absolute paths.  In particular, the two
        # slashes in https:// must not be treated as a UNC path.
        if re.search(r"[A-Za-z][A-Za-z0-9+.-]*:/?$", text[start:item_start]):
            # The matcher can first see the second slash of ``https://``
            # because the slash immediately after the colon is deliberately
            # excluded as an absolute-path start.  Skip the complete URI
            # token so later URL path separators are not reconsidered as
            # local POSIX paths.
            uri_end = match.end()
            while uri_end < end and text[uri_end] not in "{},\r\n\"' \t":
                uri_end += 1
            cursor = uri_end
            continue
        item_end = match.end()
        while item_end < end and text[item_end] not in "{},\r\n\"'":
            item_end += 1
        while item_end > item_start and text[item_end - 1].isspace():
            item_end -= 1
        if item_end > item_start:
            candidates.append(_Candidate(
                item_start,
                item_end,
                LOCAL_PATH_PLACEHOLDER,
                "latex_path_argument",
                f"latex_path_argument:{command}",
                80,
            ))
        cursor = max(match.end(), item_end + 1)
    return candidates


def _latex_path_argument_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for match in _PATH_COMMAND_RE.finditer(text):
        cursor = match.end()
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        while cursor < len(text) and text[cursor] == "[":
            optional_end = _balanced_end(text, cursor, "[", "]")
            if optional_end is None:
                cursor = len(text)
                break
            cursor = optional_end
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
        if cursor >= len(text) or text[cursor] != "{":
            continue
        argument_end = _balanced_end(text, cursor, "{", "}")
        if argument_end is None:
            continue
        candidates.extend(_argument_absolute_path_candidates(
            text,
            cursor + 1,
            argument_end - 1,
            match.group("name"),
        ))
    return candidates


def _select_non_overlapping(candidates: Sequence[_Candidate]) -> list[_Candidate]:
    # For a shared starting offset, prefer a stronger authorization and then
    # the longer span.  After that, source order makes reconstruction stable.
    ordered = sorted(candidates, key=lambda item: (item.start, -item.priority, -(item.end - item.start)))
    selected: list[_Candidate] = []
    cursor = 0
    for item in ordered:
        if item.start < cursor or item.end <= item.start:
            continue
        selected.append(item)
        cursor = item.end
    return selected


def _apply_candidates(text: str, candidates: Sequence[_Candidate]) -> SanitizedText:
    selected = _select_non_overlapping(candidates)
    if not selected:
        return SanitizedText(text)
    output: list[str] = []
    spans: list[SanitizationSpan] = []
    source_cursor = 0
    packaged_cursor = 0
    for item in selected:
        unchanged = text[source_cursor:item.start]
        output.append(unchanged)
        packaged_cursor += len(unchanged)
        original = text[item.start:item.end]
        output.append(item.replacement)
        spans.append(SanitizationSpan(
            source_start=item.start,
            source_end=item.end,
            packaged_start=packaged_cursor,
            packaged_end=packaged_cursor + len(item.replacement),
            original_sha256=_sha256_text(original),
            replacement=item.replacement,
            category=item.category,
            reason=item.reason,
        ))
        packaged_cursor += len(item.replacement)
        source_cursor = item.end
    output.append(text[source_cursor:])
    return SanitizedText("".join(output), tuple(spans))


def sanitize_tex_text_with_spans(
    text: str,
    known_paths: Iterable[object] = (),
) -> SanitizedText:
    """Sanitize TeX using only evidence-backed, auditable replacements."""

    value = str(text)
    candidates = _credential_candidates(value)
    candidates.extend(_known_path_candidates(value, known_paths))
    candidates.extend(_latex_path_argument_candidates(value))
    return _apply_candidates(value, candidates)


def sanitize_tex_text(text: str, known_paths: Iterable[object] = ()) -> str:
    """Return safely sanitized TeX while preserving ordinary TeX and math."""

    return sanitize_tex_text_with_spans(text, known_paths).text


def replace_exact_path_variants(
    text: str,
    known_path: object,
    replacement: str = LOCAL_PATH_PLACEHOLDER,
) -> str:
    """Replace one host-known absolute path, accepting Windows separator variants."""

    if replacement != LOCAL_PATH_PLACEHOLDER:
        raise ValueError("known paths must use the standard local-path placeholder")
    return _apply_candidates(str(text), _known_path_candidates(str(text), (known_path,))).text


def _general_text_result(text: str, known_paths: Iterable[object]) -> SanitizedText:
    value = str(text)
    candidates = _credential_candidates(value)
    candidates.extend(_known_path_candidates(value, known_paths))
    for pattern in (_GENERAL_WINDOWS_PATH_RE, _GENERAL_POSIX_PATH_RE):
        for match in pattern.finditer(value):
            candidates.append(_Candidate(
                match.start(),
                match.end(),
                LOCAL_PATH_PLACEHOLDER,
                "known_path",
                "general_text_absolute_path",
                80,
            ))
    return _apply_candidates(value, candidates)


def sanitize_log_text(text: str, known_paths: Iterable[object] = ()) -> str:
    """Sanitize logs and stack traces, where broad absolute-path matching is safe."""

    return _general_text_result(text, known_paths).text


def sanitize_plain_text(text: str, known_paths: Iterable[object] = ()) -> str:
    """Sanitize non-TeX human-readable audit text."""

    return _general_text_result(text, known_paths).text


def _sanitize_json_value(value: Any, known_paths: Iterable[object]) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key)
            compact = re.sub(r"[^a-z0-9]", "", normalized.casefold())
            sensitive = bool(_SENSITIVE_JSON_KEY_RE.fullmatch(normalized.strip())) or (
                compact.endswith("apikey")
                or compact in {
                    "authorization",
                    "accesstoken",
                    "refreshtoken",
                    "idtoken",
                    "accountid",
                    "accountemail",
                    "email",
                    "account",
                }
                or (
                    compact.startswith(("codex", "openai", "chatgpt"))
                    and compact.endswith((
                        "token",
                        "email",
                        "accountid",
                        "userid",
                        "login",
                        "auth",
                        "session",
                        "account",
                        "cookie",
                        "password",
                    ))
                )
            )
            if sensitive:
                cleaned[normalized] = SECRET_PLACEHOLDER
            else:
                cleaned[normalized] = _sanitize_json_value(item, known_paths)
        return cleaned
    if isinstance(value, list):
        return [_sanitize_json_value(item, known_paths) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_json_value(item, known_paths) for item in value]
    if isinstance(value, str):
        return sanitize_plain_text(value, known_paths)
    return value


def sanitize_json_text(text: str, known_paths: Iterable[object] = ()) -> str:
    """Sanitize JSON values while retaining a valid machine-readable document."""

    value = str(text)
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return sanitize_plain_text(value, known_paths)
    cleaned = _sanitize_json_value(parsed, tuple(known_paths))
    if cleaned == parsed:
        return value
    return json.dumps(cleaned, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


__all__ = [
    "LOCAL_PATH_PLACEHOLDER",
    "SECRET_PLACEHOLDER",
    "SanitizationSpan",
    "SanitizedText",
    "replace_exact_path_variants",
    "sanitize_json_text",
    "sanitize_log_text",
    "sanitize_plain_text",
    "sanitize_tex_text",
    "sanitize_tex_text_with_spans",
]
