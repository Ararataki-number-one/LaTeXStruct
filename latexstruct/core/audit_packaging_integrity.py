# -*- coding: utf-8 -*-
"""Fail-closed content-conservation gate for packaged TeX artifacts.

This gate runs *after* privacy sanitization.  Byte differences are accepted
only when they are exactly reconstructed by evidence-backed sanitization
spans.  All other changes, including prose order, math, cross references,
environment structure, braces, and command tokens, invalidate the package.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Sequence

from .audit_sanitize import SanitizationSpan, sanitize_tex_text_with_spans
from .invariants import body_text_tokens, check_invariants, cites, labels, math_tokens, refs
from .verify import _masked

PACKAGING_INTEGRITY_SCHEMA_VERSION = "latexstruct-audit-packaging-integrity-v1"
_REDACTION_SENTINEL = "AUDITAUTHORIZEDREDACTIONTOKEN"
_COMMAND_RE = re.compile(r"\\(?:[A-Za-z@]+|[^\s])")
_ENV_RE = re.compile(r"\\(?P<action>begin|end)\s*\{(?P<name>[^{}]+)\}")


class PackagingStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class AuditPackageStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _token_digest(values: Sequence[str]) -> str:
    encoded = json.dumps(list(values), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(encoded)


@dataclass(frozen=True, slots=True)
class IntegrityCheck:
    name: str
    passed: bool
    source_count: int = 0
    packaged_count: int = 0
    source_sha256: str = ""
    packaged_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "passed": self.passed,
            "source_count": self.source_count,
            "packaged_count": self.packaged_count,
        }
        if self.source_sha256:
            result["source_sha256"] = self.source_sha256
        if self.packaged_sha256:
            result["packaged_sha256"] = self.packaged_sha256
        return result


@dataclass(frozen=True, slots=True)
class TexArtifactPackagingInput:
    original: bytes | str
    packaged: bytes | str
    artifact_id: str = ""
    artifact_role: str = ""
    path: str = ""
    authorized_spans: tuple[SanitizationSpan | Mapping[str, object], ...] = ()
    known_paths: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "authorized_spans", tuple(self.authorized_spans))
        object.__setattr__(self, "known_paths", tuple(self.known_paths))


@dataclass(frozen=True, slots=True)
class TexArtifactIntegrityResult:
    artifact_id: str
    artifact_role: str
    path: str
    source_bytes_sha256: str
    packaged_bytes_sha256: str
    bytes_equal: bool
    sanitization_applied: bool
    authorized_spans: tuple[SanitizationSpan, ...]
    checks: tuple[IntegrityCheck, ...]
    failure_codes: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.failure_codes and all(item.passed for item in self.checks)

    def check(self, name: str) -> IntegrityCheck:
        for item in self.checks:
            if item.name == name:
                return item
        raise KeyError(name)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_role": self.artifact_role,
            "path": self.path,
            "source_bytes_sha256": self.source_bytes_sha256,
            "packaged_bytes_sha256": self.packaged_bytes_sha256,
            "bytes_equal": self.bytes_equal,
            "sanitization_applied": self.sanitization_applied,
            "authorized_spans": [item.to_dict() for item in self.authorized_spans],
            "checks": {item.name: item.to_dict() for item in self.checks},
            "failure_codes": list(self.failure_codes),
            "valid": self.valid,
        }


@dataclass(frozen=True, slots=True)
class AuditPackagingIntegrityResult:
    artifacts: tuple[TexArtifactIntegrityResult, ...]
    packaging_status: PackagingStatus
    audit_package_status: AuditPackageStatus
    failures: tuple[dict[str, str], ...] = ()
    schema_version: str = PACKAGING_INTEGRITY_SCHEMA_VERSION

    @property
    def valid(self) -> bool:
        return (
            self.packaging_status == PackagingStatus.SUCCESS
            and self.audit_package_status == AuditPackageStatus.VALID
            and not self.failures
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "packaging_status": self.packaging_status.value,
            "audit_package_status": self.audit_package_status.value,
            "valid": self.valid,
            "checked_tex_artifact_count": len(self.artifacts),
            "failed_tex_artifact_count": sum(not item.valid for item in self.artifacts),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "failures": [dict(item) for item in self.failures],
        }


@dataclass(frozen=True, slots=True)
class _DecodedText:
    raw: bytes
    text: str
    encoding: str
    bom: bytes = b""

    def encode(self, value: str) -> bytes:
        return self.bom + value.encode(self.encoding)


def _decode_tex(value: bytes | str) -> _DecodedText:
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _DecodedText(raw, value, "utf-8")
    raw = bytes(value)
    if raw.startswith(b"\xef\xbb\xbf"):
        return _DecodedText(raw, raw[3:].decode("utf-8"), "utf-8", b"\xef\xbb\xbf")
    if raw.startswith(b"\xff\xfe"):
        return _DecodedText(raw, raw[2:].decode("utf-16-le"), "utf-16-le", b"\xff\xfe")
    if raw.startswith(b"\xfe\xff"):
        return _DecodedText(raw, raw[2:].decode("utf-16-be"), "utf-16-be", b"\xfe\xff")
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return _DecodedText(raw, raw.decode(encoding), encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("utf-8", raw, 0, len(raw), "unable to decode TeX artifact")


def _mapping_int(item: Mapping[str, object], *names: str) -> int | None:
    for name in names:
        if name in item:
            try:
                return int(item[name])
            except (TypeError, ValueError):
                return None
    return None


def _coerce_and_validate_spans(
    source: str,
    supplied: Iterable[SanitizationSpan | Mapping[str, object]],
    known_paths: Iterable[object],
) -> tuple[tuple[SanitizationSpan, ...], tuple[str, ...]]:
    legal = sanitize_tex_text_with_spans(source, known_paths).spans
    legal_by_identity = {
        (
            item.source_start,
            item.source_end,
            item.original_sha256,
            item.replacement,
            item.category,
        ): item
        for item in legal
    }
    raw_items: list[tuple[int, int, str, str, str, str, int | None, int | None]] = []
    failures: list[str] = []
    for supplied_item in supplied:
        if isinstance(supplied_item, SanitizationSpan):
            raw_items.append((
                supplied_item.source_start,
                supplied_item.source_end,
                supplied_item.original_sha256,
                supplied_item.replacement,
                supplied_item.category,
                supplied_item.reason,
                supplied_item.packaged_start,
                supplied_item.packaged_end,
            ))
            continue
        if not isinstance(supplied_item, Mapping):
            failures.append("authorized_span_invalid_type")
            continue
        start = _mapping_int(supplied_item, "source_start", "start")
        end = _mapping_int(supplied_item, "source_end", "end")
        if start is None or end is None or start < 0 or end <= start or end > len(source):
            failures.append("authorized_span_invalid_bounds")
            continue
        original_hash = str(supplied_item.get("original_sha256") or "")
        if not original_hash:
            original_hash = hashlib.sha256(source[start:end].encode("utf-8")).hexdigest()
        raw_items.append((
            start,
            end,
            original_hash,
            str(supplied_item.get("replacement") or ""),
            str(supplied_item.get("category") or ""),
            str(supplied_item.get("reason") or ""),
            _mapping_int(supplied_item, "packaged_start"),
            _mapping_int(supplied_item, "packaged_end"),
        ))

    raw_items.sort(key=lambda item: (item[0], item[1]))
    spans: list[SanitizationSpan] = []
    source_cursor = 0
    packaged_cursor = 0
    for start, end, original_hash, replacement, category, _reason, stated_start, stated_end in raw_items:
        if start < source_cursor:
            failures.append("authorized_spans_overlap")
            continue
        actual_hash = hashlib.sha256(source[start:end].encode("utf-8")).hexdigest()
        if actual_hash != original_hash:
            failures.append("authorized_span_source_hash_mismatch")
            continue
        identity = (start, end, original_hash, replacement, category)
        authorized = legal_by_identity.get(identity)
        if authorized is None:
            failures.append("authorized_span_not_evidence_backed")
            continue
        packaged_cursor += start - source_cursor
        calculated_start = packaged_cursor
        calculated_end = calculated_start + len(replacement)
        if stated_start is not None and stated_start != calculated_start:
            failures.append("authorized_span_packaged_start_mismatch")
            continue
        if stated_end is not None and stated_end != calculated_end:
            failures.append("authorized_span_packaged_end_mismatch")
            continue
        spans.append(SanitizationSpan(
            source_start=start,
            source_end=end,
            packaged_start=calculated_start,
            packaged_end=calculated_end,
            original_sha256=original_hash,
            replacement=replacement,
            category=category,
            reason=authorized.reason,
        ))
        source_cursor = end
        packaged_cursor = calculated_end
    return tuple(spans), tuple(dict.fromkeys(failures))


def _apply_authorized_spans(source: str, spans: Sequence[SanitizationSpan]) -> str:
    output: list[str] = []
    cursor = 0
    for item in spans:
        output.extend((source[cursor:item.source_start], item.replacement))
        cursor = item.source_end
    output.append(source[cursor:])
    return "".join(output)


def _mask_authorized_spans(
    source: str,
    packaged: str,
    spans: Sequence[SanitizationSpan],
) -> tuple[str, str]:
    source_parts: list[str] = []
    packaged_parts: list[str] = []
    source_cursor = 0
    packaged_cursor = 0
    for item in spans:
        source_parts.extend((source[source_cursor:item.source_start], _REDACTION_SENTINEL))
        packaged_parts.extend((packaged[packaged_cursor:item.packaged_start], _REDACTION_SENTINEL))
        source_cursor = item.source_end
        packaged_cursor = item.packaged_end
    source_parts.append(source[source_cursor:])
    packaged_parts.append(packaged[packaged_cursor:])
    return "".join(source_parts), "".join(packaged_parts)


def _environment_tokens(text: str) -> tuple[tuple[str, ...], bool]:
    tokens: list[str] = []
    stack: list[str] = []
    balanced = True
    for match in _ENV_RE.finditer(_masked(text)):
        action = match.group("action")
        name = match.group("name").strip()
        tokens.append(f"{action}:{name}")
        if action == "begin":
            stack.append(name)
        elif not stack or stack.pop() != name:
            balanced = False
    if stack:
        balanced = False
    return tuple(tokens), balanced


def _brace_signature(text: str) -> tuple[tuple[str, ...], bool]:
    value = _masked(text)
    signature: list[str] = []
    depth = 0
    cursor = 0
    while cursor < len(value):
        if value.startswith("\\verb", cursor) and cursor + 5 < len(value):
            delimiter = value[cursor + 5]
            if not delimiter.isspace() and delimiter not in "{}":
                closing = value.find(delimiter, cursor + 6)
                if closing >= 0:
                    cursor = closing + 1
                    continue
        char = value[cursor]
        slash_count = 0
        before = cursor - 1
        while before >= 0 and value[before] == "\\":
            slash_count += 1
            before -= 1
        if char in "{}" and slash_count % 2 == 0:
            signature.append(char)
            depth += 1 if char == "{" else -1
            if depth < 0:
                return tuple(signature), False
        cursor += 1
    return tuple(signature), depth == 0


def _commands(text: str) -> tuple[str, ...]:
    return tuple(_COMMAND_RE.findall(_masked(text)))


def _conservation_check(name: str, source: Sequence[str], packaged: Sequence[str]) -> IntegrityCheck:
    return IntegrityCheck(
        name=name,
        passed=tuple(source) == tuple(packaged),
        source_count=len(source),
        packaged_count=len(packaged),
        source_sha256=_token_digest(tuple(source)),
        packaged_sha256=_token_digest(tuple(packaged)),
    )


def _boolean_check(name: str, passed: bool) -> IntegrityCheck:
    return IntegrityCheck(name=name, passed=bool(passed))


class AuditPackagingIntegrityGate:
    """Accumulate post-sanitization TeX checks and produce one machine result."""

    def __init__(self, *, ruleset=None) -> None:
        self.ruleset = ruleset
        self._artifacts: list[TexArtifactIntegrityResult] = []

    @property
    def artifacts(self) -> tuple[TexArtifactIntegrityResult, ...]:
        return tuple(self._artifacts)

    def check_tex_artifact(
        self,
        original: bytes | str,
        packaged: bytes | str,
        *,
        artifact_id: str = "",
        artifact_role: str = "",
        path: str = "",
        authorized_spans: Iterable[SanitizationSpan | Mapping[str, object]] = (),
        known_paths: Iterable[object] = (),
    ) -> TexArtifactIntegrityResult:
        failure_codes: list[str] = []
        try:
            source = _decode_tex(original)
            destination = _decode_tex(packaged)
        except (TypeError, UnicodeDecodeError, UnicodeError):
            source_raw = original.encode("utf-8") if isinstance(original, str) else bytes(original)
            packaged_raw = packaged.encode("utf-8") if isinstance(packaged, str) else bytes(packaged)
            result = TexArtifactIntegrityResult(
                artifact_id=str(artifact_id),
                artifact_role=str(artifact_role),
                path=str(path),
                source_bytes_sha256=_sha256_bytes(source_raw),
                packaged_bytes_sha256=_sha256_bytes(packaged_raw),
                bytes_equal=source_raw == packaged_raw,
                sanitization_applied=False,
                authorized_spans=(),
                checks=(_boolean_check("tex_decodable", False),),
                failure_codes=("tex_decode_failed",),
            )
            self._artifacts.append(result)
            return result

        spans, span_failures = _coerce_and_validate_spans(
            source.text,
            tuple(authorized_spans),
            tuple(known_paths),
        )
        failure_codes.extend(span_failures)
        expected_text = _apply_authorized_spans(source.text, spans)
        expected_bytes = source.encode(expected_text)
        authorized_only = expected_bytes == destination.raw
        if not authorized_only:
            failure_codes.append("unauthorized_tex_change")
        if spans and source.raw == destination.raw:
            failure_codes.append("authorized_span_without_actual_redaction")

        normalized_source, normalized_packaged = _mask_authorized_spans(
            source.text,
            destination.text,
            spans,
        )
        checks: list[IntegrityCheck] = [
            _boolean_check("tex_decodable", True),
            _boolean_check("authorized_change_only", authorized_only and not span_failures),
        ]
        try:
            invariants = check_invariants(
                normalized_source,
                normalized_packaged,
                check_body_text=True,
                pack=self.ruleset,
            )
            source_math = tuple(math_tokens(normalized_source))
            packaged_math = tuple(math_tokens(normalized_packaged))
            source_body = tuple(body_text_tokens(normalized_source, pack=self.ruleset))
            packaged_body = tuple(body_text_tokens(normalized_packaged, pack=self.ruleset))
            checks.extend((
                _conservation_check("body_text_ordered_conservation", source_body, packaged_body),
                _conservation_check("math_token_conservation", source_math, packaged_math),
                _conservation_check("label_conservation", tuple(labels(normalized_source)), tuple(labels(normalized_packaged))),
                _conservation_check("ref_conservation", tuple(refs(normalized_source)), tuple(refs(normalized_packaged))),
                _conservation_check("cite_conservation", tuple(cites(normalized_source)), tuple(cites(normalized_packaged))),
            ))
            # ``check_invariants`` is deliberately also evaluated so future
            # invariant expansion cannot silently weaken this packaging gate.
            if not invariants["body_text"]["equal"]:
                failure_codes.append("body_text_ordered_conservation_failed")
            if not invariants["math"]["equal"]:
                failure_codes.append("math_token_conservation_failed")
            if not invariants["labels"]["equal"]:
                failure_codes.append("label_conservation_failed")
            if not invariants["refs"]["equal"]:
                failure_codes.append("ref_conservation_failed")
            if not invariants["cites"]["equal"]:
                failure_codes.append("cite_conservation_failed")
        except Exception:  # noqa: BLE001 - an unverifiable artifact must fail closed
            checks.extend((
                _boolean_check("body_text_ordered_conservation", False),
                _boolean_check("math_token_conservation", False),
                _boolean_check("label_conservation", False),
                _boolean_check("ref_conservation", False),
                _boolean_check("cite_conservation", False),
            ))
            failure_codes.append("semantic_conservation_check_failed")

        source_env, source_env_balanced = _environment_tokens(normalized_source)
        packaged_env, packaged_env_balanced = _environment_tokens(normalized_packaged)
        suffix = PurePosixPath(str(path).replace("\\", "/")).suffix.casefold()
        # Class/style sources and unified diff hunks are TeX fragments rather
        # than standalone documents.  They may legitimately start/end inside
        # an environment, but packaging must still conserve their exact
        # environment and brace-token sequence.
        support_file = suffix in {".cls", ".sty", ".def", ".cfg", ".clo", ".diff"}
        environment_balance_ok = (
            source_env == packaged_env
            if support_file
            else source_env_balanced and packaged_env_balanced
        )
        checks.extend((
            _boolean_check(
                "environment_balance",
                environment_balance_ok,
            ),
            _conservation_check("environment_token_conservation", source_env, packaged_env),
        ))
        if not environment_balance_ok:
            failure_codes.append("environment_balance_failed")
        if source_env != packaged_env:
            failure_codes.append("environment_token_conservation_failed")

        source_braces, source_braces_balanced = _brace_signature(normalized_source)
        packaged_braces, packaged_braces_balanced = _brace_signature(normalized_packaged)
        brace_balance_ok = (
            source_braces == packaged_braces
            if support_file
            else source_braces_balanced and packaged_braces_balanced
        )
        checks.extend((
            _boolean_check("brace_balance", brace_balance_ok),
            _conservation_check("brace_structure_conservation", source_braces, packaged_braces),
        ))
        if not brace_balance_ok:
            failure_codes.append("brace_balance_failed")
        if source_braces != packaged_braces:
            failure_codes.append("brace_structure_conservation_failed")

        source_commands = _commands(normalized_source)
        packaged_commands = _commands(normalized_packaged)
        checks.append(_conservation_check(
            "latex_command_token_conservation",
            source_commands,
            packaged_commands,
        ))
        if source_commands != packaged_commands:
            failure_codes.append("latex_command_token_conservation_failed")

        for item in checks:
            if not item.passed and item.name not in {
                "tex_decodable",
                "authorized_change_only",
                "environment_balance",
                "environment_token_conservation",
                "brace_balance",
                "brace_structure_conservation",
                "latex_command_token_conservation",
            }:
                code = f"{item.name}_failed"
                if code not in failure_codes:
                    failure_codes.append(code)

        result = TexArtifactIntegrityResult(
            artifact_id=str(artifact_id),
            artifact_role=str(artifact_role),
            path=str(path),
            source_bytes_sha256=_sha256_bytes(source.raw),
            packaged_bytes_sha256=_sha256_bytes(destination.raw),
            bytes_equal=source.raw == destination.raw,
            sanitization_applied=bool(spans) and source.raw != destination.raw,
            authorized_spans=spans,
            checks=tuple(checks),
            failure_codes=tuple(dict.fromkeys(failure_codes)),
        )
        self._artifacts.append(result)
        return result

    # Integration-friendly aliases: callers can use either verb without
    # changing the machine-result contract.
    verify_tex_artifact = check_tex_artifact
    evaluate_tex_artifact = check_tex_artifact

    def evaluate(
        self,
        artifacts: Iterable[TexArtifactPackagingInput],
    ) -> AuditPackagingIntegrityResult:
        for item in artifacts:
            self.check_tex_artifact(
                item.original,
                item.packaged,
                artifact_id=item.artifact_id,
                artifact_role=item.artifact_role,
                path=item.path,
                authorized_spans=item.authorized_spans,
                known_paths=item.known_paths,
            )
        return self.finalize()

    def finalize(self) -> AuditPackagingIntegrityResult:
        failures = tuple(
            {
                "artifact_id": item.artifact_id,
                "path": item.path,
                "code": code,
            }
            for item in self._artifacts
            for code in item.failure_codes
        )
        valid = not failures and all(item.valid for item in self._artifacts)
        return AuditPackagingIntegrityResult(
            artifacts=tuple(self._artifacts),
            packaging_status=PackagingStatus.SUCCESS if valid else PackagingStatus.FAILED,
            audit_package_status=AuditPackageStatus.VALID if valid else AuditPackageStatus.INVALID,
            failures=failures,
        )

    def machine_result(self) -> dict[str, object]:
        return self.finalize().to_dict()


__all__ = [
    "PACKAGING_INTEGRITY_SCHEMA_VERSION",
    "AuditPackageStatus",
    "AuditPackagingIntegrityGate",
    "AuditPackagingIntegrityResult",
    "IntegrityCheck",
    "PackagingStatus",
    "TexArtifactIntegrityResult",
    "TexArtifactPackagingInput",
]
