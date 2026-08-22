# -*- coding: utf-8 -*-
"""Build deterministic, privacy-aware external AI audit submission bundles.

The host application—not an LLM—owns artifact roles, hashes, status and lineage.
This module snapshots real project files, sanitises only copies, deduplicates by
bytes SHA-256, creates honest preview fallbacks, and writes bundles atomically.
"""

from __future__ import annotations

import base64
import csv
import difflib
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .audit_prompt import build_full_prompt, build_readme, build_short_prompt
from .audit_schema import (
    AuditArtifact,
    AuditPreviewStatus,
    AuditProfile,
    AuditSubmissionManifest,
    AuditSubmissionRequest,
    AuditSubmissionResult,
    AuditTerminalStatus,
    AuditWorkflow,
    RunSnapshot,
)
from .preview import preview_storage_filename
from .runbundle import validate_archive_namespace

AUDIT_DIRECTORY = "audit-submissions"
LATEST_POINTER = "latest.json"
SUBMISSION_ID_RE = re.compile(r"^audit-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
OCR_METADATA_RE = re.compile(
    r"^%\s*LaTeXStruct-OCR-Metadata:\s*(\S+)\s*$", re.MULTILINE
)
TEXT_SUFFIXES = {
    ".tex", ".ltx", ".bib", ".md", ".txt", ".json", ".csv", ".log",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".cls", ".sty", ".py",
    ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".xml", ".env",
}
SENSITIVE_BASENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "auth.json", "credentials.json", "secrets.json", "token.json",
    "codex-auth.json", "openai-auth.json", "id_rsa", "id_ed25519",
}
MAX_BUNDLE_BYTES = 500 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 30 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 150 * 1024 * 1024

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|openai[_-]?api[_-]?key|github[_-]?token)"
    r"(\s*[=:]\s*)([\"']?)([^\s\"',}\]]+)([\"']?)"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
OPENAI_KEY_RE = re.compile(r"\bsk-(?:ws-|sp-)?[A-Za-z0-9._-]{8,}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b")
WINDOWS_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/](?:[^\r\n\"'<>|?*]+))")
UNIX_PRIVATE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:home|Users|mnt|private|tmp)/(?:[^\s\"'<>]+)"
)


@dataclass
class _Candidate:
    role: str
    path: str
    data: bytes
    parent_roles: tuple[str, ...] = ()
    source_label: str = ""
    preview_status: AuditPreviewStatus | None = None
    media_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    sanitize_text: bool = True
    source_sha256: str = ""


@dataclass
class _ProjectState:
    project: dict[str, Any]
    meta: dict[str, Any]
    source_text: str
    source_bytes: bytes
    current_text: str
    current_bytes: bytes
    report_text: str
    report_bytes: bytes
    info: dict[str, Any]
    verification: dict[str, Any]
    decisions: dict[str, Any]
    terminal_status: AuditTerminalStatus
    verification_status: str
    attempt: str
    blockers: list[dict[str, Any]]
    warnings: list[str]
    project_dir: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _submission_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"audit-{stamp}-{uuid.uuid4().hex[:8]}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return default


def _read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def _safe_archive_path(value: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip("/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part or "\x00" in part for part in path.parts)
    ):
        raise ValueError(f"审计包路径不安全：{value}")
    validate_archive_namespace([(path.as_posix(), False)])
    return path.as_posix()


def _safe_filename(value: str, fallback: str = "LaTeXStruct") -> str:
    cleaned = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff._ -]+", "_", str(value or "")).strip(" .")
    return (cleaned or fallback)[:100]


def _is_text_path(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in TEXT_SUFFIXES


def _sensitive_basename(path: str) -> bool:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    return name in SENSITIVE_BASENAMES or name.endswith((".pem", ".p12", ".pfx", ".key"))


def _sanitize_text(text: str, project_dir: Path) -> tuple[str, bool]:
    original = text
    project_strings = {
        str(project_dir),
        str(project_dir.resolve()),
        str(project_dir).replace("\\", "/"),
        str(project_dir.resolve()).replace("\\", "/"),
    }
    for value in sorted((item for item in project_strings if item), key=len, reverse=True):
        text = text.replace(value, "<PROJECT_ROOT>")
    text = SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<REDACTED>", text
    )
    text = BEARER_RE.sub("Bearer <REDACTED>", text)
    text = OPENAI_KEY_RE.sub("<REDACTED_API_KEY>", text)
    text = GITHUB_TOKEN_RE.sub("<REDACTED_GITHUB_TOKEN>", text)
    text = WINDOWS_PATH_RE.sub("<LOCAL_PATH>", text)
    text = UNIX_PRIVATE_PATH_RE.sub("<LOCAL_PATH>", text)
    return text, text != original


def _sanitize_bytes(data: bytes, path: str, project_dir: Path) -> tuple[bytes, bool]:
    if not _is_text_path(path):
        return data, False
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, False
    cleaned, changed = _sanitize_text(decoded, project_dir)
    return cleaned.encode("utf-8"), changed


def _sanitize_zip(data: bytes, project_dir: Path) -> tuple[bytes, bool, list[str]]:
    output = io.BytesIO()
    changed = False
    warnings: list[str] = []
    try:
        source = zipfile.ZipFile(io.BytesIO(data), "r")
    except (OSError, zipfile.BadZipFile):
        return data, False, ["原始项目 ZIP 无法解析，未执行 ZIP 内部脱敏"]
    with source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        seen: set[str] = set()
        for member in sorted(source.infolist(), key=lambda item: item.filename):
            if member.is_dir():
                continue
            try:
                name = _safe_archive_path(member.filename)
            except ValueError:
                changed = True
                warnings.append(f"已跳过不安全 ZIP 路径：{member.filename}")
                continue
            folded = name.casefold()
            if folded in seen:
                changed = True
                warnings.append(f"已跳过重复 ZIP 路径：{name}")
                continue
            seen.add(folded)
            if _sensitive_basename(name):
                changed = True
                warnings.append(f"已从审计副本移除敏感文件：{name}")
                continue
            payload = source.read(member)
            payload, member_changed = _sanitize_bytes(payload, name, project_dir)
            changed = changed or member_changed
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, payload)
    return output.getvalue(), changed, warnings


def _extract_ocr_metadata(source_text: str) -> dict[str, Any]:
    match = OCR_METADATA_RE.search(source_text)
    if not match:
        return {}
    try:
        raw = base64.b64decode(match.group(1), validate=True)
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _failure_is_current(project_dir: Path) -> bool:
    paths = [
        project_dir / "last-failure.json",
        project_dir / "last-failed-draft.tex",
        project_dir / "last-failure-report.md",
    ]
    present = [path for path in paths if path.exists()]
    if not present:
        return False
    marker = project_dir / "verification.json"
    try:
        return not marker.exists() or max(path.stat().st_mtime_ns for path in present) > marker.stat().st_mtime_ns
    except OSError:
        return True


def _verification_blockers(info: Mapping[str, Any], verification: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = info.get("failures")
    if not isinstance(raw, list):
        raw = verification.get("failures")
    blockers: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for index, item in enumerate(raw, start=1):
            if not isinstance(item, Mapping):
                continue
            blockers.append({
                "id": str(item.get("id") or f"verification-{index}"),
                "severity": str(item.get("severity") or "P0"),
                "summary": str(item.get("summary") or item.get("label") or "机器检查未通过"),
                "action": str(item.get("action") or "修复后重新分析"),
                "details": list(item.get("details") or [])[:20],
            })
    return blockers


def _load_project_state(store: Any, pid: str, latest_job: Mapping[str, Any] | None = None) -> _ProjectState:
    project = store.get(pid)
    if project is None:
        raise ValueError("项目不存在")
    project_dir = Path(store._dir(pid)).resolve()
    meta = _read_json(project_dir / "meta.json", {})
    if not isinstance(meta, dict):
        meta = {}
    source_text = store.read_source(pid)
    source_path = project_dir / "source.tex"
    source_bytes = source_path.read_bytes() if source_path.is_file() else source_text.encode("utf-8")

    warnings: list[str] = []
    info: dict[str, Any] = {}
    verification: dict[str, Any] = {}
    current_text = source_text
    current_bytes = source_bytes
    report_text = "# LaTeXStruct 当前运行\n\n本次运行尚未产生结构化结果。\n"
    report_bytes = report_text.encode("utf-8")
    attempt = "source"
    verified = False

    failed = store.read_failed_attempt(pid) if _failure_is_current(project_dir) else None
    if isinstance(failed, dict):
        info = dict(failed.get("details") or {})
        verification = dict(info.get("verification") or {})
        current_text = str(failed.get("draft") or source_text)
        current_bytes = current_text.encode("utf-8")
        report_text = str(failed.get("report") or report_text)
        report_bytes = report_text.encode("utf-8")
        attempt = "blocked"
    elif (project_dir / "result.tex").is_file() and (project_dir / "verification.json").is_file():
        info = _read_json(project_dir / "verification.json", {})
        if not isinstance(info, dict):
            info = {}
        current_bytes = (project_dir / "result.tex").read_bytes()
        current_text = current_bytes.decode("utf-8", errors="replace")
        if (project_dir / "report.md").is_file():
            report_bytes = (project_dir / "report.md").read_bytes()
            report_text = report_bytes.decode("utf-8", errors="replace")
        verification = dict(info.get("verification") or {})
        expected = str(info.get("result_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or expected != _sha256(current_bytes):
            warnings.append("result.tex 与 verification.json 的结果哈希不一致")
        else:
            verified = verification.get("safe_to_export") is True
        attempt = "committed"

    job_status = str((latest_job or {}).get("status") or "").lower()
    if verified:
        terminal = AuditTerminalStatus.SUCCESS
        verification_status = "VERIFIED"
    elif job_status == "cancelled":
        terminal = AuditTerminalStatus.CANCELLED
        verification_status = "UNVERIFIED"
    elif job_status == "error" and attempt == "source":
        terminal = AuditTerminalStatus.FAILED
        verification_status = "UNVERIFIED"
    elif job_status in {"running", "pausing", "paused", "cancelling", "committing"}:
        terminal = AuditTerminalStatus.PARTIAL
        verification_status = "UNVERIFIED"
    else:
        terminal = AuditTerminalStatus.UNVERIFIED
        verification_status = "UNVERIFIED"

    blockers = _verification_blockers(info, verification)
    if terminal is not AuditTerminalStatus.SUCCESS and not blockers:
        summary = {
            AuditTerminalStatus.FAILED: "任务失败，未产生可验证结果",
            AuditTerminalStatus.PARTIAL: "任务仅完成部分阶段",
            AuditTerminalStatus.CANCELLED: "任务已取消",
        }.get(terminal, "没有与当前工件绑定的完整通过记录")
        blockers.append({
            "id": "verification-state",
            "severity": "P0",
            "summary": summary,
            "action": "根据包内报告和日志修复后重新运行",
            "details": [],
        })
    if warnings:
        blockers.append({
            "id": "artifact-integrity",
            "severity": "P0",
            "summary": warnings[0],
            "action": "重新分析以建立一致的结果与验证记录",
            "details": warnings[:10],
        })

    decisions = {
        "decisions": _read_json(project_dir / "decisions.json", []),
        "items": info.get("items") or [],
        "review": info.get("review") or {},
        "ambiguous": info.get("ambiguous") or [],
        "applied": info.get("applied") or [],
        "rejected": info.get("rejected") or [],
        "attempt": attempt,
    }
    return _ProjectState(
        project=dict(project), meta=meta, source_text=source_text,
        source_bytes=source_bytes, current_text=current_text,
        current_bytes=current_bytes, report_text=report_text,
        report_bytes=report_bytes, info=info, verification=verification,
        decisions=decisions, terminal_status=terminal,
        verification_status=verification_status, attempt=attempt,
        blockers=blockers, warnings=warnings, project_dir=project_dir,
    )


def _workflow_for(state: _ProjectState) -> AuditWorkflow:
    kind = str(state.meta.get("kind") or "")
    if kind == "folder":
        return AuditWorkflow.MULTIFILE_PROJECT
    if kind == "ocr":
        return (
            AuditWorkflow.OCR_ONLY
            if state.attempt == "source"
            else AuditWorkflow.OCR_ANALYSIS_REVIEW
        )
    template = str(state.meta.get("template") or "")
    mode = str(state.meta.get("mode") or state.project.get("mode") or "")
    if template and template not in {"preserve", "preserve-source"} and mode != "ai":
        return AuditWorkflow.TEMPLATE_CONVERSION
    return AuditWorkflow.ANALYSIS_REVIEW_ONLY


def _reviewed_ids_hash(values: tuple[str, ...] | list[str]) -> str:
    canonical = "\n".join(sorted({str(item) for item in values if str(item)})).encode("utf-8")
    return _sha256(canonical)


def project_fingerprint(project_dir: str | Path, reviewed_candidate_ids: tuple[str, ...] = ()) -> str:
    root = Path(project_dir).resolve()
    names = (
        "meta.json", "source.tex", "original-source.tex", "result.tex", "report.md",
        "decisions.json", "verification.json", "last-failure.json",
        "last-failed-draft.tex", "last-failure-report.md", "original-files.zip",
    )
    digest = hashlib.sha256()
    for name in names:
        path = root / name
        digest.update(name.encode("utf-8") + b"\0")
        try:
            data = path.read_bytes()
        except OSError:
            data = b"<missing>"
        digest.update(len(data).to_bytes(8, "big") + data)
    info = _read_json(root / "verification.json", {})
    verification = info.get("verification") if isinstance(info, Mapping) else None
    evidence = verification.get("preview_artifact") if isinstance(verification, Mapping) else None
    if isinstance(evidence, Mapping):
        status = str(evidence.get("status") or "")
        sha = str(evidence.get("sha256") or "")
        try:
            filename = preview_storage_filename(status, sha)
            payload = (root / filename).read_bytes()
        except (OSError, ValueError):
            payload = b"<missing-preview>"
        digest.update(b"preview\0" + payload)
    digest.update(b"reviewed\0" + _reviewed_ids_hash(reviewed_candidate_ids).encode("ascii"))
    return digest.hexdigest()


def _runtime_record(state: _ProjectState, runtime_identity: Mapping[str, Any]) -> dict[str, Any]:
    producer = state.info.get("producer_identity") if isinstance(state.info, dict) else {}
    producer = producer if isinstance(producer, Mapping) else {}
    processing = state.meta.get("ocr_processing") if isinstance(state.meta.get("ocr_processing"), Mapping) else {}
    verification = state.verification
    models = verification.get("ai_models") if isinstance(verification.get("ai_models"), Mapping) else {}
    return {
        "app_version": str(runtime_identity.get("app_version") or producer.get("app_version") or "unknown"),
        "git_commit": str(runtime_identity.get("commit") or producer.get("commit") or "unknown"),
        "build_id": str(runtime_identity.get("build_id") or producer.get("build_id") or "unknown"),
        "prompt_version": str(producer.get("prompt_version") or runtime_identity.get("prompt_version") or "unknown"),
        "decide_model": str(models.get("decide") or "unknown"),
        "review_model": str(models.get("review") or "unknown"),
        "ocr_model": str(processing.get("model") or "unknown"),
        "ocr_backend": str(processing.get("backend") or "unknown"),
    }


def _page_range(state: _ProjectState, ocr_meta: Mapping[str, Any]) -> tuple[int, ...]:
    source = state.meta.get("ocr_source") if isinstance(state.meta.get("ocr_source"), Mapping) else {}
    start, end = source.get("selected_start"), source.get("selected_end")
    if isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= 100000:
        return tuple(range(start, end + 1))
    pages = ocr_meta.get("pages") if isinstance(ocr_meta, Mapping) else None
    if isinstance(pages, list):
        return tuple(page for page in pages if isinstance(page, int) and 1 <= page <= 100000)
    return ()


def _candidate_file(
    candidates: list[_Candidate], *, role: str, path: str, source: Path,
    parent_roles: tuple[str, ...] = (),
    preview_status: AuditPreviewStatus | None = None,
    metadata: dict[str, Any] | None = None,
    sanitize_text: bool = True,
) -> bool:
    if not source.is_file() or source.is_symlink():
        return False
    try:
        data = source.read_bytes()
    except OSError:
        return False
    candidates.append(_Candidate(
        role=role, path=path, data=data, parent_roles=parent_roles,
        source_label=source.name, preview_status=preview_status,
        media_type=mimetypes.guess_type(path)[0] or "application/octet-stream",
        metadata=metadata or {}, sanitize_text=sanitize_text,
        source_sha256=_sha256(data),
    ))
    return True


def _compile_log_bytes(record: Any) -> bytes:
    if not isinstance(record, Mapping):
        return b""
    log = str(record.get("log") or record.get("stdout") or "")
    header = {
        key: record.get(key)
        for key in (
            "available", "ok", "status", "preview_status", "engine", "returncode",
            "passes", "pages", "fatal_line", "errors", "timed_out",
        )
        if key in record
    }
    return (json.dumps(header, ensure_ascii=False, indent=2) + "\n\n" + log).encode("utf-8")


def _load_preview(state: _ProjectState) -> tuple[bytes, AuditPreviewStatus] | None:
    evidence = state.verification.get("preview_artifact")
    if not isinstance(evidence, Mapping):
        return None
    try:
        status = AuditPreviewStatus(str(evidence.get("status") or ""))
    except ValueError:
        return None
    if status is AuditPreviewStatus.SOURCE_PREVIEW:
        return None
    digest = str(evidence.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    try:
        storage = preview_storage_filename(status.value, digest)
        payload = (state.project_dir / storage).read_bytes()
    except (OSError, ValueError):
        return None
    if not payload.startswith(b"%PDF-") or _sha256(payload) != digest:
        return None
    return payload, status


def _source_preview_pdf(text: str, title: str) -> bytes:
    """Create an explicitly labelled source-only PDF without invoking LaTeX."""
    warning = "SOURCE PREVIEW - NOT A LATEX COMPILED RESULT"
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    try:
        try:
            import pymupdf as fitz
        except ImportError:
            import fitz  # type: ignore
        document = fitz.open()
        page = None
        y = 0.0
        for index, raw in enumerate(lines or [""], start=1):
            if page is None or y > 800:
                page = document.new_page(width=595, height=842)
                page.insert_text((36, 30), warning, fontname="helv", fontsize=10)
                safe_title = title.encode("ascii", "backslashreplace").decode("ascii")[:80]
                page.insert_text((36, 47), safe_title, fontname="helv", fontsize=8)
                y = 68
            safe = raw.expandtabs(4).encode("ascii", "backslashreplace").decode("ascii")
            page.insert_text((28, y), f"{index:05d}  {safe}"[:150], fontname="cour", fontsize=6.5)
            y += 8.5
        return document.tobytes(garbage=4, deflate=True)
    except Exception:
        body = f"BT /F1 12 Tf 36 780 Td ({warning}) Tj ET".encode("ascii")
        objects = [
            b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
            b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >> endobj\n",
            b"4 0 obj << /Length " + str(len(body)).encode("ascii") + b" >> stream\n" + body + b"\nendstream endobj\n",
            b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        ]
        output = io.BytesIO()
        output.write(b"%PDF-1.4\n")
        offsets = [0]
        for obj in objects:
            offsets.append(output.tell())
            output.write(obj)
        xref = output.tell()
        output.write(f"xref\n0 {len(objects)+1}\n".encode("ascii"))
        output.write(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
        output.write(f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
        return output.getvalue()


def _diff_bytes(before: str, after: str, before_name: str, after_name: str) -> bytes:
    before_lines = before.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)
    after_lines = after.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)
    return "".join(difflib.unified_diff(
        before_lines, after_lines, fromfile=before_name, tofile=after_name, n=3
    )).encode("utf-8")


def _issues_csv(state: _ProjectState) -> bytes:
    output = io.StringIO(newline="")
    fields = ("issue_id", "severity", "category", "status", "candidate_id", "message", "next_action")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for index, blocker in enumerate(state.blockers, start=1):
        writer.writerow({
            "issue_id": str(blocker.get("id") or f"BLOCKER-{index:03d}"),
            "severity": str(blocker.get("severity") or "P0"),
            "category": "verification", "status": "open", "candidate_id": "",
            "message": str(blocker.get("summary") or ""),
            "next_action": str(blocker.get("action") or ""),
        })
    for index, item in enumerate(state.decisions.get("ambiguous") or [], start=1):
        if not isinstance(item, Mapping):
            continue
        writer.writerow({
            "issue_id": f"AMBIGUOUS-{index:03d}", "severity": "review",
            "category": "structure", "status": "open",
            "candidate_id": str(item.get("candidate_id") or ""),
            "message": str(item.get("reason") or ""),
            "next_action": "对照源文后重新分析",
        })
    return output.getvalue().encode("utf-8")


def _current_project_zip(state: _ProjectState) -> bytes | None:
    original = state.project_dir / "original-files.zip"
    if not original.is_file():
        return None
    per_file = state.info.get("per_file")
    if not isinstance(per_file, Mapping) or not per_file:
        return original.read_bytes()
    try:
        source = zipfile.ZipFile(original, "r")
    except zipfile.BadZipFile:
        return None
    result = io.BytesIO()
    with source, zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        written: set[str] = set()
        for member in sorted(source.infolist(), key=lambda item: item.filename):
            if member.is_dir():
                continue
            try:
                rel = _safe_archive_path(member.filename)
            except ValueError:
                continue
            payload = source.read(member)
            replacement = per_file.get(rel)
            if isinstance(replacement, str):
                payload = replacement.encode("utf-8")
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, payload)
            written.add(rel)
        for rel, value in sorted(per_file.items()):
            if not rel or rel in written or not isinstance(value, str):
                continue
            safe = _safe_archive_path(str(rel))
            info = zipfile.ZipInfo(safe, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, value.encode("utf-8"))
    return result.getvalue()


def _collect_evidence(state: _ProjectState, candidates: list[_Candidate], warnings: list[str]) -> None:
    total = 0
    resources = state.meta.get("ocr_resources") if isinstance(state.meta.get("ocr_resources"), Mapping) else {}
    for group, role, prefix in (
        (resources.get("source_pages") or [], "page_image", "evidence/page-images"),
        (resources.get("formula_crops") or [], "formula_crop", "evidence/formula-crops"),
    ):
        if not isinstance(group, list):
            continue
        for index, item in enumerate(group, start=1):
            if not isinstance(item, Mapping):
                continue
            rel = str(item.get("path") or "").replace("\\", "/")
            try:
                source = (state.project_dir / rel).resolve()
                source.relative_to(state.project_dir)
            except (OSError, ValueError):
                continue
            if not source.is_file() or source.is_symlink():
                continue
            size = source.stat().st_size
            if size > MAX_EVIDENCE_FILE_BYTES or total + size > MAX_EVIDENCE_TOTAL_BYTES:
                warnings.append(f"证据文件超过审计包限额，已跳过：{rel}")
                continue
            suffix = source.suffix.lower() or ".bin"
            if _candidate_file(candidates, role=role, path=f"{prefix}/{index:04d}{suffix}", source=source, sanitize_text=False):
                total += size
    for dirname, role, prefix in (
        ("formula-evidence", "formula_crop", "evidence/formula-crops"),
        ("source-pages", "page_image", "evidence/page-images"),
    ):
        root = state.project_dir / dirname
        if not root.is_dir():
            continue
        for source in sorted(root.rglob("*")):
            if not source.is_file() or source.is_symlink():
                continue
            size = source.stat().st_size
            if size > MAX_EVIDENCE_FILE_BYTES or total + size > MAX_EVIDENCE_TOTAL_BYTES:
                continue
            path = f"{prefix}/{_safe_filename(source.name, 'evidence.bin')}"
            if any(item.path == path for item in candidates):
                continue
            if _candidate_file(candidates, role=role, path=path, source=source, sanitize_text=False):
                total += size


def _collect_candidates(
    state: _ProjectState,
    request: AuditSubmissionRequest,
    workflow: AuditWorkflow,
    ocr_meta: Mapping[str, Any],
) -> tuple[list[_Candidate], list[dict[str, Any]], list[str]]:
    candidates: list[_Candidate] = []
    missing: list[dict[str, Any]] = []
    warnings = list(state.warnings)
    root = state.project_dir
    source_parent: tuple[str, ...] = ()

    if request.include_source and workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}:
        source_info = state.meta.get("ocr_source") if isinstance(state.meta.get("ocr_source"), Mapping) else {}
        rel = str(source_info.get("path") or "")
        source_file = root / rel if rel else root / "__missing__"
        role = "source_pdf" if str(source_info.get("source_type") or "") == "pdf" or rel.lower().endswith(".pdf") else "source_image"
        extension = ".pdf" if role == "source_pdf" else (source_file.suffix.lower() or ".img")
        if not rel or not _candidate_file(candidates, role=role, path=f"inputs/source{extension}", source=source_file, sanitize_text=False):
            missing.append({"role": role, "reason": "OCR 项目没有可验证的原始 PDF/图片"})
        else:
            source_parent = (role,)

    if request.include_source and workflow is AuditWorkflow.MULTIFILE_PROJECT:
        original = root / "original-files.zip"
        if original.is_file():
            payload = original.read_bytes()
            candidates.append(_Candidate(
                role="source_project_zip", path="inputs/original-project.zip", data=payload,
                media_type="application/zip", sanitize_text=False, source_sha256=_sha256(payload),
            ))
            source_parent = ("source_project_zip",)
        else:
            missing.append({"role": "source_project_zip", "reason": "原始多文件项目快照缺失"})

    if request.include_source and workflow not in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW, AuditWorkflow.MULTIFILE_PROJECT}:
        original = root / "original-source.tex"
        source = original if original.is_file() else root / "source.tex"
        role = "original_source_tex" if original.is_file() else "source_tex"
        if _candidate_file(candidates, role=role, path="inputs/source.tex", source=source):
            source_parent = (role,)
        else:
            missing.append({"role": role, "reason": "输入 TeX 缺失"})

    source_role = "raw_ocr_tex" if workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW} else "source_tex"
    source_stage_path = "stages/00_raw_ocr.tex" if source_role == "raw_ocr_tex" else "stages/00_source.tex"
    candidates.append(_Candidate(
        role=source_role, path=source_stage_path, data=state.source_bytes,
        parent_roles=source_parent, source_label="source.tex", media_type="application/x-tex",
        source_sha256=_sha256(state.source_bytes),
    ))

    for filename, role, path in (
        ("preflight.tex", "preflight_tex", "stages/05_preflight.tex"),
        ("ai-analyzed.tex", "ai_analyzed_tex", "stages/10_ai_analyzed.tex"),
        ("ai-reviewed.tex", "ai_reviewed_tex", "stages/20_ai_reviewed.tex"),
        ("pre-template.tex", "pre_template_tex", "stages/20_pre_template.tex"),
        ("post-template.tex", "post_template_tex", "stages/30_post_template.tex"),
    ):
        _candidate_file(candidates, role=role, path=path, source=root / filename, parent_roles=(source_role,))

    if workflow in {AuditWorkflow.ANALYSIS_REVIEW_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}:
        if not any(item.role == "ai_analyzed_tex" for item in candidates):
            missing.append({"role": "ai_analyzed_tex", "reason": "当前流水线未单独持久化分析阶段快照"})
        if not any(item.role == "ai_reviewed_tex" for item in candidates):
            missing.append({"role": "ai_reviewed_tex", "reason": "当前流水线未单独持久化独立审阅阶段快照；当前结果仍会保留"})

    current_role = "current_reviewed_tex" if state.attempt != "source" else "current_unverified_tex"
    candidates.append(_Candidate(
        role=current_role, path="stages/30_current.tex", data=state.current_bytes,
        parent_roles=(source_role,), source_label="current", media_type="application/x-tex",
        source_sha256=_sha256(state.current_bytes),
    ))
    candidates.extend([
        _Candidate("report_markdown", "audit/report.md", state.report_bytes, (current_role,), media_type="text/markdown", source_sha256=_sha256(state.report_bytes)),
        _Candidate("issues_csv", "audit/issues.csv", _issues_csv(state), ("report_markdown",), media_type="text/csv"),
        _Candidate("diff_raw_to_current", "audit/raw_to_current.diff", _diff_bytes(state.source_text, state.current_text, source_stage_path, "stages/30_current.tex"), (source_role, current_role), media_type="text/x-diff"),
    ])

    if request.include_verification and request.profile is not AuditProfile.QUICK:
        candidates.extend([
            _Candidate("verification_json", "audit/verification.json", _json_bytes({"verification": state.verification, "attempt": state.attempt, "terminal_status": state.terminal_status.value}), (current_role,), media_type="application/json"),
            _Candidate("decisions_json", "audit/decisions.json", _json_bytes(state.decisions), (source_role, current_role), media_type="application/json"),
        ])

    if request.include_compile_logs and request.profile is not AuditProfile.QUICK:
        raw_log = _compile_log_bytes(state.verification.get("compile_before"))
        current_log = _compile_log_bytes(state.verification.get("compile_after"))
        if raw_log:
            candidates.append(_Candidate("compile_raw_log", "audit/compile_raw.log", raw_log, (source_role,), media_type="text/plain"))
        else:
            missing.append({"role": "compile_raw_log", "reason": "本次运行没有保存原始 TeX 编译日志"})
        if current_log:
            candidates.append(_Candidate("compile_current_log", "audit/compile_current.log", current_log, (current_role,), media_type="text/plain"))
        else:
            missing.append({"role": "compile_current_log", "reason": "本次运行没有保存当前 TeX 编译日志"})

    preview = _load_preview(state)
    if preview is not None:
        payload, status = preview
        role = "compiled_preview_pdf" if status is AuditPreviewStatus.COMPILED else "partial_compiled_pdf"
        candidates.append(_Candidate(role, f"previews/current_{status.value}.pdf", payload, (current_role,), preview_status=status, media_type="application/pdf", sanitize_text=False, source_sha256=_sha256(payload)))
    else:
        payload = _source_preview_pdf(state.current_text, state.project.get("name") or "LaTeXStruct current source")
        candidates.append(_Candidate("source_preview_pdf", "previews/current_SOURCE_PREVIEW.pdf", payload, (current_role,), preview_status=AuditPreviewStatus.SOURCE_PREVIEW, media_type="application/pdf", sanitize_text=False, metadata={"notice": "This is source rendering, not LaTeX compilation."}))

    if workflow in {AuditWorkflow.OCR_ONLY, AuditWorkflow.OCR_ANALYSIS_REVIEW}:
        raw_preview = _source_preview_pdf(state.source_text, "Raw OCR source preview")
        candidates.append(_Candidate("source_preview_pdf", "previews/raw_ocr_SOURCE_PREVIEW.pdf", raw_preview, (source_role,), preview_status=AuditPreviewStatus.SOURCE_PREVIEW, media_type="application/pdf", sanitize_text=False, metadata={"stage": "raw_ocr", "notice": "This is source rendering, not LaTeX compilation."}))
        if ocr_meta:
            candidates.append(_Candidate("outline_json", "evidence/outline.json", _json_bytes({"outline": ocr_meta.get("outline") or [], "pages": ocr_meta.get("pages") or []}), (source_role,), media_type="application/json"))
        else:
            missing.append({"role": "outline_json", "reason": "OCR metadata 中没有可解析的大纲"})
        quality = state.meta.get("ocr_quality")
        if isinstance(quality, Mapping):
            candidates.append(_Candidate("ocr_quality_json", "audit/ocr-quality.json", _json_bytes(quality), (source_role,), media_type="application/json"))

    candidates.append(_Candidate("metadata_json", "audit/project-metadata.json", _json_bytes({
        "project": {key: state.project.get(key) for key in ("id", "name", "mode", "template", "kind", "created")},
        "meta": state.meta, "attempt": state.attempt,
    }), media_type="application/json"))

    if workflow is AuditWorkflow.MULTIFILE_PROJECT and request.profile is not AuditProfile.QUICK:
        reviewed = _current_project_zip(state)
        if reviewed:
            candidates.append(_Candidate("reviewed_project_zip", "project/reviewed-project.zip", reviewed, ("source_project_zip", current_role), media_type="application/zip", sanitize_text=False, source_sha256=_sha256(reviewed)))
        else:
            missing.append({"role": "reviewed_project_zip", "reason": "无法重建当前多文件项目"})

    if request.include_evidence or request.profile is AuditProfile.FULL:
        _collect_evidence(state, candidates, warnings)
    candidates.sort(key=lambda item: (0 if item.path.startswith("stages/00_") else 1))
    return candidates, missing, warnings


def _deduplicate(candidates: list[_Candidate], project_dir: Path, sanitize: bool) -> tuple[list[AuditArtifact], dict[str, bytes], list[str]]:
    files: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []
    by_digest: dict[str, int] = {}
    warnings: list[str] = []
    for candidate in candidates:
        path = _safe_archive_path(candidate.path)
        payload = bytes(candidate.data)
        sanitized = False
        if sanitize:
            if path.lower().endswith(".zip"):
                payload, sanitized, zip_warnings = _sanitize_zip(payload, project_dir)
                warnings.extend(zip_warnings)
            elif candidate.sanitize_text:
                payload, sanitized = _sanitize_bytes(payload, path, project_dir)
        digest = _sha256(payload)
        previous = by_digest.get(digest)
        if previous is not None:
            records[previous]["aliases"].append(path)
            if candidate.role != records[previous]["role"]:
                records[previous]["alias_roles"].append(candidate.role)
            continue
        by_digest[digest] = len(records)
        records.append({
            "artifact_id": f"{candidate.role}:{digest[:16]}", "role": candidate.role,
            "path": path, "digest": digest, "size": len(payload),
            "media_type": candidate.media_type or mimetypes.guess_type(path)[0] or "application/octet-stream",
            "parent_roles": candidate.parent_roles, "aliases": [], "alias_roles": [],
            "source_sha256": candidate.source_sha256, "preview_status": candidate.preview_status,
            "sanitized": sanitized, "metadata": candidate.metadata,
        })
        files[path] = payload
    role_to_id: dict[str, str] = {}
    for record in records:
        role_to_id.setdefault(record["role"], record["artifact_id"])
        for role in record["alias_roles"]:
            role_to_id.setdefault(role, record["artifact_id"])
    artifacts = [
        AuditArtifact(
            artifact_id=record["artifact_id"], artifact_role=record["role"], path=record["path"],
            bytes_sha256=record["digest"], size_bytes=record["size"], media_type=record["media_type"],
            parents=tuple(role_to_id[role] for role in record["parent_roles"] if role in role_to_id),
            aliases=tuple(record["aliases"]), alias_roles=tuple(dict.fromkeys(record["alias_roles"])),
            source_sha256=record["source_sha256"], preview_status=record["preview_status"],
            sanitized=record["sanitized"], metadata=record["metadata"],
        ) for record in records
    ]
    validate_archive_namespace([(path, False) for path in files])
    return artifacts, files, warnings


def _write_atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_zip(path: Path, files: Mapping[str, bytes]) -> None:
    validate_archive_namespace([(name, False) for name in files])
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name in sorted(files):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, files[name])
        if temporary.stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError("AI 审计提交包超过 500 MB，请关闭完整取证或拆分源项目")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_audit_submission(
    *, store: Any, pid: str,
    request: AuditSubmissionRequest | Mapping[str, Any] | None = None,
    runtime_identity: Mapping[str, Any] | None = None,
    latest_job: Mapping[str, Any] | None = None,
    create_package: bool = True,
) -> AuditSubmissionResult:
    """Create one immutable submission snapshot and optionally its full ZIP."""
    request = request if isinstance(request, AuditSubmissionRequest) else AuditSubmissionRequest.from_mapping(request)
    state = _load_project_state(store, pid, latest_job)
    if state.terminal_status is AuditTerminalStatus.PARTIAL and latest_job and str(latest_job.get("status")) in {"running", "pausing", "paused", "cancelling", "committing"}:
        raise ValueError("项目仍在处理中；请等待进入终态后再生成审计提交包")
    workflow = _workflow_for(state)
    ocr_meta = _extract_ocr_metadata(state.source_text)
    candidates, missing, warnings = _collect_candidates(state, request, workflow, ocr_meta)
    artifacts, artifact_files, dedupe_warnings = _deduplicate(candidates, state.project_dir, request.sanitize)
    warnings.extend(dedupe_warnings)
    reviewed_hash = _reviewed_ids_hash(request.reviewed_candidate_ids)
    fingerprint = project_fingerprint(state.project_dir, request.reviewed_candidate_ids)
    generated_at = _utc_now()
    sid = _submission_id()
    runtime = _runtime_record(state, runtime_identity or {})
    snapshot = RunSnapshot(
        snapshot_id=f"snapshot:{fingerprint}", project_id=pid,
        project_name=str(state.project.get("name") or "未命名项目"), workflow_type=workflow,
        terminal_status=state.terminal_status, verification_status=state.verification_status,
        generated_at_utc=generated_at, project_fingerprint=fingerprint,
        reviewed_candidate_ids_sha256=reviewed_hash, runtime=runtime,
        template=str(state.meta.get("template") or state.project.get("template") or ""),
        page_range=_page_range(state, ocr_meta), blockers=tuple(state.blockers),
        artifacts=tuple(artifacts), missing_artifacts=tuple(missing),
        metadata={"attempt": state.attempt, "reviewed_candidate_ids": list(request.reviewed_candidate_ids), "request": request.to_dict(), "llm_used_for_packaging": False},
    )
    safe_project = _safe_filename(snapshot.project_name, "LaTeXStruct")
    stamp = generated_at.replace(":", "").replace("-", "")
    package_filename = f"{safe_project}__AI-Audit__{stamp}__{sid}__{state.terminal_status.value}.zip"
    provisional = AuditSubmissionManifest(submission_id=sid, snapshot=snapshot, profile=request.profile, package_filename=package_filename, warnings=tuple(dict.fromkeys(warnings)))
    short_prompt = build_short_prompt(provisional)
    full_prompt = build_full_prompt(provisional, request.audit_focus)
    readme = build_readme(provisional)
    control_bytes = {
        "00_README_FIRST.md": readme.encode("utf-8"),
        "01_PROMPT_SHORT.txt": (short_prompt + "\n").encode("utf-8"),
        "02_PROMPT_FULL.md": full_prompt.encode("utf-8"),
    }
    control_records = {name: {"bytes_sha256": _sha256(data), "size_bytes": len(data)} for name, data in control_bytes.items()}
    manifest = AuditSubmissionManifest(submission_id=sid, snapshot=snapshot, profile=request.profile, package_filename=package_filename, warnings=tuple(dict.fromkeys(warnings)), control_files=control_records)
    control_bytes["submission_manifest.json"] = _json_bytes(manifest.to_dict())
    sums_files = {**artifact_files, **control_bytes}
    sums_bytes = "".join(f"{_sha256(sums_files[name])}  {name}\n" for name in sorted(sums_files)).encode("utf-8")
    package_files = {**sums_files, "audit/SHA256SUMS": sums_bytes} if create_package else {}

    root = state.project_dir / AUDIT_DIRECTORY
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".tmp-{sid}-{uuid.uuid4().hex[:8]}"
    final_dir = root / sid
    if final_dir.exists():
        raise ValueError("审计提交包 ID 冲突，请重新生成")
    staging.mkdir(parents=True, exist_ok=False)
    package_path = ""
    package_sha = ""
    try:
        for name, data in control_bytes.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (staging / "audit").mkdir(parents=True, exist_ok=True)
        (staging / "audit" / "SHA256SUMS").write_bytes(sums_bytes)
        if create_package:
            target = staging / package_filename
            _write_zip(target, package_files)
            package_sha = _sha256(target.read_bytes())
        state_record = {
            "submission_id": sid, "created_at_utc": generated_at,
            "project_fingerprint": fingerprint, "reviewed_candidate_ids_sha256": reviewed_hash,
            "package_filename": package_filename if create_package else "", "package_sha256": package_sha,
            "lightweight_only": not create_package, "status": state.terminal_status.value,
            "workflow_type": workflow.value, "profile": request.profile.value,
        }
        (staging / "submission-state.json").write_bytes(_json_bytes(state_record))
        os.replace(staging, final_dir)
        package_path = str(final_dir / package_filename) if create_package else ""
        _write_atomic_bytes(root / LATEST_POINTER, _json_bytes({**state_record, "directory": sid}))
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return AuditSubmissionResult(
        submission_id=sid, manifest=manifest, prompt_short=short_prompt,
        prompt_full=full_prompt, readme=readme, package_path=package_path,
        package_sha256=package_sha, lightweight_only=not create_package,
    )


def load_submission_summary(
    *, store: Any, pid: str, submission_id: str | None = None,
    reviewed_candidate_ids: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    project_dir = Path(store._dir(pid)).resolve()
    root = project_dir / AUDIT_DIRECTORY
    if submission_id is None:
        pointer = _read_json(root / LATEST_POINTER, None)
        if not isinstance(pointer, dict):
            return None
        submission_id = str(pointer.get("directory") or pointer.get("submission_id") or "")
    if not SUBMISSION_ID_RE.fullmatch(str(submission_id or "")):
        raise ValueError("审计提交包 ID 格式无效")
    directory = root / str(submission_id)
    state = _read_json(directory / "submission-state.json", None)
    manifest = _read_json(directory / "submission_manifest.json", None)
    if not isinstance(state, dict) or not isinstance(manifest, dict):
        return None
    current_fingerprint = project_fingerprint(project_dir, reviewed_candidate_ids)
    stale = current_fingerprint != str(state.get("project_fingerprint") or "")
    filename = str(state.get("package_filename") or "")
    package = directory / filename if filename else None
    package_ready = bool(package and package.is_file())
    if package_ready:
        actual = _sha256(package.read_bytes())
        if actual != str(state.get("package_sha256") or ""):
            package_ready = False
            stale = True
    return {
        "ok": True, "submission_id": submission_id,
        "status": state.get("status") or (manifest.get("workflow") or {}).get("status"),
        "verification_status": (manifest.get("workflow") or {}).get("verification_status", "UNVERIFIED"),
        "workflow_type": state.get("workflow_type") or (manifest.get("workflow") or {}).get("type"),
        "profile": state.get("profile") or manifest.get("profile"), "generated_at_utc": state.get("created_at_utc"),
        "package_filename": filename, "package_sha256": state.get("package_sha256") or "",
        "package_ready": package_ready, "lightweight_only": bool(state.get("lightweight_only")),
        "prompt_short": _read_text(directory / "01_PROMPT_SHORT.txt").strip(), "stale": stale,
        "project_fingerprint": state.get("project_fingerprint"), "current_project_fingerprint": current_fingerprint,
        "reviewed_candidate_ids_sha256": state.get("reviewed_candidate_ids_sha256"), "warnings": manifest.get("warnings") or [],
    }


def submission_package_path(store: Any, pid: str, submission_id: str) -> Path:
    if not SUBMISSION_ID_RE.fullmatch(str(submission_id or "")):
        raise ValueError("审计提交包 ID 格式无效")
    project_dir = Path(store._dir(pid)).resolve()
    directory = project_dir / AUDIT_DIRECTORY / submission_id
    state = _read_json(directory / "submission-state.json", None)
    if not isinstance(state, dict):
        raise FileNotFoundError("审计提交包不存在")
    filename = str(state.get("package_filename") or "")
    if not filename:
        raise FileNotFoundError("当前仅准备了轻量审计材料，请先生成完整 ZIP")
    path = (directory / filename).resolve()
    path.relative_to(directory.resolve())
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("审计提交包文件缺失")
    expected = str(state.get("package_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or _sha256(path.read_bytes()) != expected:
        raise ValueError("审计提交包哈希校验失败")
    return path


def submission_directory(store: Any, pid: str) -> Path:
    path = Path(store._dir(pid)).resolve() / AUDIT_DIRECTORY
    path.mkdir(parents=True, exist_ok=True)
    return path
