# -*- coding: utf-8 -*-
"""AI 决策引擎（M1 MVP）。

- LLMClient：OpenAI 兼容 chat/completions 客户端（纯标准库 urllib，
  默认 DeepSeek API），JSON 模式，失败重试 1 次；
- decide_candidates：候选批量 → 决策 JSON → 校验（坐标/环境白名单）→ Decision 列表；
- 决策/复查/OCR 三角色独立配置（base_url/model/key）。
"""

from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .parser import Document
from .patch import Decision
from .prompts import build_decide_system, build_decide_user, build_meta
from .scanner import Candidate

ALLOWED_WRAP_ENVS = {
    "theorem", "lemma", "proposition", "corollary", "definition",
    "remark", "example", "conjecture", "problem", "claim", "proof",
}
ALLOWED_ACTIONS = {"wrap", "move-boundary", "none"}
AI_KINDS = {"theorem-like", "proof", "scope-fix"}
MIN_AI_CONFIDENCE = 0.75


class LLMError(Exception):
    pass


@dataclass
class RoleConfig:
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-chat"
    api_key: str = ""
    timeout: float = 180.0


@dataclass
class AIConfig:
    decide: RoleConfig = field(default_factory=RoleConfig)
    review: RoleConfig = field(default_factory=lambda: RoleConfig(model="deepseek-reasoner"))
    review_enabled: bool = True
    batch_size: int = 30
    context_lines: int = 6
    review_max_rounds: int = 2
    review_batch: int = 25  # 复查分块大小（整本书时避免单次调用超上下文）


class LLMClient:
    def __init__(self, cfg: RoleConfig):
        self.cfg = cfg
        self.last_usage: Dict = {}

    def chat_json(self, system: str, user: str) -> Tuple[dict, Dict]:
        """返回 (解析后的 JSON 对象, usage)。失败抛出 LLMError。"""
        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        if self._is_qwen():
            payload["enable_thinking"] = False
        raw = self._post_chat(payload, "LLM 调用")
        content = self._message_text(raw)
        return self._parse_json(content), self.last_usage

    @staticmethod
    def _parse_json(content: str) -> dict:
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:]
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise LLMError(f"响应不是 JSON: {content[:120]!r}")
        try:
            obj = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise LLMError(f"响应 JSON 无法解析：第 {exc.lineno} 行第 {exc.colno} 列") from None
        if not isinstance(obj, dict):
            raise LLMError("响应 JSON 顶层必须是对象")
        return obj

    def chat_vision(self, system: str, user_text: str, image_data_uri: str) -> str:
        """视觉模型调用（OCR 转写）：返回模型文本。"""
        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": image_data_uri}},
                        {"type": "text", "text": user_text},
                    ],
                },
            ],
            "temperature": 0,
            "max_tokens": 8000,
        }
        if self._is_qwen():
            payload["enable_thinking"] = False
        raw = self._post_chat(payload, "视觉模型调用")
        return self._message_text(raw)

    def _endpoint_url(self) -> str:
        base = (self.cfg.base_url or "").strip().rstrip("/")
        if not base:
            raise LLMError("未配置 API Base URL")
        try:
            parsed = urlsplit(base)
        except ValueError:
            raise LLMError("API Base URL 格式无效") from None
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise LLMError("API Base URL 必须是有效的 http/https 地址")
        if parsed.username or parsed.password:
            raise LLMError("API Base URL 不应包含用户名或密码")
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def _is_qwen(self) -> bool:
        return (self.cfg.model or "").lower().startswith("qwen")

    def _post_chat(self, payload: dict, label: str) -> dict:
        """发送 OpenAI 兼容请求；仅重试限流、服务端错误和暂时性网络错误。"""
        if not self.cfg.api_key:
            raise LLMError("未配置 API Key")
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        for attempt in range(2):
            req = urllib.request.Request(
                self._endpoint_url(),
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.cfg.api_key}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                    body = resp.read().decode("utf-8")
                raw = json.loads(body)
                if not isinstance(raw, dict):
                    raise LLMError(f"{label}失败: 响应不是 JSON 对象")
                self.last_usage = raw.get("usage", {}) or {}
                return raw
            except urllib.error.HTTPError as e:
                detail = self._describe_http_error(e)
                if attempt == 0 and e.code in {408, 409, 425, 429, 500, 502, 503, 504}:
                    time.sleep(2)
                    continue
                raise LLMError(f"{label}失败: {detail}") from None
            except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
                detail = self._redact(str(getattr(e, "reason", e)))
                if attempt == 0:
                    time.sleep(2)
                    continue
                raise LLMError(f"{label}失败: 网络错误: {detail}") from None
            except json.JSONDecodeError:
                raise LLMError(f"{label}失败: 服务返回了非 JSON 响应") from None
        raise LLMError(f"{label}失败: 未知错误")

    def _describe_http_error(self, error: urllib.error.HTTPError) -> str:
        try:
            body = error.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = ""
        detail = ""
        try:
            obj = json.loads(body)
            err = obj.get("error", obj) if isinstance(obj, dict) else {}
            if isinstance(err, dict):
                detail = str(err.get("message") or err.get("code") or "")
            elif err:
                detail = str(err)
        except (TypeError, ValueError):
            detail = body
        detail = self._redact(detail).strip()[:300]
        hints = {
            400: "请求参数或模型不兼容",
            401: "认证失败，请检查 API Key 与 Base URL 是否属于同一区域",
            403: "无权调用该模型，请检查工作空间和模型权限",
            404: "接口或模型不存在，请检查 Base URL 和模型标识",
            429: "请求过于频繁或额度不足，请稍后重试",
        }
        summary = hints.get(error.code, error.reason or "请求失败")
        return f"HTTP {error.code} {summary}" + (f"：{detail}" if detail else "")

    def _redact(self, text: str) -> str:
        safe = text or ""
        if self.cfg.api_key:
            safe = safe.replace(self.cfg.api_key, "[已隐藏]")
        return re.sub(r"sk-(?:ws-|sp-)?[A-Za-z0-9._-]{8,}", "[已隐藏]", safe)

    @staticmethod
    def _message_text(raw: dict) -> str:
        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError("模型响应缺少 choices[0].message.content") from e
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = [str(item.get("text", "")) for item in content if isinstance(item, dict)]
            return "".join(parts)
        if content is None:
            return ""
        raise LLMError("模型响应 content 类型不受支持")


# ---------------------------------------------------------------------------
# 决策
# ---------------------------------------------------------------------------


def _span(d: dict, lo: int, hi: int) -> Optional[Tuple[int, int]]:
    if not isinstance(d, dict):
        return None
    s = d.get("start_line")
    e = d.get("end_line")
    if not isinstance(s, int) or not isinstance(e, int):
        return None
    if s < lo or e > hi or s > e:
        return None
    return (s, e)


def _confidence(item: dict) -> float:
    try:
        return max(0.0, min(1.0, float(item.get("confidence", 0.5))))
    except (TypeError, ValueError):
        return 0.5


def parse_decisions(
    obj: dict,
    candidates: List[Candidate],
    windows: Dict[str, Tuple[int, int]],
    doc: Document,
) -> Tuple[List[Decision], List[dict], List[dict]]:
    """校验 AI 输出并转换为 Decision；越界/非法项转入歧义清单。"""
    decisions: List[Decision] = []
    ambiguous: List[dict] = []
    notes: List[dict] = []
    by_id = {c.id: c for c in candidates}
    raw = obj.get("decisions")
    if not isinstance(raw, list):
        return [], [{"candidate_id": "-", "line": 1, "reason": "AI 响应缺少 decisions 数组"}], []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        cid = item.get("candidate_id", "")
        c = by_id.get(cid)
        if c is None or cid in seen:
            ambiguous.append({"candidate_id": cid, "line": c.span.start_line if c else 1,
                              "reason": "AI 引用了未知或重复的候选，保守忽略"})
            continue
        seen.add(cid)
        action = item.get("action")
        if action not in ALLOWED_ACTIONS:
            ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                              "reason": f"非法动作 {action!r}，保守保留"})
            continue
        lo, hi = windows[cid]
        if action == "none":
            notes.append({"candidate_id": cid, "line": c.span.start_line,
                          "reason": str(item.get("reason", ""))[:120]})
            continue
        env = str(item.get("env", "") or "")
        if action == "wrap":
            if env not in ALLOWED_WRAP_ENVS:
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": f"非法环境 {env!r}，保守保留"})
                continue
            body = _span(item.get("body_span") or {}, lo, hi)
            if body is None:
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": "body_span 缺失或越出上下文范围，保守保留"})
                continue
            if not (body[0] <= c.span.start_line <= body[1]):
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": "body_span 未包含候选标题，保守保留"})
                continue
            conf = _confidence(item)
            if conf < MIN_AI_CONFIDENCE:
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": f"AI 置信度 {conf:.0%} 低于自动修改阈值，需人工确认"})
                continue
            # 可选参数只能来自扫描器在原文中确定性提取的编号/Proof 参数，绝不采用
            # 模型自由生成的 LaTeX 片段。
            source_optional = (
                c.payload.get("proof_arg", "") if c.kind == "proof"
                else c.payload.get("number", "")
            )
            decisions.append(
                Decision(
                    candidate_id=cid,
                    action="wrap",
                    env=env,
                    body_span=body,
                    title_span=(body[0], body[0]),
                    optional_arg=str(source_optional or "")[:120],
                    keep_title_text=True,
                    source="ai",
                    reason=str(item.get("reason", ""))[:120],
                    confidence=conf,
                )
            )
        else:  # move-boundary
            mp = item.get("move_payload") or {}
            old_end = mp.get("old_end_line")
            new_end = mp.get("new_end_line")
            if not isinstance(old_end, int) or not isinstance(new_end, int):
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": "move_payload 缺失，保守保留"})
                continue
            if not (lo <= old_end <= new_end <= hi):
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": "move_payload 行号越出上下文范围，保守保留"})
                continue
            conf = _confidence(item)
            if conf < MIN_AI_CONFIDENCE:
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": f"AI 置信度 {conf:.0%} 低于自动修改阈值，需人工确认"})
                continue
            decisions.append(
                Decision(
                    candidate_id=cid,
                    action="move-boundary",
                    env=c.env_hint,
                    source="ai",
                    reason=str(item.get("reason", ""))[:120],
                    confidence=conf,
                    payload={"old_end_line": old_end, "new_end_line": new_end},
                )
            )
    return decisions, ambiguous, notes


def decide_candidates(
    client,
    doc: Document,
    ctx,
    candidates: List[Candidate],
    ai_config: AIConfig,
    mode: str,
) -> Tuple[List[Decision], List[dict], List[dict], Dict]:
    if not candidates:
        return [], [], [], {}
    system = build_decide_system(build_meta(doc, ctx, mode))
    decisions: List[Decision] = []
    ambiguous: List[dict] = []
    notes: List[dict] = []
    usage_total: Dict = {}
    for i in range(0, len(candidates), max(1, ai_config.batch_size)):
        batch = candidates[i : i + ai_config.batch_size]
        windows = {
            c.id: (
                max(1, c.span.start_line - ai_config.context_lines),
                min(doc.text.count("\n") + 1, c.span.end_line + ai_config.context_lines),
            )
            for c in batch
        }
        user = build_decide_user(doc, batch, ai_config.context_lines)
        obj, usage = client.chat_json(system, user)
        usage_total["model"] = getattr(client, "cfg", None) and client.cfg.model or ""
        for k, v in usage.items():
            if isinstance(v, (int, float)):
                usage_total[k] = usage_total.get(k, 0) + v
        ds, am, nt = parse_decisions(obj, batch, windows, doc)
        decisions.extend(ds)
        ambiguous.extend(am)
        notes.extend(nt)
    return decisions, ambiguous, notes, usage_total
