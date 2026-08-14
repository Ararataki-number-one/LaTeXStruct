# -*- coding: utf-8 -*-
"""AI 决策引擎（M1 MVP）。

- LLMClient：OpenAI 兼容 chat/completions 客户端（纯标准库 urllib，
  默认 DeepSeek API），JSON 模式，失败重试 1 次；
- decide_candidates：候选批量 → 决策 JSON → 校验（坐标/环境白名单）→ Decision 列表；
- 决策/复查/OCR 三角色独立配置（base_url/model/key）。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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


class LLMClient:
    def __init__(self, cfg: RoleConfig):
        self.cfg = cfg
        self.last_usage: Dict = {}

    def chat_json(self, system: str, user: str) -> Tuple[dict, Dict]:
        """返回 (解析后的 JSON 对象, usage)。失败抛出 LLMError。"""
        if not self.cfg.api_key:
            raise LLMError("未配置 API Key")
        url = self.cfg.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(2):
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.cfg.api_key}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))
                content = raw["choices"][0]["message"]["content"]
                self.last_usage = raw.get("usage", {}) or {}
                return self._parse_json(content), self.last_usage
            except (LLMError, KeyError):
                raise
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt == 0:
                    time.sleep(2)
        raise LLMError(f"LLM 调用失败: {last_err}")

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
        return json.loads(text[start : end + 1])

    def chat_vision(self, system: str, user_text: str, image_data_uri: str) -> str:
        """视觉模型调用（OCR 转写）：返回模型文本。"""
        if not self.cfg.api_key:
            raise LLMError("未配置 API Key")
        url = self.cfg.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": user_text},
                        {"type": "image_url", "image_url": {"url": image_data_uri}},
                    ],
                },
            ],
            "temperature": 0,
            "max_tokens": 8000,
        }
        data = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(2):
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.cfg.api_key}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))
                content = raw["choices"][0]["message"]["content"]
                self.last_usage = raw.get("usage", {}) or {}
                return content or ""
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt == 0:
                    time.sleep(2)
        raise LLMError(f"视觉模型调用失败: {last_err}")


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
            try:
                conf = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
            except (TypeError, ValueError):
                conf = 0.5
            decisions.append(
                Decision(
                    candidate_id=cid,
                    action="wrap",
                    env=env,
                    body_span=body,
                    title_span=(body[0], body[0]),
                    optional_arg=str(item.get("optional_arg", "") or "")[:120],
                    keep_title_text=bool(item.get("keep_title_text", True)),
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
            if not (lo <= old_end <= hi and lo <= new_end <= hi and new_end >= lo):
                ambiguous.append({"candidate_id": cid, "line": c.span.start_line,
                                  "reason": "move_payload 行号越出上下文范围，保守保留"})
                continue
            decisions.append(
                Decision(
                    candidate_id=cid,
                    action="move-boundary",
                    env=env or c.env_hint,
                    source="ai",
                    reason=str(item.get("reason", ""))[:120],
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.5)))),
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
