# -*- coding: utf-8 -*-
"""Independent full-document review uses only host inventory IDs."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from latexstruct.core.ai import AIConfig
from latexstruct.core.formal_inventory import inventory_document
from latexstruct.core.full_review import (
    reconcile_full_review_decisions,
    run_full_document_review,
)
from latexstruct.core.parser import parse_latex
from latexstruct.core.patch import Decision
from latexstruct.core.pipeline import _build_context
from latexstruct.core.scanner import scan


SOURCE = "\n".join([
    r"\documentclass{article}",
    r"\usepackage{amsthm}",
    r"\newtheorem*{theorem}{Theorem}",
    r"\begin{document}",
    "Theorem 2.1. Every red-blue colouring has the property.",
    r"\begin{remark}",
    "This is ordinary transition prose, not a mathematical remark.",
    r"\end{remark}",
    r"\end{document}",
])


class FakeFullReviewClient:
    def __init__(self, answers, *, unlisted=(), omit=()):
        self.answers = answers
        self.unlisted = list(unlisted)
        self.omit = set(omit)
        self.cfg = SimpleNamespace(model="fake-full-review")

    def chat_json(self, _system, user):
        chunk_id = re.search(r"^chunk_id: (\S+)$", user, re.M).group(1)
        start = int(re.search(r"^inspected_start_line: (\d+)$", user, re.M).group(1))
        end = int(re.search(r"^inspected_end_line: (\d+)$", user, re.M).group(1))
        item_ids = list(dict.fromkeys(re.findall(r'"item_id": "([^"]+)"', user)))
        findings = [
            {"item_id": item_id, **self.answers[item_id]}
            for item_id in item_ids
            if item_id in self.answers and item_id not in self.omit
        ]
        return {
            "chunk_id": chunk_id,
            "inspected_start_line": start,
            "inspected_end_line": end,
            "findings": findings,
            "unlisted_formal_lines": self.unlisted,
        }, {"prompt_tokens": 10, "completion_tokens": 5}


def _fixture():
    document = parse_latex(SOURCE)
    context = _build_context(document)
    scanned = scan(document, structured_envs=context.existing_envs)
    inventory = inventory_document(document, context.existing_envs)
    candidates = {item.id: item for item in scanned.candidates}
    anchor = next(item for item in inventory.anchors if not item.original_env)
    environment = next(item for item in inventory.environments if item.original_env == "remark")
    return document, inventory, candidates, anchor, environment


def test_full_review_can_wrap_a_miss_and_remove_an_existing_overwrap():
    document, inventory, candidates, anchor, environment = _fixture()
    client = FakeFullReviewClient({
        anchor.id: {
            "verdict": "formal",
            "env": "theorem",
            "body_span": {"start_line": 5, "end_line": 5},
            "confidence": 0.97,
            "evidence": "显式 Theorem 2.1 标题及完整陈述",
            "reason": "应套 theorem",
        },
        environment.id: {
            "verdict": "unwrap",
            "env": "",
            "body_span": {},
            "confidence": 0.99,
            "evidence": "环境内只是过渡叙述且没有 formal 陈述",
            "reason": "误套 remark",
        },
    })

    result = run_full_document_review(
        client,
        document,
        inventory,
        candidates,
        AIConfig(max_candidate_lines=120),
    )

    assert result.ok is True
    assert result.invalid == []
    assert result.escalations == []
    assert {item.action for item in result.decisions} == {"wrap", "unwrap"}
    wrap = next(item for item in result.decisions if item.action == "wrap")
    unwrap = next(item for item in result.decisions if item.action == "unwrap")
    assert wrap.body_span == (5, 5)
    assert wrap.env == "theorem"
    assert unwrap.payload == {
        "old_env": "remark",
        "begin_line": 6,
        "end_line": 8,
        "source_sha256": environment.source_sha256,
    }

    reconciled = reconcile_full_review_decisions([
        Decision(candidate_id=wrap.candidate_id, action="none"),
        Decision(candidate_id="unrelated", action="none"),
    ], result)
    assert sum(item.candidate_id == wrap.candidate_id for item in reconciled) == 1
    assert any(item.candidate_id == "unrelated" for item in reconciled)


def test_missing_one_inventory_answer_is_not_treated_as_pass():
    document, inventory, candidates, anchor, environment = _fixture()
    answers = {
        anchor.id: {
            "verdict": "formal", "env": "theorem",
            "body_span": {"start_line": 5, "end_line": 5},
            "confidence": 0.97, "evidence": "显式标题", "reason": "",
        },
        environment.id: {
            "verdict": "keep", "env": "", "body_span": {},
            "confidence": 0.9, "evidence": "", "reason": "",
        },
    }
    result = run_full_document_review(
        FakeFullReviewClient(answers, omit={environment.id}),
        document,
        inventory,
        candidates,
        AIConfig(max_candidate_lines=120),
    )
    assert result.ok is False
    assert result.checked is False
    assert any("必须恰好一个" in item["reason"] for item in result.invalid)


def test_unlisted_formal_line_is_an_explicit_blocker():
    document, inventory, candidates, anchor, environment = _fixture()
    client = FakeFullReviewClient({
        anchor.id: {
            "verdict": "formal", "env": "theorem",
            "body_span": {"start_line": 5, "end_line": 5},
            "confidence": 0.97, "evidence": "显式标题", "reason": "",
        },
        environment.id: {
            "verdict": "keep", "env": "", "body_span": {},
            "confidence": 0.9, "evidence": "环境正确", "reason": "",
        },
    }, unlisted=[9])
    result = run_full_document_review(
        client,
        document,
        inventory,
        candidates,
        AIConfig(max_candidate_lines=120),
    )
    assert result.ok is False
    assert result.checked is False
    assert result.escalations[0]["line"] == 9
    assert "清单外" in result.escalations[0]["reason"]


@pytest.mark.parametrize(
    ("verdict", "env"),
    [
        ("keep", ""),
        ("unwrap", ""),
        ("change-env", "theorem"),
    ],
)
def test_cross_chunk_environment_cannot_receive_decisive_verdict(verdict, env):
    source = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsthm}",
        r"\newtheorem*{remark}{Remark}",
        r"\begin{document}",
        r"\begin{remark}",
        *[f"Long formal environment line {index}." for index in range(600)],
        r"\end{remark}",
        r"\end{document}",
    ])
    document = parse_latex(source)
    context = _build_context(document)
    scanned = scan(document, structured_envs=context.existing_envs)
    inventory = inventory_document(document, context.existing_envs)
    candidates = {item.id: item for item in scanned.candidates}
    environment = next(
        item for item in inventory.environments if item.original_env == "remark"
    )
    client = FakeFullReviewClient({
        environment.id: {
            "verdict": verdict,
            "env": env,
            "body_span": {},
            "confidence": 0.99,
            "evidence": "只根据当前窗口错误地建议破坏性修改",
            "reason": "跨块环境不应自动修改",
        },
    })

    result = run_full_document_review(
        client,
        document,
        inventory,
        candidates,
        AIConfig(max_candidate_lines=120),
    )

    assert result.ok is False
    assert result.checked is False
    assert result.decisions == []
    assert any(
        verdict in item["reason"] and "跨出本批可见范围" in item["reason"]
        for item in result.invalid
    )


def test_fully_visible_existing_environment_keep_remains_compatible():
    document, inventory, candidates, anchor, environment = _fixture()
    client = FakeFullReviewClient({
        anchor.id: {
            "verdict": "formal", "env": "theorem",
            "body_span": {"start_line": 5, "end_line": 5},
            "confidence": 0.99, "evidence": "显式 Theorem 2.1 标题", "reason": "正式定理",
        },
        environment.id: {
            "verdict": "keep", "env": "", "body_span": {},
            "confidence": 0.99, "evidence": "已查看完整 remark 环境", "reason": "范围正确",
        },
    })

    result = run_full_document_review(
        client,
        document,
        inventory,
        candidates,
        AIConfig(max_candidate_lines=120),
    )

    assert result.ok is True
    assert result.checked is True
    kept = next(item for item in result.findings if item["item_id"] == environment.id)
    assert kept["verdict"] == "keep"
