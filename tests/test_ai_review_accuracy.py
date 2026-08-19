# -*- coding: utf-8 -*-
"""AI 决策/复查闭环回归（纯 FakeClient，不访问网络）。"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.ai import AIConfig, RoleConfig, parse_decisions  # noqa: E402
from latexstruct.core.patch import Decision  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.review import _as_confidence, parse_findings  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402


class FakeClient:
    def __init__(self, responses):
        self.responses = responses if isinstance(responses, list) else [responses]
        self.calls = []
        self.index = 0

    @property
    def cfg(self):
        class Config:
            model = "offline-fake"
        return Config()

    def chat_json(self, system, user):
        self.calls.append((system, user))
        response = self.responses[min(self.index, len(self.responses) - 1)]
        self.index += 1
        return response, {"total_tokens": 1}


def test_non_finite_review_confidence_cannot_pass_a_threshold():
    assert _as_confidence(float("nan"), 0.0) == 0.0
    assert _as_confidence(float("inf"), 0.0) == 0.0
    assert _as_confidence(float("-inf"), 0.0) == 0.0


class ExplicitOkReviewClient(FakeClient):
    """读取请求列出的 ID，并逐项显式返回 ok（空数组不再代表通过）。"""

    def __init__(self):
        super().__init__([])

    def chat_json(self, system, user):
        self.calls.append((system, user))
        first = user.splitlines()[0]
        ids_text = first.split("：", 1)[1].split("。", 1)[0]
        ids = [item.strip() for item in ids_text.split(",") if item.strip()]
        return {
            "findings": [
                {
                    "candidate_id": cid,
                    "verdict": "ok",
                    "fix": {},
                    "reason": "before/after 一致且结构正确",
                }
                for cid in ids
            ]
        }, {"total_tokens": 1}


class ExplicitNoneDecisionClient(FakeClient):
    """Return one preserve decision for each ID in the current decision batch."""

    def __init__(self):
        super().__init__([])

    def chat_json(self, system, user):
        self.calls.append((system, user))
        ids = re.findall(r"^### 候选 (\S+)$", user, flags=re.MULTILINE)
        return {
            "decisions": [
                {
                    "candidate_id": cid,
                    "action": "none",
                    "reason": "本测试只检查确定性规则复查",
                }
                for cid in ids
            ]
        }, {"total_tokens": 1}


def _ai_candidates(text):
    doc = parse_latex(text)
    candidates = [
        candidate for candidate in scan(doc).candidates
        if candidate.kind in {"theorem-like", "proof", "scope-fix"}
    ]
    return doc, candidates


def _config(**kwargs):
    return AIConfig(
        decide=RoleConfig(api_key="fake"),
        review=RoleConfig(api_key="fake"),
        **kwargs,
    )


def test_decision_batch_requires_exactly_one_answer_per_candidate():
    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem. First statement.\n\nLemma. Second statement.\n"
        "\\end{document}\n"
    )
    doc, candidates = _ai_candidates(text)
    assert len(candidates) == 2
    windows = {candidate.id: (1, len(text.splitlines()) + 1) for candidate in candidates}
    first = candidates[0]
    response = {"decisions": [
        {
            "candidate_id": first.id,
            "action": "wrap",
            "env": first.env_hint,
            "body_span": {
                "start_line": first.span.start_line,
                "end_line": first.span.end_line,
            },
            "confidence": 0.99,
        },
        {"candidate_id": first.id, "action": "none", "reason": "duplicate"},
    ]}
    decisions, ambiguous, notes = parse_decisions(
        response, candidates, windows, doc,
    )
    assert decisions == [] and notes == []
    assert {item["candidate_id"] for item in ambiguous} == {
        candidates[0].id, candidates[1].id,
    }
    assert any("2 个决策" in item["reason"] for item in ambiguous)
    assert any("未返回" in item["reason"] for item in ambiguous)


def test_high_risk_proof_candidate_is_never_mixed_with_theorem_batch():
    class PreserveEveryCandidate(FakeClient):
        def __init__(self):
            super().__init__([])

        def chat_json(self, system, user):
            self.calls.append((system, user))
            ids = re.findall(r"^### 候选 (\S+)$", user, flags=re.MULTILINE)
            return {
                "decisions": [
                    {
                        "candidate_id": candidate_id,
                        "action": "none",
                        "reason": "本测试只验证批次隔离",
                        "confidence": 0.99,
                    }
                    for candidate_id in ids
                ]
            }, {"total_tokens": 1}

    text = (
        "\\documentclass{book}\n\\begin{document}\n"
        "Theorem. First statement.\n\n"
        "Proof. The proof is immediate. \\qed\n\n"
        "Lemma. Second statement.\n"
        "\\end{document}\n"
    )
    client = PreserveEveryCandidate()
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(
            review_enabled=False,
            batch_size=50,
        ),
        ai_client=client,
    )
    assert result.ok, result.report_md
    proof_calls = [user for _system, user in client.calls if "kind: proof" in user]
    assert len(proof_calls) == 1
    assert "待决策候选共 1 个" in proof_calls[0]
    assert "kind: theorem-like" not in proof_calls[0]


def test_multi_atom_theorems_are_isolated_in_decision_and_review_batches():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Definition. First part of the definition.\n\n"
        "The collection also satisfies this continuation.\n\n"
        "Lemma. First part of the lemma.\n\n"
        "It is worth mentioning that this is still part of the lemma.\n\n"
        "\\section{Next topic}\n\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    targets = [
        candidate for candidate in candidates
        if candidate.kind == "theorem-like"
    ]
    assert len(targets) == 2
    end_by_env = {
        "definition": text.split("\n").index(
            "The collection also satisfies this continuation."
        ) + 1,
        "lemma": text.split("\n").index(
            "It is worth mentioning that this is still part of the lemma."
        ) + 1,
    }
    decide = FakeClient([
        {"decisions": [{
            "candidate_id": candidate.id,
            "action": "wrap",
            "env": candidate.env_hint,
            "body_span": {
                "start_line": candidate.span.start_line,
                "end_line": end_by_env[candidate.env_hint],
            },
            "confidence": 0.99,
            "reason": "逐块确认到可靠停点前",
        }]}
        for candidate in targets
    ])
    review = ExplicitOkReviewClient()
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(
            review_enabled=True,
            review_max_rounds=1,
            batch_size=50,
            review_batch=50,
        ),
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    assert len(decide.calls) == 2
    assert all(
        user.count("### 候选 ") == 1 for _system, user in decide.calls
    )
    for candidate in targets:
        matching_review_calls = [
            user for _system, user in review.calls
            if candidate.id in user.splitlines()[0]
        ]
        assert len(matching_review_calls) == 1
        assert "待复查 candidate 共 1 个" in matching_review_calls[0]
        assert "逐块审计要求" in matching_review_calls[0]


def test_none_candidate_is_reviewed_with_real_source_and_can_reenter_safely():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Question. Is every finite field perfect?\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "none",
        "reason": "初次判断不确定",
    }]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "missed-extra",
        "fix": {
            "action": "wrap",
            "env": "question",
            "body_span": {
                "start_line": target.span.start_line,
                "end_line": target.span.end_line,
            },
            "confidence": 0.98,
            "evidence": "源标题明确为 Question",
        },
        "reason": "正式问题条目，初次漏包",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    assert "\\begin{question}" in result.result
    assert "\\newtheorem*{question}{Question}" in result.result
    assert not any(item.get("candidate_id") == target.id for item in result.ai_notes)
    assert not any(item.get("candidate_id") == target.id for item in result.ambiguous)
    assert review.calls
    prompt = review.calls[0][1]
    assert "真实源片段" in prompt
    assert "Question. Is every finite field perfect?" in prompt
    assert '"kind": "theorem-like"' in prompt


def _short_definition_case(review_end_line):
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Definition.\n"
        "A fibration has fibres which are discrete categories.\n\n"
        "The collection of discrete fibrations forms a full subcategory.\n\n"
        "\\begin{lemma}\nA separate result.\n\\end{lemma}\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = next(
        candidate for candidate in candidates
        if candidate.kind == "theorem-like" and candidate.env_hint == "definition"
    )
    initial_end = target.span.end_line
    final_end = text.split("\n").index(
        "The collection of discrete fibrations forms a full subcategory."
    ) + 1
    chosen_review_end = initial_end if review_end_line == "short" else final_end
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "definition",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": initial_end,
        },
        "confidence": 0.99,
        "reason": "首段看似完整",
    }]})
    if review_end_line == "ok":
        review_finding = {
            "candidate_id": target.id,
            "verdict": "ok",
            "reason": "逐块复核后确认应保持原文，不自动猜测定义边界",
        }
    else:
        review_finding = {
            "candidate_id": target.id,
            "verdict": "missed-extra",
            "fix": {
                "action": "wrap",
                "env": "definition",
                "body_span": {
                    "start_line": target.span.start_line,
                    "end_line": chosen_review_end,
                },
                "confidence": 0.99,
                "evidence": "逐块核对后确认承接段仍属于同一定义",
            },
            "reason": "初次范围漏掉承接段",
        }
    review = FakeClient({"findings": [review_finding]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    return text, target, result, review


def test_pending_review_can_replace_rejected_short_range_with_complete_range():
    _text, target, result, review = _short_definition_case("complete")
    assert result.ok, result.report_md
    begin = result.result.index("\\begin{definition}")
    continuation = result.result.index(
        "The collection of discrete fibrations forms a full subcategory."
    )
    end = result.result.index("\\end{definition}")
    assert begin < continuation < end
    recovered = next(
        decision for decision in result.decisions
        if decision.candidate_id == target.id
    )
    assert recovered.source == "review"
    assert len([
        decision for decision in result.decisions
        if decision.candidate_id == target.id
    ]) == 1
    assert review.calls
    assert "当前选择后、可靠停点前遗漏的非空原子块" in review.calls[0][1]
    assert "The collection of discrete fibrations" in review.calls[0][1]


def test_pending_review_short_range_is_still_fail_closed():
    text, target, result, _review = _short_definition_case("short")
    assert not result.ok
    assert result.result == text
    assert "\\begin{definition}" not in result.result
    assert "\\newtheorem*{definition}" not in result.result
    assert any(
        item.get("candidate_id") == target.id
        and "复查范围仍未通过源坐标安全门" in item.get("reason", "")
        for item in result.ambiguous
    )


def test_pending_short_wrap_review_ok_preserves_source_and_cache_is_safe():
    text, target, result, _review = _short_definition_case("ok")
    assert result.ok, result.report_md
    assert result.result == text
    assert result.verification["safe_to_export"] is True
    assert result.verification["structure_decisions"]["manual_required"] == 0
    assert target.id in result.review["preserved_candidate_ids"]
    assert not any(
        decision.candidate_id == target.id for decision in result.decisions
    )
    assert not any(
        item.get("candidate_id") == target.id for item in result.ambiguous
    )
    assert not any(
        patch.decision.candidate_id == target.id for patch in result.rejected
    )
    note = next(
        item for item in result.ai_notes
        if item.get("candidate_id") == target.id
    )
    assert note["source"] == "review"
    assert result.review["escalations"] == []

    class ExplodingClient:
        last_usage = {}

        def chat_json(self, *_args, **_kwargs):
            raise AssertionError("复用 preserve 缓存时不应再次调用 AI")

    reused = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=ExplodingClient(),
        review_client=ExplodingClient(),
        decisions_override=result.decisions,
        ambiguous_override=result.ambiguous,
        ai_notes_override=result.ai_notes,
    )
    assert reused.ok, reused.report_md
    assert reused.result == text
    assert reused.verification["decisions_reused"] is True
    assert reused.verification["structure_decisions"]["manual_required"] == 0


def test_review_confirmed_none_is_visible_as_preserved_decision():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Theorem 2 shows why the preceding estimate is useful.\n"
        "\\end{document}\n"
    )
    # The stricter scanner intentionally rejects this narrative reference, so
    # use an unnumbered title-shaped candidate that still needs semantic review.
    text = text.replace(
        "Theorem 2 shows why the preceding estimate is useful.",
        "Remark. This heading-like sentence is only a transition.",
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "none",
        "confidence": 0.96,
        "reason": "语境表明是过渡句",
    }]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "ok",
        "reason": "确认保持原文",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    assert result.verification["safe_to_export"] is True
    assert target.id in result.review["preserved_candidate_ids"]
    assert not any(
        entry.get("candidate_id") == target.id for entry in result.ambiguous
    )
    item = next(
        entry for entry in result.decision_items
        if entry["candidate_id"] == target.id
    )
    assert item["status"] == "preserved"
    assert item["source"] == "ai"
    assert item["confidence"] == 0.96


def test_pending_ok_cannot_hide_duplicate_initial_decision_protocol_error():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Remark. This candidate needs one unambiguous answer.\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [
        {
            "candidate_id": target.id,
            "action": "none",
            "reason": "first answer",
        },
        {
            "candidate_id": target.id,
            "action": "none",
            "reason": "duplicate answer",
        },
    ]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "ok",
        "reason": "later review says preserve",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    assert not result.ok
    assert result.result == text
    assert target.id not in result.review["preserved_candidate_ids"]
    assert not any(
        note.get("candidate_id") == target.id for note in result.ai_notes
    )
    assert any(
        item.get("candidate_id") == target.id
        and ("2 个决策" in item.get("reason", "") or "协议错误" in item.get("reason", ""))
        for item in result.ambiguous
    )


def test_empty_review_findings_are_reported_as_unreviewed_not_passed():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Theorem. Every finite subgroup here is cyclic.\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.98,
        "reason": "正式定理",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=FakeClient({"findings": []}),
    )
    assert not result.ok
    assert result.verification["ai_review"]["ok"] is False
    assert result.verification["ai_review"]["checked"] is True
    assert result.verification["ai_review"]["invalid"] >= 1
    assert result.verification["ai_review"]["escalations"] >= 1
    assert result.review["findings"] == []
    assert any("未返回" in item["reason"] for item in result.review["invalid"])
    assert any("未形成唯一有效结论" in item["reason"] for item in result.ambiguous)


def test_high_confidence_wrong_env_cannot_override_explicit_title_hint():
    text = (
        "\\documentclass{article}\n\\usepackage{amsthm}\n"
        "\\newtheorem*{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem. This is actually an auxiliary lemma.\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.95,
        "reason": "形式条目",
    }]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "wrong-env",
        "fix": {
            "env": "lemma",
            "confidence": 0.97,
            "evidence": "正文明确称其为 auxiliary lemma",
        },
        "reason": "应使用 lemma",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    assert not result.ok
    assert any(decision.env == "theorem" for decision in result.decisions)
    assert "\\begin{lemma}" not in result.result
    assert "\\newtheorem*{theorem}{Theorem}" in result.result
    assert any("源标题确定的环境" in item["reason"] for item in result.review["invalid"])


def test_low_confidence_wrong_env_stays_invalid_and_does_not_change_env():
    text = (
        "\\documentclass{article}\n\\begin{document}\n"
        "Theorem. A formal statement.\n\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.99,
    }]})
    review = FakeClient({"findings": [{
        "candidate_id": target.id,
        "verdict": "wrong-env",
        "fix": {
            "env": "theorem",
            "confidence": 0.51,
            "evidence": "弱猜测",
        },
        "reason": "可能是引理",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=1),
        ai_client=decide,
        review_client=review,
    )
    assert not result.ok
    assert any(decision.env == "theorem" for decision in result.decisions)
    assert "\\begin{lemma}" not in result.result
    assert any("低于 90%" in item["reason"] for item in result.review["invalid"])


def test_wrong_env_cannot_inherit_initial_confidence_or_reason_as_evidence():
    """复查遗漏字段时不得偷用初次决策的高置信度补齐。"""
    decision = Decision(
        candidate_id="c-1",
        action="wrap",
        env="remark",
        confidence=0.99,
    )
    findings, invalid = parse_findings(
        {"findings": [{
            "candidate_id": "c-1",
            "verdict": "wrong-env",
            "fix": {"env": "note"},
            "reason": "generic model explanation",
        }]},
        {"c-1"},
        20,
        targets={
            "c-1": {
                "decision": decision,
                "kind": "theorem-like",
            },
        },
    )
    assert findings == []
    assert any("自己的置信度" in item["reason"] for item in invalid)


def test_rule_generated_structure_is_also_presented_to_review():
    sample = os.path.join(os.path.dirname(__file__), "samples", "basic_book.tex")
    text = open(sample, encoding="utf-8").read()
    decide = ExplicitNoneDecisionClient()
    review = ExplicitOkReviewClient()
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(
            review_enabled=True,
            review_max_rounds=1,
            review_batch=50,
        ),
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    prompts = "\n".join(call[1] for call in review.calls)
    assert re.search(r"action=(merge-bilingual-title|convert-to-exercise-env)", prompts)
    assert "修改前源片段" in prompts and "结果片段" in prompts


def test_final_review_report_contains_only_last_round_findings():
    text = (
        "\\documentclass{article}\n\\usepackage{amsthm}\n"
        "\\newtheorem*{theorem}{Theorem}\n\\begin{document}\n"
        "Theorem. This statement is an auxiliary lemma.\n"
        "\\end{document}\n"
    )
    _doc, candidates = _ai_candidates(text)
    target = candidates[0]
    decide = FakeClient({"decisions": [{
        "candidate_id": target.id,
        "action": "wrap",
        "env": "theorem",
        "body_span": {
            "start_line": target.span.start_line,
            "end_line": target.span.end_line,
        },
        "confidence": 0.99,
    }]})
    review = FakeClient([
        {"findings": [{
            "candidate_id": target.id,
            "verdict": "wrong-env",
            "fix": {
                "env": "theorem",
                "confidence": 0.99,
                "evidence": "源正文明确写作 auxiliary lemma",
            },
            "reason": "第一轮重新确认环境",
        }]},
        {"findings": [{
            "candidate_id": target.id,
            "verdict": "ok",
            "fix": {},
            "reason": "第二轮确认最终结果",
        }]},
    ])
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True, review_max_rounds=2),
        ai_client=decide,
        review_client=review,
    )
    assert result.ok, result.report_md
    assert [item["verdict"] for item in result.review["findings"]] == ["ok"]
    assert result.review["findings"][0]["reason"] == "第二轮确认最终结果"
    assert len(result.review["history"]) == 2


def main():
    import traceback

    tests = [
        (name, value) for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    failed = 0
    for name, test in tests:
        try:
            test()
            print("PASS", name)
        except Exception:
            failed += 1
            print("FAIL", name)
            traceback.print_exc()
    print(f"{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
