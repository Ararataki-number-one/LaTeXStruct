# -*- coding: utf-8 -*-
"""OCR formal-environment accuracy gates (model-independent source evidence)."""

from __future__ import annotations

import base64
import copy
import json

from latexstruct.core.ai import AIConfig, RoleConfig
from latexstruct.core.parser import parse_latex
from latexstruct.core.pipeline import (
    DETERMINISTIC_SEMANTIC_ANCHOR_KEY,
    _apply_decisions,
    _build_context,
    _build_ocr_semantic_anchors,
    run_pipeline,
)
from latexstruct.core.rules import build_rule_decisions
from latexstruct.core.scanner import scan


def _ocr_marker() -> str:
    payload = {
        "version": 1,
        "kind": "article",
        "pages": [1],
        "source_has_toc": False,
        "outline": [],
    }
    token = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return "% LaTeXStruct-OCR-Metadata: " + token


class _ExplodingClient:
    last_usage = {}

    def chat_json(self, *_args, **_kwargs):
        raise AssertionError("locked OCR semantic anchors must not be sent to AI")


class _StaticClient:
    last_usage = {}

    def __init__(self, response):
        self.response = response
        self.calls = []

    def chat_json(self, system, user):
        self.calls.append((system, user))
        return self.response, {"total_tokens": 1, "model": "test"}


def _config(*, review_enabled=False):
    return AIConfig(
        decide=RoleConfig(api_key="test"),
        review=RoleConfig(api_key="test"),
        review_enabled=review_enabled,
        review_max_rounds=1,
    )


def _accuracy_corpus(entries=20):
    lines = [
        r"\documentclass{article}",
        r"\usepackage{amsmath,amsthm}",
        r"\newtheorem*{theorem}{Theorem}",
        r"\newtheorem*{lemma}{Lemma}",
        r"\newtheorem*{question}{Question}",
        r"\newtheorem*{problem}{Problem}",
        r"\begin{document}",
        _ocr_marker(),
        "",
    ]
    expected = []
    for index in range(1, entries + 1):
        env = "theorem" if index % 2 else "lemma"
        start = len(lines) + 1
        lines.extend([
            f"{env.title()} {index}.1. For every $x_{index}$ one has",
            r"\[",
            f"x_{index}=x_{index}.",
            r"\]",
        ])
        expected.append((env, start, len(lines)))
        lines.append("")
        proof_start = len(lines) + 1
        lines.extend([
            f"Proof. Fix $x_{index}$.",
            rf"Thus $x_{index}=x_{index}$. \hfill $\square$",
        ])
        expected.append(("proof", proof_start, len(lines)))
        lines.extend(["", "This paragraph is explanatory prose outside the proof.", ""])

    question_start = len(lines) + 1
    lines.append("Question 90.1. Is the formal bound sharp?")
    expected.append(("question", question_start, question_start))
    lines.extend(["", "It is useful to discuss several possible answers.", ""])
    problem_start = len(lines) + 1
    lines.extend([
        "Problem 90.2. Determine all values satisfying",
        r"\[",
        r"x^2=x.",
        r"\]",
    ])
    expected.append(("problem", problem_start, len(lines)))
    lines.extend(["", r"\end{document}", ""])
    return "\n".join(lines), expected


def test_ocr_formal_accuracy_gate_exceeds_95_percent_with_exact_boundaries():
    text, expected = _accuracy_corpus(entries=20)
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=False),
        ai_client=_ExplodingClient(),
    )
    assert result.ok, result.report_md
    actual = [
        (decision.env.removesuffix("*"), *decision.body_span)
        for decision in result.decisions
        if DETERMINISTIC_SEMANTIC_ANCHOR_KEY in decision.payload
    ]
    expected_set = set(expected)
    actual_set = set(actual)
    true_positive = len(expected_set & actual_set)
    precision = true_positive / len(actual_set)
    recall = true_positive / len(expected_set)
    exact_boundary_rate = true_positive / len(expected_set)
    assert precision >= 0.95
    assert recall >= 0.95
    assert exact_boundary_rate >= 0.95
    assert actual_set == expected_set
    assert result.verification["content_invariant"] is True
    assert result.verification["invariants"]["math"]["equal"] is True
    assert result.verification["structure_decisions"]["formal_residual_ids"] == []


def test_ocr_semantic_anchors_are_not_editable_review_targets():
    text = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsthm}",
        r"\newtheorem*{theorem}{Theorem}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 7. A complete formal statement.",
        r"\end{document}",
        "",
    ])
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=True),
        ai_client=_ExplodingClient(),
        review_client=_ExplodingClient(),
    )
    assert result.ok, result.report_md
    assert result.result.count(r"\begin{theorem}") == 1
    assert result.verification["ai_review"]["checked"] is False
    anchor = next(
        decision for decision in result.decisions
        if DETERMINISTIC_SEMANTIC_ANCHOR_KEY in decision.payload
    )
    assert anchor.body_span == (6, 6)
    assert anchor.env == "theorem"


def test_ocr_semantic_anchor_revalidates_range_kind_and_source_hash():
    text = "\n".join([
        r"\documentclass{article}",
        r"\usepackage{amsthm}",
        r"\newtheorem*{theorem}{Theorem}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 8. A complete formal statement.",
        "",
        "Outside discussion.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    ctx = _build_context(doc)
    anchors, locked_ids = _build_ocr_semantic_anchors(doc, scanned, ctx)
    assert len(anchors) == 1 and locked_ids == {anchors[0].candidate_id}
    candidate_map = {candidate.id: candidate for candidate in scanned.candidates}

    tampered_range = copy.deepcopy(anchors[0])
    tampered_range.body_span = (6, 7)
    ambiguous = []
    _out, applied, _rejected, _dropped = _apply_decisions(
        doc, [tampered_range], ctx, ambiguous, candidate_map
    )
    assert applied == []
    assert any("源范围被改写" in item["reason"] for item in ambiguous)

    tampered_env = copy.deepcopy(anchors[0])
    tampered_env.env = "lemma"
    ambiguous = []
    _out, applied, _rejected, _dropped = _apply_decisions(
        doc, [tampered_env], ctx, ambiguous, candidate_map
    )
    assert applied == []
    assert any("目标环境被改写" in item["reason"] for item in ambiguous)

    tampered_hash = copy.deepcopy(anchors[0])
    tampered_hash.payload[DETERMINISTIC_SEMANTIC_ANCHOR_KEY][
        "source_sha256"
    ] = "0" * 64
    ambiguous = []
    _out, applied, _rejected, _dropped = _apply_decisions(
        doc, [tampered_hash], ctx, ambiguous, candidate_map
    )
    assert applied == []
    assert any("源内容或数学文本已变化" in item["reason"] for item in ambiguous)


def test_unbounded_ocr_proof_remains_ai_owned_and_residual_blocks_export():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Proof. The argument continues on a missing page.",
        r"\end{document}",
        "",
    ])
    proof = next(
        candidate for candidate in scan(parse_latex(text)).candidates
        if candidate.kind == "proof"
    )
    client = _StaticClient({"decisions": [{
        "candidate_id": proof.id,
        "action": "none",
        "confidence": 0.99,
        "reason": "cannot prove the missing boundary",
    }]})
    result = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=False),
        ai_client=client,
    )
    assert client.calls
    assert result.ok is False
    assert result.result == text
    assert result.verification["structure_decisions"]["formal_residual_ids"] == [
        proof.id
    ]
    assert any("显式 formal 标题" in item["reason"] for item in result.ambiguous)


def test_lowercase_discussion_after_closed_statement_is_not_locked():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1. A formal claim.",
        "",
        "in the next section we discuss why the claim is useful.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_styled_historical_note_after_closed_statement_is_not_locked():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1. A formal claim.",
        "",
        r"\textit{Historical note. This theorem was first proved in 1950.}",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_display_does_not_authorise_styled_historical_note():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1. A formal claim satisfying",
        r"\[",
        r"x=x.",
        r"\]",
        "",
        r"\textit{Historical note. This theorem was first proved in 1950.}",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 9)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_title_only_statement_accepts_formal_every_body():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1.",
        "",
        "Every graph has a vertex set.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    anchor = next(item for item in anchors if item.candidate_id == first.id)
    assert first.id in locked_ids
    assert anchor.body_span == (4, 6)


def test_title_only_statement_rejects_lowercase_discussion_body():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1.",
        "",
        "in the next section we discuss a historical variation.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_title_only_statement_rejects_styled_historical_note():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1.",
        "",
        r"\textit{Historical note. This theorem was first proved in 1950.}",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_title_only_statement_rejects_for_historical_context():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1.",
        "",
        "For historical context, this theorem was first proved in 1950.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"theorem-like"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == first.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_title_only_let_and_if_require_and_accept_math_evidence():
    formal_bodies = (
        "Let $G$ be a graph with vertex set $V(G)$.",
        "If $x=y$, then $x-y=0$.",
    )
    for body in formal_bodies:
        text = "\n".join([
            r"\documentclass{article}",
            r"\begin{document}",
            _ocr_marker(),
            "Theorem 1.",
            "",
            body,
            "",
            "Theorem 2. Another formal claim.",
            r"\end{document}",
            "",
        ])
        doc = parse_latex(text)
        scanned = scan(doc)
        first = next(
            candidate for candidate in scanned.candidates
            if candidate.kind == "theorem-like"
            and candidate.payload.get("number") == "1"
        )
        anchors, locked_ids = _build_ocr_semantic_anchors(
            doc, scanned, _build_context(doc)
        )
        anchor = next(item for item in anchors if item.candidate_id == first.id)
        assert first.id in locked_ids
        assert anchor.body_span == (4, 6)


def test_title_only_conditional_without_math_evidence_is_not_locked():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Theorem 1.",
        "",
        "Let us recall the historical context.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    first = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "theorem-like"
        and candidate.payload.get("number") == "1"
    )
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert first.id not in locked_ids
    assert all(anchor.candidate_id != first.id for anchor in anchors)


def test_lowercase_discussion_after_unmarked_proof_is_not_locked():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Proof. A formal argument.",
        "",
        "in the next section we discuss a different argument.",
        "",
        "Theorem 2. Another formal claim.",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    proof = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "proof"
    )
    rule_decisions, _ambiguous = build_rule_decisions(
        doc, scanned, kinds={"proof"}
    )
    unsafe_rule = next(
        decision for decision in rule_decisions
        if decision.candidate_id == proof.id
    )
    assert unsafe_rule.body_span == (4, 6)
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert proof.id not in locked_ids
    assert all(anchor.candidate_id != proof.id for anchor in anchors)


def test_unmarked_proof_with_terminal_phrase_and_section_stop_is_locked():
    text = "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        "Proof of Theorem 6.1. The estimate gives",
        r"\[",
        r"R(\ell,k) \leqslant B(\ell,k),",
        r"\]",
        "as required.",
        "",
        r"\section{Next}",
        r"\end{document}",
        "",
    ])
    doc = parse_latex(text)
    scanned = scan(doc)
    proof = next(
        candidate for candidate in scanned.candidates
        if candidate.kind == "proof"
    )
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    anchor = next(item for item in anchors if item.candidate_id == proof.id)
    assert proof.id in locked_ids
    assert anchor.body_span == (4, 8)


def test_ocr_semantic_environment_pass_is_idempotent():
    text, _expected = _accuracy_corpus(entries=3)
    first = run_pipeline(
        text,
        mode="ai",
        ai_config=_config(review_enabled=False),
        ai_client=_ExplodingClient(),
    )
    second = run_pipeline(
        first.result,
        mode="ai",
        ai_config=_config(review_enabled=False),
        ai_client=_ExplodingClient(),
    )
    assert first.ok and second.ok
    assert second.result == first.result
    assert not any(
        DETERMINISTIC_SEMANTIC_ANCHOR_KEY in decision.payload
        for decision in second.decisions
    )
