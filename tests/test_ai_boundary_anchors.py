# -*- coding: utf-8 -*-
"""Host-owned AI decision boundary anchors."""

from __future__ import annotations

from latexstruct.core.ai import parse_decisions
from latexstruct.core.parser import parse_latex
from latexstruct.core.prompts import (
    build_decide_user,
    candidate_boundary_anchors,
)
from latexstruct.core.scanner import scan


SOURCE = """\\documentclass{book}
\\begin{document}
Theorem 1. The first statement begins here.

The second paragraph is still part of the statement.

Lemma 2. This is the reliable successor.
\\end{document}
"""


def _theorems(text: str = SOURCE):
    doc = parse_latex(text)
    candidates = [
        candidate
        for candidate in scan(doc).candidates
        if candidate.kind == "theorem-like"
    ]
    assert len(candidates) == 2
    return doc, candidates


def _wrap(candidate, anchor_id=None, *, body_span=None):
    item = {
        "candidate_id": candidate.id,
        "action": "wrap",
        "env": candidate.env_hint,
        "body_span": body_span or {
            "start_line": candidate.span.start_line,
            "end_line": candidate.span.end_line,
        },
        "confidence": 0.99,
        "reason": "host boundary",
    }
    if anchor_id is not None:
        item["end_anchor_id"] = anchor_id
    return {"decisions": [item]}


def test_correct_host_anchor_recovers_span_when_model_line_numbers_drift():
    doc, (candidate, _successor) = _theorems()
    window = (1, doc.text.count("\n") + 1)
    anchors = candidate_boundary_anchors(doc, candidate, window)
    target = next(anchor for anchor in anchors if anchor.end_line == 5)

    decisions, ambiguous, _notes = parse_decisions(
        _wrap(
            candidate,
            target.anchor_id,
            body_span={"start_line": 999, "end_line": 1000},
        ),
        [candidate],
        {candidate.id: window},
        doc,
    )

    assert ambiguous == []
    assert decisions[0].body_span == (candidate.span.start_line, 5)
    assert decisions[0].payload["end_anchor_id"] == target.anchor_id
    assert decisions[0].payload["end_anchor_line"] == 5
    assert len(decisions[0].payload["end_anchor_span_sha256"]) == 64


def test_forged_stale_and_cross_candidate_anchors_are_rejected():
    doc, (candidate, successor) = _theorems()
    window = (1, doc.text.count("\n") + 1)
    current_anchor = candidate_boundary_anchors(doc, candidate, window)[0]
    cross_anchor = candidate_boundary_anchors(doc, successor, window)[0]

    changed_doc, (changed_candidate, _changed_successor) = _theorems(
        SOURCE.replace("second paragraph", "mutated paragraph")
    )
    changed_window = (1, changed_doc.text.count("\n") + 1)
    assert changed_candidate.id == candidate.id

    cases = [
        (doc, candidate, window, "ba1_" + "0" * 32),
        (doc, candidate, window, cross_anchor.anchor_id),
        (changed_doc, changed_candidate, changed_window, current_anchor.anchor_id),
    ]
    for active_doc, active_candidate, active_window, anchor_id in cases:
        decisions, ambiguous, _notes = parse_decisions(
            _wrap(active_candidate, anchor_id),
            [active_candidate],
            {active_candidate.id: active_window},
            active_doc,
        )
        assert decisions == []
        assert any("伪造、过期或跨候选" in item["reason"] for item in ambiguous)


def test_legacy_response_without_anchor_keeps_strict_body_span_validation():
    doc, (candidate, _successor) = _theorems()
    window = (1, doc.text.count("\n") + 1)

    decisions, ambiguous, _notes = parse_decisions(
        _wrap(
            candidate,
            body_span={"start_line": candidate.span.start_line, "end_line": 5},
        ),
        [candidate],
        {candidate.id: window},
        doc,
    )
    invalid, invalid_ambiguous, _notes = parse_decisions(
        _wrap(
            candidate,
            body_span={"start_line": 999, "end_line": 1000},
        ),
        [candidate],
        {candidate.id: window},
        doc,
    )

    assert ambiguous == []
    assert decisions[0].body_span == (candidate.span.start_line, 5)
    assert decisions[0].payload["end_anchor_id"] == ""
    assert invalid == []
    assert any("body_span" in item["reason"] for item in invalid_ambiguous)


def test_decision_prompt_lists_every_host_atomic_endpoint_anchor():
    doc, (candidate, _successor) = _theorems()
    window = (1, doc.text.count("\n") + 1)
    anchors = candidate_boundary_anchors(doc, candidate, window)

    prompt = build_decide_user(
        doc,
        [candidate],
        windows={candidate.id: window},
    )

    assert [anchor.end_line for anchor in anchors] == [3, 5]
    assert "宿主边界 anchors（完整原子块候选" in prompt
    assert all(anchor.anchor_id in prompt for anchor in anchors)
    assert "原子块第 5..5 行" in prompt
