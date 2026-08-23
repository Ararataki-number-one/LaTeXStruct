# -*- coding: utf-8 -*-
"""Visual repair suggestions stay bound to host inventory and reversible spans."""

from types import SimpleNamespace

from latexstruct.core.formal_inventory import inventory_document
from latexstruct.core.parser import parse_latex
from latexstruct.core.patch import Decision, PatchContext, build_ops
from latexstruct.core.pipeline import _build_context
from latexstruct.core.quality_loop import reconcile_visual_repairs
from latexstruct.core.scanner import scan


SOURCE = "\n".join([
    r"\documentclass{article}",
    r"\usepackage{amsthm}",
    r"\newtheorem*{theorem}{Theorem}",
    r"\begin{document}",
    "Theorem 2.1. Every red-blue colouring has the property.",
    r"\begin{remark}",
    "This is ordinary transition prose.",
    r"\end{remark}",
    r"\end{document}",
])


def _fixture():
    document = parse_latex(SOURCE)
    context = _build_context(document)
    scanned = scan(document, structured_envs=context.existing_envs)
    inventory = inventory_document(document, context.existing_envs)
    candidates = {item.id: item for item in scanned.candidates}
    anchor = next(item for item in inventory.anchors if not item.original_env)
    environment = next(item for item in inventory.environments)
    candidate = next(
        item for item in candidates.values()
        if item.kind == "theorem-like" and item.span.start_line == anchor.start_line
    )
    return inventory, candidates, anchor, environment, candidate


def _suggestion(item_id, problem, *, env="", confidence=0.99):
    return SimpleNamespace(
        inventory_id=item_id,
        problem=problem,
        env=env,
        confidence=confidence,
        evidence="源页与编译页的 formal 标签类型不一致",
    )


def test_anchor_repair_reuses_existing_span_and_cannot_invent_one():
    inventory, candidates, anchor, _environment, candidate = _fixture()
    existing = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env="lemma",
        body_span=(anchor.start_line, anchor.end_line),
        source="full-review",
    )
    plan = reconcile_visual_repairs(
        [existing],
        [_suggestion(anchor.id, "wrong-env", env="theorem")],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )

    assert plan.ok is True
    repaired = next(item for item in plan.decisions if item.candidate_id == candidate.id)
    assert repaired.body_span == existing.body_span
    assert repaired.env == "theorem"
    assert repaired.source == "visual-review"

    no_span = reconcile_visual_repairs(
        [],
        [_suggestion(anchor.id, "missing-env", env="theorem")],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )
    assert no_span.ok is False
    assert "不能为 anchor 猜测正文范围" in no_span.invalid[0]["reason"]


def test_anchor_overwrap_removes_only_the_reversible_wrap():
    inventory, candidates, anchor, _environment, candidate = _fixture()
    wrap = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env="theorem",
        body_span=(anchor.start_line, anchor.end_line),
    )
    unrelated = Decision(candidate_id="keep-me", action="none")

    plan = reconcile_visual_repairs(
        [wrap, unrelated],
        [_suggestion(anchor.id, "overwrapped")],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )

    assert plan.ok is True
    assert plan.preserved_candidate_ids == [candidate.id]
    assert plan.decisions == [unrelated]


def test_existing_environment_repair_carries_exact_source_hash():
    inventory, candidates, _anchor, environment, _candidate = _fixture()
    # This synthetic ordinary remark has no host wrong-env finding, so visual
    # evidence alone cannot select an arbitrary theorem type.
    blocked = reconcile_visual_repairs(
        [],
        [_suggestion(environment.id, "wrong-env", env="theorem")],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )

    assert blocked.ok is False

    from dataclasses import replace
    from latexstruct.core.formal_inventory import FormalFinding

    finding = FormalFinding(
        id="host-wrong-env",
        kind="wrong-env",
        start_line=environment.start_line,
        end_line=environment.end_line,
        original_env=environment.original_env,
        suggested_env="theorem",
        source_sha256=environment.source_sha256,
        reason="explicit title conflicts with source environment",
        environment_id=environment.id,
    )
    inventory = replace(inventory, findings=inventory.findings + (finding,))
    plan = reconcile_visual_repairs(
        [],
        [_suggestion(environment.id, "wrong-env", env="theorem")],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )
    assert plan.ok is True
    decision = plan.decisions[0]
    assert decision.action == "change-env"
    assert decision.payload["source_sha256"] == environment.source_sha256
    ops, error = build_ops(decision, SOURCE.split("\n"), PatchContext())
    assert error == ""
    assert len(ops) == 2

    tampered = SOURCE.replace("ordinary transition", "changed transition")
    _ops, error = build_ops(decision, tampered.split("\n"), PatchContext())
    assert "哈希" in error


def test_visual_target_hash_change_and_duplicate_suggestion_fail_closed():
    inventory, candidates, anchor, _environment, candidate = _fixture()
    wrap = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env="theorem",
        body_span=(anchor.start_line, anchor.end_line),
    )
    suggestion = _suggestion(anchor.id, "missing-env", env="theorem")
    changed = reconcile_visual_repairs(
        [wrap],
        [suggestion],
        source_text=SOURCE.replace("Every red-blue", "Every blue-red"),
        inventory=inventory,
        candidates_by_id=candidates,
    )
    assert changed.ok is False
    assert "哈希" in changed.invalid[0]["reason"]

    duplicate = reconcile_visual_repairs(
        [wrap],
        [suggestion, suggestion],
        source_text=SOURCE,
        inventory=inventory,
        candidates_by_id=candidates,
    )
    assert duplicate.ok is False
    assert "恰好有一个" in duplicate.invalid[0]["reason"]
