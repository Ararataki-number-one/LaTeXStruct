# -*- coding: utf-8 -*-
"""span 合法化测试（实测驱动：AI 多包图注/叙述段/译文框时的确定性收缩）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.legalize import (  # noqa: E402
    has_proof_end_marker,
    legalize_decisions,
    legalize_wrap,
)
from latexstruct.core.ai import AIConfig, candidate_windows  # noqa: E402
from latexstruct.core.patch import Decision  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def read_sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return f.read()


def test_overlong_theorem_span_is_fail_closed():
    # 真实切片：AI 若把图注/翻译框/叙述段包进定理，不得静默伪装成完整结果。
    doc = parse_latex(read_sample("godsil_1_7.tex"))
    res = scan(doc)
    cands = [c for c in res.candidates if c.kind == "theorem-like"]
    assert cands
    c = cands[0]
    # 伪造 AI 过度扩张的 span（覆盖到标题段之后 40 行）
    d = Decision(candidate_id=c.id, action="wrap", env=c.env_hint, source="ai",
                 body_span=(c.span.start_line, c.span.end_line + 40))
    legalize_wrap(doc, d, c)
    assert "保守跳过" in getattr(d, "_legalize_error", "")


def test_multiparagraph_theorem_must_reach_structural_stop():
    text = (
        "Theorem.\n\nFirst part.\n\nSecond part.\n\n"
        "Lemma. A separate result.\n"
    )
    doc = parse_latex(text)
    theorem = next(
        c for c in scan(doc).candidates
        if c.kind == "theorem-like" and c.env_hint == "theorem"
    )
    lines = text.split("\n")
    first_line = lines.index("First part.") + 1
    second_line = lines.index("Second part.") + 1

    truncated = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, first_line),
    )
    legalize_wrap(doc, truncated, theorem)
    assert "漏段" in getattr(truncated, "_legalize_error", "")

    complete = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, second_line),
    )
    legalize_wrap(doc, complete, theorem)
    assert complete.body_span == (theorem.span.start_line, second_line)
    assert not hasattr(complete, "_legalize_error")


def _assert_revealed_theorem_boundary_triad(text, env, short_text, final_text, stop_text):
    doc = parse_latex(text)
    candidate = next(
        item for item in scan(doc).candidates
        if item.kind == "theorem-like" and item.env_hint == env
    )
    lines = text.split("\n")
    short_end = lines.index(short_text) + 1
    complete_end = lines.index(final_text) + 1
    stop_line = lines.index(stop_text) + 1

    short = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env=env,
        source="ai",
        body_span=(candidate.span.start_line, short_end),
    )
    legalize_wrap(doc, short, candidate)
    assert "漏段" in getattr(short, "_legalize_error", "")
    # The safety gate reports the problem but never fills in the omitted atom.
    assert short.body_span == (candidate.span.start_line, short_end)

    complete = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env=env,
        source="ai",
        body_span=(candidate.span.start_line, complete_end),
    )
    legalize_wrap(doc, complete, candidate)
    assert complete.body_span == (candidate.span.start_line, complete_end)
    assert not hasattr(complete, "_legalize_error")

    crossing = Decision(
        candidate_id=candidate.id,
        action="wrap",
        env=env,
        source="ai",
        body_span=(candidate.span.start_line, stop_line),
    )
    legalize_wrap(doc, crossing, candidate)
    assert "跨越" in getattr(crossing, "_legalize_error", "")
    assert crossing.body_span == (candidate.span.start_line, stop_line)


def test_revealed_definition_continuation_requires_second_atom():
    text = (
        "Definition.\n"
        "A fibration has fibres which are discrete categories.\n\n"
        "The collection of discrete fibrations forms a full subcategory, "
        "whose morphisms are the corresponding maps.\n\n"
        "\\begin{lemma}\nA separate result.\n\\end{lemma}\n"
    )
    _assert_revealed_theorem_boundary_triad(
        text,
        "definition",
        "A fibration has fibres which are discrete categories.",
        (
            "The collection of discrete fibrations forms a full subcategory, "
            "whose morphisms are the corresponding maps."
        ),
        "\\begin{lemma}",
    )


def test_revealed_example_continuation_requires_second_atom():
    text = (
        "Example.\n"
        "Every contraction in this family is Lipschitz.\n\n"
        "It is worth mentioning that, if a function is Lipschitz, the same "
        "estimate applies to its restriction.\n\n"
        "\\subsection{A separate topic}\n"
    )
    _assert_revealed_theorem_boundary_triad(
        text,
        "example",
        "Every contraction in this family is Lipschitz.",
        (
            "It is worth mentioning that, if a function is Lipschitz, the same "
            "estimate applies to its restriction."
        ),
        "\\subsection{A separate topic}",
    )


def test_title_only_theorem_cannot_leave_body_outside():
    text = "Theorem 1.\n\nActual statement.\n\nLemma 2. Next.\n"
    doc = parse_latex(text)
    theorem = next(
        c for c in scan(doc).candidates
        if c.kind == "theorem-like" and c.env_hint == "theorem"
    )
    decision = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, theorem.span.end_line),
    )
    legalize_wrap(doc, decision, theorem)
    assert "漏段" in getattr(decision, "_legalize_error", "")


def test_false_title_phrases_are_not_proof_stops():
    text = (
        "Proof. First step.\n\n"
        "Note that the second step is essential.\n\n"
        "Theorem 1.2 has an application here.\n\n"
        "Finally the identity follows. \\qed\n\n"
        "Lemma 3. A genuinely new result.\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    qed_line = text.split("\n").index("Finally the identity follows. \\qed") + 1
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, qed_line),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span == (proof.span.start_line, qed_line)
    assert not hasattr(decision, "_legalize_error")


def test_proof_end_markers_are_strict():
    assert not has_proof_end_marker(r"Apply $\square$ to $P$ and continue.")
    assert not has_proof_end_marker(r"Apply the operator $\square$")
    assert not has_proof_end_marker("This completes the proof of Claim 1.")
    assert not has_proof_end_marker("if our proof is complete.")
    assert not has_proof_end_marker("It remains to show that our proof is complete.")
    assert not has_proof_end_marker("The final step shows our proof is complete.")
    assert has_proof_end_marker("The identity follows, and our proof is complete.")
    assert has_proof_end_marker(r"The identity follows. \hfill $\square$")
    assert has_proof_end_marker(r"$\square$")
    assert has_proof_end_marker(r"\hfill $\blacksquare$")
    assert has_proof_end_marker("∎")


def test_qed_inside_box_closes_box_before_proof():
    text = (
        "Proof. First step.\n\n"
        "\\begin{tcolorbox}\nFinal step. \\qed\n\\end{tcolorbox}\n\n"
        "Theorem. A new result.\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    qed_line = text.split("\n").index("Final step. \\qed") + 1
    box_end = text.split("\n").index("\\end{tcolorbox}") + 1
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, qed_line),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span == (proof.span.start_line, box_end)
    assert not hasattr(decision, "_legalize_error")


def test_custom_starred_theorem_environment_is_a_stop():
    text = (
        "\\newtcbtheorem{mythm}{Theorem}{}{}\n\n"
        "Proof. First step.\n\nFinal step.\n\n"
        "\\begin{mythm*}{}{x}\nA new result.\n\\end{mythm*}\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    final_line = text.split("\n").index("Final step.") + 1
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, final_line),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span == (proof.span.start_line, final_line)
    assert not hasattr(decision, "_legalize_error")


def test_theorem_end_on_separator_blank_is_normalized():
    text = "Theorem. Complete statement.\n\nLemma. Next result.\n"
    doc = parse_latex(text)
    theorem = next(
        c for c in scan(doc).candidates
        if c.kind == "theorem-like" and c.env_hint == "theorem"
    )
    decision = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, theorem.span.end_line + 1),
    )
    legalize_wrap(doc, decision, theorem)
    assert decision.body_span == (theorem.span.start_line, theorem.span.end_line)
    assert not hasattr(decision, "_legalize_error")


def test_proof_span_stops_before_next_title():
    # proof 的 span 不得越过下一定理类标题
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Theorem 1. A.\n\n"
        "Proof. Fix it.\n\n"
        "More argument.\n\n"
        "Theorem 2. B.\n\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    res = scan(doc)
    proof = [c for c in res.candidates if c.kind == "proof"][0]
    d = Decision(candidate_id=proof.id, action="wrap", env="proof", source="ai",
                 body_span=(proof.span.start_line, 11))  # 越过 Theorem 2（第 10 行）
    legalize_wrap(doc, d, proof)
    # 终点必须落在下一停点（Theorem 2）之前，且吸附到"More argument."段尾
    expected_end = text.split("\n").index("More argument.") + 1
    assert d.body_span == (proof.span.start_line, expected_end)


def test_proof_span_snapped_to_block_end():
    # 终点落在段中间 → 吸附到段尾
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Theorem 1. A.\n\n"
        "Proof. First line.\n"
        "Second line of argument. \\qed\n\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    res = scan(doc)
    proof = [c for c in res.candidates if c.kind == "proof"][0]
    d = Decision(candidate_id=proof.id, action="wrap", env="proof", source="ai",
                 body_span=(proof.span.start_line, proof.span.start_line + 1))
    legalize_wrap(doc, d, proof)
    blk = next(b for b in doc.blocks if b.kind == "para" and "Second line" in b.text)
    assert d.body_span[1] == blk.span.end_line


def test_partial_proof_span_extends_to_first_explicit_qed():
    text = (
        "\\documentclass{book}\n\\begin{document}\n\n"
        "Proof. First step.\n\n"
        "Second step.\n\n"
        "Final step. \\hfill $\\square$\n\n"
        "After the proof, we discuss the bound.\n\n"
        "Theorem 2. A new result.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    d = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        # 模型只选了第一段；程序不能把它当成完整证明。
        body_span=(proof.span.start_line, proof.span.end_line),
    )
    legalize_wrap(doc, d, proof)
    lines = text.split("\n")
    qed_line = lines.index("Final step. \\hfill $\\square$") + 1
    narration_line = lines.index("After the proof, we discuss the bound.") + 1
    assert d.body_span[1] == qed_line
    assert d.body_span[1] < narration_line
    assert not hasattr(d, "_legalize_error")


def test_existing_theorem_environment_is_a_reliable_proof_stop():
    text = (
        "\\documentclass{book}\n\\newtheorem{lemma}{Lemma}\n\\begin{document}\n\n"
        "Proof. First step.\n\n"
        "The final argument.\n\n"
        "\\begin{lemma}\nA separate result.\n\\end{lemma}\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    final_line = text.split("\n").index("The final argument.") + 1
    d = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, final_line),
    )
    legalize_wrap(doc, d, proof)
    lemma_line = text.split("\n").index("\\begin{lemma}") + 1
    assert d.body_span == (proof.span.start_line, final_line)
    assert d.body_span[1] < lemma_line
    assert not hasattr(d, "_legalize_error")


def test_canonical_plain_language_proof_completion_is_a_hard_stop():
    text = (
        "Proof. First step.\n\n"
        "The last identity follows, and the proof is done.\n\n"
        "A separate discussion begins here."
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    d = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, proof.span.end_line),
    )
    legalize_wrap(doc, d, proof)
    end_line = text.split("\n").index(
        "The last identity follows, and the proof is done."
    ) + 1
    assert d.body_span == (proof.span.start_line, end_line)
    assert not hasattr(d, "_legalize_error")


def test_proof_fragment_without_reliable_end_is_fail_closed():
    text = "Proof. First step.\n\nThe argument continues on a missing page."
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    d = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, proof.span.end_line),
    )
    legalize_wrap(doc, d, proof)
    assert "避免生成被截断的 proof" in getattr(d, "_legalize_error", "")


def test_end_document_alone_does_not_prove_proof_boundary():
    text = (
        "\\begin{document}\nProof. First step.\n\nSecond step.\n"
        "\\end{document}\n"
    )
    doc = parse_latex(text)
    proof = next(c for c in scan(doc).candidates if c.kind == "proof")
    second_line = text.split("\n").index("Second step.") + 1
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, second_line),
    )
    legalize_wrap(doc, decision, proof)
    assert "结束标记" in getattr(decision, "_legalize_error", "")


def test_rule_source_is_untouched_but_review_source_is_revalidated():
    doc = parse_latex(read_sample("godsil_1_7.tex"))
    res = scan(doc)
    c = [c for c in res.candidates if c.kind == "theorem-like"][0]
    span = (1, 5)
    d_rule = Decision(candidate_id=c.id, action="wrap", env="theorem", source="rule", body_span=span)
    d_review = Decision(candidate_id=c.id, action="wrap", env="theorem", source="review", body_span=span)
    legalize_decisions(doc, [d_rule, d_review], {c.id: c})
    assert d_rule.body_span == span
    # A review response does not get the old silent "snap to title only"
    # behaviour.  Its stale pre-candidate coordinates remain unapplied and are
    # surfaced to pending review instead of being rewritten into a short wrap.
    assert d_review.body_span == span
    assert "保守跳过" in getattr(d_review, "_legalize_error", "")


def test_external_custom_starred_env_is_shared_window_and_legalize_stop():
    text = (
        "Theorem. First statement.\n\n"
        "Second statement.\n\n"
        "\\begin{myresult*}\n"
        "Theorem. Already structured.\n"
        "\\end{myresult*}\n"
    )
    doc = parse_latex(text)
    structured_envs = {"myresult"}
    result = scan(doc, structured_envs=structured_envs)
    theorem_candidates = [
        candidate for candidate in result.candidates
        if candidate.kind == "theorem-like"
    ]
    assert len(theorem_candidates) == 1
    theorem = theorem_candidates[0]
    stop_line = text.split("\n").index("\\begin{myresult*}") + 1
    second_line = text.split("\n").index("Second statement.") + 1

    windows, incomplete = candidate_windows(
        doc,
        [theorem],
        AIConfig(context_lines=1, max_candidate_lines=30),
        structured_envs,
    )
    assert windows[theorem.id][1] == stop_line
    assert theorem.id not in incomplete

    decision = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, second_line),
    )
    legalize_wrap(doc, decision, theorem, structured_envs)
    assert decision.body_span == (theorem.span.start_line, second_line)
    assert not hasattr(decision, "_legalize_error")

    no_evidence = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, second_line),
    )
    legalize_wrap(doc, no_evidence, theorem)
    assert "保守跳过" in getattr(no_evidence, "_legalize_error", "")


def main():
    import traceback

    tests = [
        (k, v)
        for k, v in sorted(globals().items())
        if k.startswith("test_") and callable(v)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
