# -*- coding: utf-8 -*-
"""标准 TeX 的范围准确性回归：正确结构零修改，歧义边界 fail closed。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.legalize import legalize_wrap  # noqa: E402
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.patch import Decision  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402


def _candidate(text, kind):
    doc = parse_latex(text)
    candidate = next(item for item in scan(doc).candidates if item.kind == kind)
    return doc, candidate


def _line(text, fragment):
    return next(
        number
        for number, line in enumerate(text.split("\n"), start=1)
        if fragment in line
    )


def test_complete_structured_theorem_and_proof_have_no_scope_fix():
    text = r"""\documentclass{article}
\usepackage{amsthm}
\newtheorem{theorem}{Theorem}
\begin{document}
\begin{theorem}
Every finite subgroup of a field is cyclic.
\end{theorem}
This theorem has several useful applications.

\begin{proof}
Choose an element of maximal order. \qed
\end{proof}
We next discuss a related construction.
\end{document}
"""
    result = scan(parse_latex(text))
    assert not [item for item in result.candidates if item.kind == "scope-fix"]
    assert not [item for item in result.candidates if item.kind in {"theorem-like", "proof"}]


def test_complete_single_line_theorem_is_not_only_title():
    text = r"""\documentclass{article}
\newtheorem{theorem}{Theorem}
\begin{document}
\begin{theorem}Every finite integral domain is a field.\end{theorem}
The converse needs an additional hypothesis.
\end{document}
"""
    scope = [item.rule_id for item in scan(parse_latex(text)).candidates if item.kind == "scope-fix"]
    assert "env-only-title" not in scope
    assert "env-body-outside" not in scope


def test_genuinely_title_only_environment_is_reported_without_moving_plain_text():
    text = r"""\documentclass{article}
\newtheorem{theorem}{Theorem}
\begin{document}
\begin{theorem}
Theorem 2.1.
\end{theorem}
An unrelated paragraph follows the empty entry.
\end{document}
"""
    scope = [item.rule_id for item in scan(parse_latex(text)).candidates if item.kind == "scope-fix"]
    assert "env-only-title" in scope
    assert "env-body-outside" not in scope


def test_proof_of_requires_a_mathematical_target_and_is_not_a_false_stop():
    text = r"""\documentclass{article}
\begin{document}
Theorem 1. This statement has two explanatory paragraphs.

Proof of concept is useful during software prototyping.

Proof of Theorem 1. The assertion follows immediately. \qed

Proof of 2.3. Apply the preceding lemma. \qed
\end{document}
"""
    doc = parse_latex(text)
    result = scan(doc)
    proofs = [item for item in result.candidates if item.kind == "proof"]
    assert len(proofs) == 2
    assert all("Proof of concept" not in item.title_text for item in proofs)

    theorem = next(item for item in result.candidates if item.kind == "theorem-like")
    concept_line = _line(text, "Proof of concept")
    decision = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        body_span=(theorem.span.start_line, concept_line),
    )
    legalize_wrap(doc, decision, theorem)
    assert decision.body_span[1] == concept_line


def test_starred_and_common_custom_theorem_environments_are_not_rewrapped():
    text = r"""\documentclass{article}
\usepackage{amsthm,tcolorbox,mdframed,thmtools}
\newtcbtheorem[number within=section]{boxedthm}{Boxed theorem}{}{box}
\declaretheorem[name={Main Axiom}]{axiom}
\newmdtheoremenv[linecolor=blue]{mdlemma}[Lemma]
\begin{document}
\begin{theorem*}
Theorem 1. This text is already structured.
\end{theorem*}
\begin{proof*}
Proof. This text is already structured. \qed
\end{proof*}
\begin{boxedthm}
Theorem 2. This boxed statement is already structured.
\end{boxedthm}
\begin{axiom}
Definition 3. This axiom is already structured.
\end{axiom}
\begin{mdlemma}
Lemma 4. This framed lemma is already structured.
\end{mdlemma}

Theorem 5. This genuinely bare statement remains detectable.
\end{document}
"""
    candidates = scan(parse_latex(text)).candidates
    theorem_like = [item for item in candidates if item.kind == "theorem-like"]
    proofs = [item for item in candidates if item.kind == "proof"]
    assert len(theorem_like) == 1
    assert theorem_like[0].title_text.startswith("Theorem 5")
    assert proofs == []


def test_theorem_legalizer_rejects_range_short_of_next_structure():
    text = r"""\documentclass{article}
\begin{document}
Theorem 1. Let $G$ be a finite group.

If $G$ is cyclic, every subgroup is cyclic.
This second line belongs to the same statement.

This paragraph discusses why the theorem matters.

Theorem 2. A separate statement.
\end{document}
"""
    doc, theorem = _candidate(text, "theorem-like")
    selected_line = _line(text, "If $G$ is cyclic")
    decision = Decision(
        candidate_id=theorem.id,
        action="wrap",
        env="theorem",
        source="ai",
        # 模型漏掉停点前仍非空的讨论段；不能把较短范围当成完整定理。
        body_span=(theorem.span.start_line, selected_line),
    )
    legalize_wrap(doc, decision, theorem)
    assert "漏段" in getattr(decision, "_legalize_error", "")


def test_proof_does_not_expand_past_model_end_into_discussion():
    text = r"""\documentclass{article}
\begin{document}
Proof. First reduce to the finite case.

Apply induction to finish the algebraic step.

After the proof, we discuss a sharper constant.

Theorem 2. A new result.
\end{document}
"""
    doc, proof = _candidate(text, "proof")
    requested_end = _line(text, "Apply induction")
    discussion = _line(text, "After the proof")
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, requested_end),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span[1] == requested_end
    assert decision.body_span[1] < discussion
    assert "保守跳过" in getattr(decision, "_legalize_error", "")


def test_proof_without_qed_is_accepted_only_at_reliable_structural_boundary():
    text = r"""\documentclass{article}
\begin{document}
Proof. First reduce to the finite case.

Apply induction to finish the algebraic step.

Theorem 2. A new result.
\end{document}
"""
    doc, proof = _candidate(text, "proof")
    requested_end = _line(text, "Apply induction")
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        body_span=(proof.span.start_line, requested_end),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span == (proof.span.start_line, requested_end)
    assert not hasattr(decision, "_legalize_error")


def test_explicit_qed_is_a_safe_boundary_before_following_discussion():
    text = r"""\documentclass{article}
\begin{document}
Proof. First reduce to the finite case.

Apply induction. \qed

After the proof, we discuss a sharper constant.

Theorem 2. A new result.
\end{document}
"""
    doc, proof = _candidate(text, "proof")
    decision = Decision(
        candidate_id=proof.id,
        action="wrap",
        env="proof",
        source="ai",
        # 决策漏选后半段时，硬 QED 仍能提供可证明的安全终点。
        body_span=(proof.span.start_line, proof.span.end_line),
    )
    legalize_wrap(doc, decision, proof)
    assert decision.body_span[1] == _line(text, r"Apply induction. \qed")
    assert decision.body_span[1] < _line(text, "After the proof")
    assert not hasattr(decision, "_legalize_error")


def main():
    import traceback

    tests = [
        (name, function)
        for name, function in sorted(globals().items())
        if name.startswith("test_") and callable(function)
    ]
    failed = 0
    for name, function in tests:
        try:
            function()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
