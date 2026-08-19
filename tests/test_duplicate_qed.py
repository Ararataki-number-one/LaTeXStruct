# -*- coding: utf-8 -*-
"""Per-proof duplicate-QED regression tests."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latexstruct.core.compilecheck import compile_latex  # noqa: E402
from latexstruct.core.legalize import (  # noqa: E402
    proof_body_has_terminal_explicit_qed,
)
from latexstruct.core.parser import parse_latex  # noqa: E402
from latexstruct.core.patch import (  # noqa: E402
    LOCAL_QED_SUPPRESS_LINE,
    SUPPRESS_AUTO_QED_PAYLOAD_KEY,
    Decision,
    PatchContext,
    apply_patches,
    build_ops,
    content_invariant,
)
from latexstruct.core.pipeline import run_pipeline  # noqa: E402
from latexstruct.core.scanner import scan  # noqa: E402
from latexstruct.core.template import FAITHFULBOOK  # noqa: E402


def _decisions_for_all_candidates(source: str):
    decisions = []
    for candidate in scan(parse_latex(source)).candidates:
        if candidate.kind == "proof":
            # These deliberately hostile values prove that pipeline metadata is
            # re-derived from source rather than trusted from AI/cache payloads.
            claimed = not bool("square" in candidate.payload.get("text", ""))
            decisions.append(
                Decision(
                    candidate_id=candidate.id,
                    action="wrap",
                    env="proof",
                    body_span=(candidate.span.start_line, candidate.span.end_line),
                    source="ai",
                    payload={SUPPRESS_AUTO_QED_PAYLOAD_KEY: claimed},
                )
            )
        else:
            decisions.append(
                Decision(candidate_id=candidate.id, action="none", source="ai")
            )
    return decisions


PLAIN_SOURCE = r"""\documentclass{article}
\usepackage{amsthm}
\usepackage{amssymb}
\renewcommand{\qedsymbol}{\typeout{LATEXSTRUCT-AUTO-QED}\ensuremath{\blacksquare}}
\begin{document}
\textbf{Theorem 7.7}\quad A theorem.

\textbf{Proof}\quad Let \(f\) be a maximum flow. The result follows. \(\square\)

\textbf{Proof}\quad A second argument works. This completes the proof.
\end{document}
"""


def test_terminal_explicit_qed_is_distinct_from_boundary_prose_and_nonterminal_square():
    examples = [
        (r"Proof. Done. \(\square\)", True),
        (r"Proof. Done. \qed", True),
        (
            "Proof.\n\\begin{equation*}\nx=x. \\qedhere\n\\end{equation*}",
            True,
        ),
        ("Proof. This completes the proof.", False),
        (r"Proof. The modal conclusion is \(p \Box\)", False),
        ("Proof. A local claim is marked □\nThe proof then continues.", False),
    ]
    for source, expected in examples:
        doc = parse_latex(source)
        assert (
            proof_body_has_terminal_explicit_qed(
                doc, 1, len(source.splitlines())
            )
            is expected
        )


def test_plain_amsthm_suppresses_only_the_proof_with_source_square_and_compiles():
    result = run_pipeline(
        PLAIN_SOURCE,
        mode="ai",
        decisions_override=_decisions_for_all_candidates(PLAIN_SOURCE),
    )

    assert result.ok, result.report_md
    assert result.result.count(LOCAL_QED_SUPPRESS_LINE) == 1
    explicit = result.result.index(r"\(\square\)")
    guard = result.result.index(LOCAL_QED_SUPPRESS_LINE)
    first_end = result.result.index(r"\end{proof}", explicit)
    assert explicit < guard < first_end
    second_begin = result.result.index(r"\begin{proof}", first_end)
    second_end = result.result.index(r"\end{proof}", second_begin)
    assert LOCAL_QED_SUPPRESS_LINE not in result.result[second_begin:second_end]
    assert result.result.count(r"\(\square\)") == PLAIN_SOURCE.count(r"\(\square\)")
    assert result.verification["content_invariant"] is True
    assert result.verification["invariants"]["math"]["equal"] is True

    compiled = compile_latex(result.result)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]
        # The first proof retains only its source square; the unmarked second
        # proof still expands the ordinary amsthm QED exactly once.
        assert compiled["log"].count("LATEXSTRUCT-AUTO-QED") == 1


def test_faithfulbook_black_qed_style_uses_the_same_local_suppression_and_compiles():
    source = PLAIN_SOURCE.replace(
        r"\documentclass{article}", r"\documentclass{book}"
    ).replace(
        r"\begin{document}", "\\begin{document}\n\\chapter{Flows}"
    )
    result = run_pipeline(
        source,
        mode="ai",
        template=FAITHFULBOOK,
        decisions_override=_decisions_for_all_candidates(source),
    )

    assert result.ok, result.report_md
    assert "% LaTeXStruct template: faithfulbook v1" in result.result
    assert result.result.count(LOCAL_QED_SUPPRESS_LINE) == 1
    assert result.result.count(r"\(\square\)") == source.count(r"\(\square\)")
    assert result.verification["content_invariant"] is True
    assert result.verification["invariants"]["math"]["equal"] is True

    compiled = compile_latex(result.result)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]


def test_guard_is_a_noop_for_unknown_proof_without_qedsymbol_and_is_reversible():
    source = r"""\documentclass{article}
\usepackage{amssymb}
\newenvironment{proof}{\par\noindent Proof.\ }{\par}
\begin{document}
The custom proof ends here. \(\square\)
\end{document}
"""
    lines = source.split("\n")
    decision = Decision(
        candidate_id="custom-proof",
        action="wrap",
        env="proof",
        body_span=(5, 5),
        payload={SUPPRESS_AUTO_QED_PAYLOAD_KEY: True},
    )
    ops, error = build_ops(decision, lines, PatchContext())
    assert not error
    output, applied, rejected = apply_patches(lines, [(decision, ops)])
    assert not rejected
    assert content_invariant(lines, output, applied)
    rendered = "\n".join(output)
    assert LOCAL_QED_SUPPRESS_LINE in rendered

    compiled = compile_latex(rendered)
    if compiled["available"]:
        assert compiled["ok"], compiled["errors"]
