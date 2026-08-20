# -*- coding: utf-8 -*-
"""Independent, fail-closed structure-accuracy acceptance tests."""

import pytest

from tools.evaluate_tex_structure_accuracy import (
    TRUTH_SCHEMA,
    evaluate_tex_structure,
)


ORIGINAL = r"""\documentclass{article}
\begin{document}
\section{1. Results}
Introductory narrative remains outside every formal environment.

\textbf{Theorem 1.1.} \textit{Every widget works.}
\[
w = 1.
\]

\textit{Proof.} Apply the widget rule.
\hfill $\square$

Closing narrative also remains outside.
\section*{2. End}
Final words.
\end{document}
"""


PERFECT = r"""\documentclass{book}
\begin{document}
\tableofcontents
\chapter{Results}
Introductory narrative remains outside every formal environment.

\begin{theorem*}[1.1]
\textit{Every widget works.}
\[
w = 1.
\]
\end{theorem*}

\begin{proof}
Apply the widget rule.
\hfill $\square$
\ifcsname qedsymbol\endcsname\let\qedsymbol\empty\fi
\end{proof}

Closing narrative also remains outside.
\chapter*{End}
Final words.
\end{document}
"""


def _line_number(text, prefix):
    return next(
        index for index, line in enumerate(text.splitlines(), start=1)
        if line.startswith(prefix)
    )


def _manifest():
    theorem_start = _line_number(ORIGINAL, r"\textbf{Theorem")
    theorem_end = _line_number(ORIGINAL, r"\]")
    proof_start = _line_number(ORIGINAL, r"\textit{Proof")
    proof_end = _line_number(ORIGINAL, r"\hfill")
    return {
        "schema": TRUTH_SCHEMA,
        "items": [
            {
                "kind": "theorem",
                "id": "1.1",
                "start_line": theorem_start,
                "end_line": theorem_end,
            },
            {
                "kind": "proof",
                "id": "P1.1",
                "start_line": proof_start,
                "end_line": proof_end,
            },
        ],
    }


def test_perfect_structure_passes_every_independent_gate():
    report = evaluate_tex_structure(ORIGINAL, PERFECT, manifest=_manifest())

    assert report["passed"] is True
    score = report["exact_structure"]
    assert (score["true_positive"], score["predicted"], score["expected"]) == (2, 2, 2)
    assert score["precision"] == score["recall"] == score["f1"] == 1.0
    assert report["residual_formal_headings"] == []
    assert report["body_token_conservation"]["conserved"] is True
    assert report["document_structure"]["toc_present"] is True
    assert report["document_structure"]["outline_coverage"] == 1.0
    assert not any(report["blockers"].values())


def test_missing_environment_and_residual_heading_fail_closed():
    candidate = PERFECT.replace(
        "\\begin{theorem*}[1.1]\n\\textit{Every widget works.}\n"
        "\\[\nw = 1.\n\\]\n\\end{theorem*}",
        "\\textbf{Theorem 1.1.} \\textit{Every widget works.}\n"
        "\\[\nw = 1.\n\\]",
    )

    report = evaluate_tex_structure(ORIGINAL, candidate, manifest=_manifest())

    assert report["passed"] is False
    assert report["exact_structure"]["true_positive"] == 1
    assert report["exact_structure"]["missing"] == ["theorem:1.1"]
    assert report["blockers"]["missing"] is True
    assert report["blockers"]["residual_formal_heading"] is True


def test_duplicate_environment_is_a_false_positive_and_blocker():
    theorem = (
        "\\begin{theorem*}[1.1]\n\\textit{Every widget works.}\n"
        "\\[\nw = 1.\n\\]\n\\end{theorem*}"
    )
    candidate = PERFECT.replace(theorem, theorem + "\n" + theorem)

    report = evaluate_tex_structure(ORIGINAL, candidate, manifest=_manifest())

    score = report["exact_structure"]
    assert score["true_positive"] == 2
    assert score["predicted"] == 3
    assert score["precision"] == pytest.approx(2 / 3)
    assert score["duplicates"][0]["id"] == "1.1"
    assert report["blockers"]["duplicate"] is True
    assert report["passed"] is False


def test_overwrapped_environment_cannot_receive_partial_credit():
    candidate = PERFECT.replace(
        "\\begin{theorem*}[1.1]\n",
        "\\begin{theorem*}[1.1]\n"
        "Introductory narrative remains outside every formal environment.\n",
    ).replace(
        "\\chapter{Results}\nIntroductory narrative remains outside every formal environment.\n",
        "\\chapter{Results}\n",
    )

    report = evaluate_tex_structure(ORIGINAL, candidate, manifest=_manifest())

    assert report["body_token_conservation"]["conserved"] is True
    assert report["exact_structure"]["true_positive"] == 1
    errors = report["exact_structure"]["boundary_errors"]
    assert len(errors) == 1
    assert errors[0]["kind"] == "theorem"
    assert errors[0]["id"] == "1.1"
    assert errors[0]["error"] == "overwrapped"
    assert report["blockers"]["boundary_error"] is True
    assert report["passed"] is False


def test_body_token_deletion_fails_even_when_formal_score_is_perfect():
    candidate = PERFECT.replace("Final words.\n", "")

    report = evaluate_tex_structure(ORIGINAL, candidate, manifest=_manifest())

    assert report["exact_structure"]["f1"] == 1.0
    conservation = report["body_token_conservation"]
    assert conservation["conserved"] is False
    assert conservation["missing_token_count"] > 0
    assert _line_number(ORIGINAL, "Final words.") in conservation["missing_original_lines"]
    assert report["blockers"]["body_token_change"] is True
    assert report["passed"] is False


def test_toc_and_outline_are_release_gates_not_advisory_metrics():
    no_toc = PERFECT.replace("\\tableofcontents\n", "")
    report = evaluate_tex_structure(ORIGINAL, no_toc, manifest=_manifest())
    assert report["document_structure"]["toc_present"] is False
    assert report["blockers"]["toc_missing"] is True
    assert report["passed"] is False

    wrong_outline = PERFECT.replace("\\chapter*{End}", "\\chapter*{Appendix}")
    report = evaluate_tex_structure(ORIGINAL, wrong_outline, manifest=_manifest())
    assert report["document_structure"]["outline_coverage"] == 0.5
    assert report["blockers"]["outline_incomplete"] is True
    assert report["passed"] is False


@pytest.mark.parametrize("mutation", ["duplicate", "overlap", "bad-bound", "wrong-heading"])
def test_invalid_truth_manifest_is_rejected_instead_of_scored(mutation):
    manifest = _manifest()
    if mutation == "duplicate":
        manifest["items"].append(dict(manifest["items"][0]))
        error = "duplicate truth key"
    elif mutation == "overlap":
        manifest["items"][1]["start_line"] = manifest["items"][0]["end_line"]
        error = "overlapping truth bounds"
    elif mutation == "bad-bound":
        manifest["items"][0]["end_line"] = 10000
        error = "invalid line bounds"
    else:
        manifest["items"][0]["id"] = "9.9"
        error = "truth heading does not match"

    with pytest.raises(ValueError, match=error):
        evaluate_tex_structure(ORIGINAL, PERFECT, manifest=manifest)


def test_auto_discovery_is_available_but_identified_as_weaker_truth_mode():
    report = evaluate_tex_structure(ORIGINAL, PERFECT, manifest=None)

    assert report["inputs"]["truth_mode"] == "auto-discovery"
    assert report["exact_structure"]["expected"] == 2
    assert report["exact_structure"]["f1"] == 1.0
