# -*- coding: utf-8 -*-
"""Independent, fail-closed structure-accuracy acceptance tests."""

import hashlib

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


REVIEWED_ORIGINAL = r"""\documentclass{article}
\begin{document}
\begin{center}
2. A reviewed multi-line
heading
\end{center}
Narrative outside the reviewed structures.

{\bfseries Theorem 4.2 (Synthetic source).} Alpha theorem body.

{\bfseries Remark.} Beta unnumbered formal body.

\textcolor{cyan}{\textit{Proof of \textcolor{black}{Theorem 4.2}.}} First proof token alpha.

{\itshape Proof.} Second proof token beta.

\begin{center}
\textbf{References}
\end{center}
Reference text remains ordinary body text.
\end{document}
"""


REVIEWED_PERFECT = r"""\documentclass{book}
\begin{document}
\tableofcontents
\chapter{A reviewed multi-line heading}
Narrative outside the reviewed structures.

\begin{theorem*}[4.2]
Alpha theorem body.
\end{theorem*}

\begin{remark*}
Beta unnumbered formal body.
\end{remark*}

\begin{proof}
First proof token alpha.
\end{proof}

\begin{proof}
Second proof token beta.
\end{proof}

\chapter*{References}
Reference text remains ordinary body text.
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


def _reviewed_manifest():
    return {
        "schema": TRUTH_SCHEMA,
        "headings": [
            {
                "level": 0,
                "title": "A reviewed multi-line heading",
                "start_line": _line_number(REVIEWED_ORIGINAL, "2. A reviewed"),
                "end_line": _line_number(REVIEWED_ORIGINAL, "heading"),
            },
            {
                "level": 0,
                "title": "References",
                "start_line": _line_number(REVIEWED_ORIGINAL, r"\textbf{References}"),
                "end_line": _line_number(REVIEWED_ORIGINAL, r"\textbf{References}"),
            },
        ],
        "items": [
            {
                "kind": "theorem",
                "id": "4.2",
                "start_line": _line_number(REVIEWED_ORIGINAL, r"{\bfseries Theorem"),
                "end_line": _line_number(REVIEWED_ORIGINAL, r"{\bfseries Theorem"),
            },
            {
                "kind": "remark",
                "id": "remark-after-4.2",
                "heading_label": "Remark",
                "start_line": _line_number(REVIEWED_ORIGINAL, r"{\bfseries Remark"),
                "end_line": _line_number(REVIEWED_ORIGINAL, r"{\bfseries Remark"),
            },
            {
                "kind": "proof",
                "id": "proof-theorem-4.2",
                "heading_label": "Proof of Theorem 4.2",
                "start_line": _line_number(REVIEWED_ORIGINAL, r"\textcolor{cyan}"),
                "end_line": _line_number(REVIEWED_ORIGINAL, r"\textcolor{cyan}"),
            },
            {
                "kind": "proof",
                "id": "proof-second",
                "heading_label": "Proof",
                "start_line": _line_number(REVIEWED_ORIGINAL, r"{\itshape Proof"),
                "end_line": _line_number(REVIEWED_ORIGINAL, r"{\itshape Proof"),
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


def test_faithfulbook_layout_controls_do_not_count_as_added_body_text():
    candidate = PERFECT.replace(
        "\\tableofcontents\n",
        "\\LSFirstPageEmpty\n\\tableofcontents\n\\LSMainMatter\n",
    ).replace(
        "\\chapter{Results}\n",
        "\\chapter{Results}\n\\LSChapterContents\n",
    )

    report = evaluate_tex_structure(ORIGINAL, candidate, manifest=_manifest())

    assert report["passed"] is True
    assert report["body_token_conservation"]["conserved"] is True
    assert report["body_token_conservation"]["excess_token_count"] == 0


def test_page_break_normalization_does_not_consume_next_line_bracket_text():
    original = ORIGINAL.replace(
        "Final words.",
        "\\clearpage\n[28] Reference entry.\nFinal words.",
    )
    candidate = PERFECT.replace(
        "Final words.",
        "[28] Reference entry.\nFinal words.",
    )
    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is True
    assert report["body_token_conservation"]["conserved"] is True


def _semantic_number_sources():
    original = ORIGINAL.replace(
        "w = 1.",
        r"\text{(1)}\qquad w = 1.",
    ).replace(
        "Final words.",
        "Final words.\n\\section*{References}\n"
        "[1] First reference payload.\n\n"
        "\\noindent [2]\\quad Second reference payload.",
    )
    candidate = PERFECT.replace(
        "\\[\nw = 1.\n\\]",
        "\\begin{equation}\nw = 1.\n\\tag{1}\n\\end{equation}",
    ).replace(
        "Final words.",
        "Final words.\n\\begin{thebibliography}{2}\n"
        "\\bibitem{ref1} First reference payload.\n\n"
        "\\bibitem{ref2} Second reference payload.\n"
        "\\end{thebibliography}",
    )
    return original, candidate


def test_semantic_ir_equation_tags_and_bibitems_are_scored_as_representations():
    original, candidate = _semantic_number_sources()

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is True
    assert report["exact_structure"]["f1"] == 1.0
    assert report["body_token_conservation"]["conserved"] is True
    assert report["document_structure"]["outline_coverage"] == 1.0


def test_changed_equation_tag_number_is_a_body_conservation_failure():
    original, candidate = _semantic_number_sources()
    candidate = candidate.replace(r"\tag{1}", r"\tag{2}")

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is False
    assert report["body_token_conservation"]["conserved"] is False
    assert report["blockers"]["body_token_change"] is True


def test_equation_number_moved_to_another_display_is_not_globally_cancelled():
    original, candidate = _semantic_number_sources()
    original = original.replace(
        "Closing narrative also remains outside.",
        "\\[\n\\text{(2)}\\qquad z = 2.\n\\]\n"
        "Closing narrative also remains outside.",
    )
    candidate = candidate.replace("\\tag{1}\n", "", 1).replace(
        "Closing narrative also remains outside.",
        "\\begin{equation}\nz = 2.\n\\tag{1}\n\\tag{2}\n"
        "\\end{equation}\nClosing narrative also remains outside.",
    )

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is False
    assert report["body_token_conservation"]["conserved"] is False
    assert report["blockers"]["body_token_change"] is True


def test_swapped_bibitem_numbers_are_not_deleted_by_normalization():
    original, candidate = _semantic_number_sources()
    candidate = candidate.replace("{ref1}", "{temporary}", 1)
    candidate = candidate.replace("{ref2}", "{ref1}", 1)
    candidate = candidate.replace("{temporary}", "{ref2}", 1)

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is False
    assert report["body_token_conservation"]["conserved"] is False
    # A swap preserves the multiset, so ordered common-number tokens—not mere
    # token counts—must be what closes this hole.
    assert report["body_token_conservation"]["missing_token_count"] == 0
    assert report["body_token_conservation"]["excess_token_count"] == 0
    assert report["body_token_conservation"]["first_difference_index"] is not None


@pytest.mark.parametrize("display", ["7", "Author2020", "01"])
def test_conflicting_optional_bibitem_label_fails_closed(display):
    original, candidate = _semantic_number_sources()
    candidate = candidate.replace(
        r"\bibitem{ref1}", rf"\bibitem[{display}]{{ref1}}",
    )

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is False
    assert report["body_token_conservation"]["conserved"] is False


def test_matching_numeric_optional_bibitem_label_is_the_same_representation():
    original, candidate = _semantic_number_sources()
    candidate = candidate.replace(
        r"\bibitem{ref1}", r"\bibitem[1]{ref1}",
    )

    report = evaluate_tex_structure(original, candidate, manifest=_manifest())

    assert report["passed"] is True
    assert report["body_token_conservation"]["conserved"] is True


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
    assert report["inputs"]["release_evidence_eligible"] is False
    assert report["exact_structure"]["expected"] == 2
    assert report["exact_structure"]["f1"] == 1.0


def test_reviewed_manifest_handles_old_style_unnumbered_and_nested_proof_titles():
    report = evaluate_tex_structure(
        REVIEWED_ORIGINAL,
        REVIEWED_PERFECT,
        manifest=_reviewed_manifest(),
    )

    assert report["passed"] is True
    assert report["inputs"]["truth_mode"] == "manifest"
    assert report["inputs"]["outline_truth_mode"] == "manifest"
    assert report["inputs"]["release_evidence_eligible"] is True
    assert report["exact_structure"]["true_positive"] == 4
    assert report["exact_structure"]["expected"] == 4
    assert report["document_structure"]["matched_outline_nodes"] == 2
    assert report["document_structure"]["expected_outline_nodes"] == 2
    assert report["body_token_conservation"]["conserved"] is True


def test_proofs_are_matched_individually_by_reviewed_body_tokens():
    duplicated_proof = REVIEWED_PERFECT.replace(
        "Second proof token beta.",
        "First proof token alpha.",
    )

    report = evaluate_tex_structure(
        REVIEWED_ORIGINAL,
        duplicated_proof,
        manifest=_reviewed_manifest(),
    )

    assert report["passed"] is False
    assert report["exact_structure"]["true_positive"] == 3
    assert "proof:proof-second" in report["exact_structure"]["missing"]
    assert any(
        duplicate["id"] == "proof-theorem-4.2"
        for duplicate in report["exact_structure"]["duplicates"]
    )


def test_old_style_and_nested_residual_headings_fail_closed():
    unwrapped = REVIEWED_PERFECT.replace(
        "\\begin{remark*}\nBeta unnumbered formal body.\n\\end{remark*}",
        "{\\bfseries Remark.} Beta unnumbered formal body.",
    ).replace(
        "\\begin{proof}\nFirst proof token alpha.\n\\end{proof}",
        "\\textcolor{cyan}{\\textit{Proof of "
        "\\textcolor{black}{Theorem 4.2}.}} First proof token alpha.",
        1,
    )

    report = evaluate_tex_structure(
        REVIEWED_ORIGINAL,
        unwrapped,
        manifest=_reviewed_manifest(),
    )

    residual_kinds = {item["kind"] for item in report["residual_formal_headings"]}
    assert {"remark", "proof"} <= residual_kinds
    assert report["blockers"]["residual_formal_heading"] is True
    assert report["passed"] is False


def test_reviewed_multiline_outline_rejects_truncated_candidate_and_bad_truth():
    truncated = REVIEWED_PERFECT.replace(
        "\\chapter{A reviewed multi-line heading}",
        "\\chapter{A reviewed multi-line}",
    )
    report = evaluate_tex_structure(
        REVIEWED_ORIGINAL,
        truncated,
        manifest=_reviewed_manifest(),
    )
    assert report["document_structure"]["matched_outline_nodes"] == 1
    assert report["document_structure"]["outline_coverage"] == 0.5
    assert report["blockers"]["outline_incomplete"] is True

    bad_manifest = _reviewed_manifest()
    bad_manifest["headings"][0]["end_line"] -= 1
    with pytest.raises(ValueError, match="title does not match source lines"):
        evaluate_tex_structure(
            REVIEWED_ORIGINAL,
            REVIEWED_PERFECT,
            manifest=bad_manifest,
        )


def test_binary_and_normalized_text_hashes_have_explicit_distinct_semantics():
    original_crlf = ORIGINAL.replace("\n", "\r\n")
    report = evaluate_tex_structure(original_crlf, PERFECT, manifest=_manifest())
    inputs = report["inputs"]

    binary_digest = hashlib.sha256(original_crlf.encode("utf-8")).hexdigest()
    normalized_digest = hashlib.sha256(ORIGINAL.encode("utf-8")).hexdigest()
    assert inputs["original"]["binary_sha256"] == binary_digest
    assert inputs["original"]["normalized_text_sha256"] == normalized_digest
    assert inputs["original_binary_sha256"] == binary_digest
    assert inputs["original_normalized_text_sha256"] == normalized_digest
    assert inputs["original_sha256"] == normalized_digest
    assert binary_digest != normalized_digest
