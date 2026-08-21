from latexstruct.core.parser import parse_latex
from latexstruct.core.rules import build_rule_decisions
from latexstruct.core.scanner import scan


def _wrap_decisions(source: str):
    document = parse_latex(source)
    result = scan(document)
    decisions, ambiguous = build_rule_decisions(
        document,
        result,
        kinds={"theorem-like", "proof"},
    )
    assert not ambiguous
    return result, [decision for decision in decisions if decision.action == "wrap"]


def _line(source: str, needle: str) -> int:
    return next(
        index
        for index, value in enumerate(source.splitlines(), start=1)
        if needle in value
    )


def test_explicit_qed_closes_long_proof_across_narrative_reset_and_page_break():
    source = r"""\documentclass{article}
\begin{document}
\textbf{Lemma 1.} The assertion holds.

\textbf{Proof.} Start with the first estimate.

A capitalized narrative reset is still part of this proof.

\clearpage
%=== PAGE BREAK === page 2
Set \(x=1\), and continue the calculation.

This completes the proof. \(\blacksquare\)

Afterwards we discuss a different construction.

\textbf{Lemma 2.} A separate assertion holds.
\end{document}
"""
    _result, decisions = _wrap_decisions(source)
    proof = next(decision for decision in decisions if decision.env == "proof")
    assert proof.body_span == (
        _line(source, r"\textbf{Proof."),
        _line(source, r"\blacksquare"),
    )
    assert proof.body_span[1] < _line(source, "Afterwards")


def test_terminal_qed_on_proof_heading_line_does_not_wrap_following_discussion():
    source = r"""\documentclass{article}
\begin{document}
\textbf{Lemma 4.} The assertion holds.

\textbf{Proof.} Immediate from the definition. \(\blacksquare\)

For comparison, the next paragraph treats a different question.

\textbf{Theorem 5.} Another assertion holds.
\end{document}
"""
    _result, decisions = _wrap_decisions(source)
    proof = next(decision for decision in decisions if decision.env == "proof")
    expected = _line(source, r"\textbf{Proof.")
    assert proof.body_span == (expected, expected)
    assert proof.body_span[1] < _line(source, "For comparison")


def test_no_qed_proof_accepts_mathematical_transition_verbs_but_not_new_topic():
    source = r"""\documentclass{article}
\begin{document}
\textbf{Theorem 7.} The assertion holds.

\textbf{Proof of Theorem 7.} Begin with an ordered family.

Indeed, there are at most \(n\) choices.

Dividing by \(n!\), we obtain
\[
1\leq 1.
\]

\noindent provided \(n\geq 1\).

8. A new topic

The discussion starts here.
\end{document}
"""
    _result, decisions = _wrap_decisions(source)
    proof = next(decision for decision in decisions if decision.env == "proof")
    assert proof.body_span == (
        _line(source, r"\textbf{Proof of Theorem 7."),
        _line(source, r"\noindent provided \(n\geq 1\)."),
    )
    assert proof.body_span[1] < _line(source, "8. A new topic")


def test_isolated_numbered_attribution_is_title_metadata_not_statement_body():
    source = r"""\documentclass{article}
\begin{document}
{\bfseries Conjecture 1.1 (Author, [15]).}

\[
x=1.
\]
\end{document}
"""
    result, decisions = _wrap_decisions(source)
    candidate = next(item for item in result.candidates if item.kind == "theorem-like")
    decision = next(item for item in decisions if item.env == "conjecture")
    assert candidate.payload["title_remainder"] == ""
    assert candidate.payload["title_line_new"] == ""
    assert candidate.payload["title_prefix"] == r"{\bfseries Conjecture 1.1 (Author, [15]).}"
    assert decision.optional_arg == r"1.1 {(Author, {\char91}15{\char93})}"


def test_parenthetical_followed_by_statement_text_remains_in_the_body():
    source = r"""\documentclass{article}
\begin{document}
\textbf{Conjecture 2.1.} (Named case) Every graph has the property.
\end{document}
"""
    result, decisions = _wrap_decisions(source)
    candidate = next(item for item in result.candidates if item.kind == "theorem-like")
    decision = next(item for item in decisions if item.env == "conjecture")
    assert candidate.payload["number"] == "2.1"
    assert candidate.payload["title_remainder"].startswith("(Named case) Every graph")
    assert decision.optional_arg == "2.1"
