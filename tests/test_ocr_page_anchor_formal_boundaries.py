# -*- coding: utf-8 -*-
"""Regression gates for formal entries immediately after host OCR page anchors.

These fixtures are bounded extracts from the immutable 37-page Ramsey run.  The
page marker and ``\\hypertarget`` are host-owned layout evidence; they must never
become part of the wrapped theorem/proof body.  The positive cases exercise the
four exact boundary failures seen in that run, while the negative cases ensure
that the narrow recovery path cannot become a general paragraph heuristic.
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

from latexstruct.core.parser import parse_latex
from latexstruct.core.pipeline import (
    DETERMINISTIC_SEMANTIC_ANCHOR_KEY,
    _apply_decisions,
    _build_context,
    _build_ocr_semantic_anchors,
)
from latexstruct.core.rules import build_rule_decisions
from latexstruct.core.scanner import scan


_PAGE_ANCHOR_THEOREM_RULE = "ocr-page-anchor-bare-title"
_PAGE_ANCHOR_PROOF_RULE = "ocr-page-anchor-proof-start"


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


def _document(body: list[str]) -> str:
    # Body line 1 is source line 4.  Keeping this prefix fixed makes every exact
    # boundary assertion below a literal regression check rather than a value
    # derived from scanner output.
    return "\n".join([
        r"\documentclass{article}",
        r"\begin{document}",
        _ocr_marker(),
        *body,
        r"\end{document}",
        "",
    ])


def _lemma_44_body() -> list[str]:
    return [
        "% Page 16",
        "% LaTeXStruct-Page: page_id=ocr-page-000016 source_page=16",
        r"\hypertarget{ocr-page-000016}{}",
        r"\textbf{Lemma 4.4.} \emph{Let \(G\) be a graph. If \(\beta > 0\) and \(R, s, k \in \mathbb{N}\) with \(s \leq k\) are such that}",
        r"\begin{equation*}",
        r"R \geq e^{-\beta s}n \qquad \text{and} \qquad e(G[U]) \geq \beta|U|^2",
        r"\tag{16}",
        r"\end{equation*}",
        r"\emph{for every set \(U \subset V(G)\) with \(|U| \geq R\), then \(G\) has at most}",
        r"\[",
        r"\binom{n}{s}\binom{R}{k-s}",
        r"\]",
        r"\emph{independent sets of size \(k\).}",
        "",
        "The proof of Lemma 4.4 is roughly as follows: choose a fingerprint and its container.",
        "",
        r"\textbf{Lemma 4.5.} \emph{A subsequent formal statement.}",
    ]


def _theorem_48_body() -> list[str]:
    return [
        "% Page 18",
        "% LaTeXStruct-Page: page_id=ocr-page-000018 source_page=18",
        r"\hypertarget{ocr-page-000018}{}",
        r"\textbf{Theorem 4.8} (Mubayi and Verstraete, 2024). \textit{If there exists an optimally pseudorandom} \(K_\ell\)\textit{-free graph with \(n\) vertices and density \(p = \Theta\bigl(n^{-1/(2\ell-3)}\bigr)\), then}",
        "",
        r"\[",
        r"R(\ell,k) \ge \frac{ck^{\ell-1}}{(\log k)^{2\ell-4}}",
        r"\]",
        "",
        r"\textit{for some constant \(c > 0\).}",
        "",
        "In fact, the same conclusion holds under the slightly weaker assumption that the graph is jumbled.",
        "",
        "The proof of Theorem 4.8 is surprisingly simple: take a suitable random subset.",
        "",
        r"\textbf{Lemma 4.9} (Alon and R\"odl, 2005). \textit{A subsequent formal statement.}",
    ]


def _definition_104_body() -> list[str]:
    return [
        "% Page 32",
        "% LaTeXStruct-Page: page_id=ocr-page-000032 source_page=32",
        r"\hypertarget{ocr-page-000032}{}",
        r"Definition 10.4 (\((p, R)\)-Janson hypergraphs). We say that a hypergraph \(\mathcal{H}\) is \((p, R)\)-Janson if there exists a probability measure \(\mu\) supported on the edges of \(\mathcal{H}\) such that",
        "",
        r"\[",
        r"\sum_{\substack{L\subset V(\mathcal{H})\\ |L|\ge 2}} p^{-|L|}\left(\sum_{L\subset E\in \mathcal{H}} \mu(E)\right)^2 < \frac{1}{R}.",
        r"\]",
        "",
        r"They apply this definition to the hypergraph \(\mathcal{H}\) with vertex set \(U\).",
        "",
        r"\textbf{Lemma 10.5.} \emph{A subsequent formal statement.}",
    ]


def _proof_61_body() -> list[str]:
    return [
        "% Page 22",
        "% LaTeXStruct-Page: page_id=ocr-page-000022 source_page=22",
        r"\hypertarget{ocr-page-000022}{}",
        r"\emph{Proof of Theorem 6.1.} By Lemma 6.2, it will suffice to bound the right-hand side of (24). When \(L \notin \mathcal{L}(k,\ell)\), we use the usual bound. On the other hand, if \(L \in \mathcal{L}(k,\ell)\), then",
        r"\[",
        r"\ell'(L)=c\log k'(L)+O(1).",
        r"\]",
        "",
        r"Therefore, if \(k\) is sufficiently large, then by Theorem 5.1 we have",
        r"\[",
        r"\binom{k'(L)+\ell'(L)-2}{\ell'(L)-1}^{-1} R(\ell'(L),k'(L)) \leq k^{-2c}.",
        r"\]",
        "",
        "Hence, by Lemmas 6.2 and 6.3, we deduce that",
        r"\[",
        r"R(\ell,k) \leq 2\cdot k^{-2c}\binom{k+\ell-2}{\ell-1},",
        r"\]",
        r"as required. \hfill \(\square\)",
        "",
        r"\section{Ramsey numbers closer to the diagonal}",
    ]


def _candidate(scanned, *, kind: str, number: str = ""):
    matches = [
        item
        for item in scanned.candidates
        if item.kind == kind
        and (not number or str(item.payload.get("number") or "") == number)
    ]
    assert len(matches) == 1, [
        (item.id, item.kind, item.rule_id, item.payload.get("number"))
        for item in matches
    ]
    return matches[0]


def _scan_case(body: list[str], *, kind: str, number: str = ""):
    text = _document(body)
    doc = parse_latex(text)
    scanned = scan(doc)
    return text, doc, scanned, _candidate(scanned, kind=kind, number=number)


def _assert_exact_rule_and_lock(
    body: list[str],
    *,
    kind: str,
    number: str,
    expected_rule: str,
    expected_span: tuple[int, int],
) -> None:
    _text, doc, scanned, candidate = _scan_case(
        body, kind=kind, number=number
    )
    assert candidate.rule_id == expected_rule
    decisions, ambiguous = build_rule_decisions(doc, scanned, kinds={kind})
    decision = next(
        item for item in decisions if item.candidate_id == candidate.id
    )
    assert decision.body_span == expected_span
    assert not any(
        item.get("candidate_id") == candidate.id for item in ambiguous
    )

    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    anchor = next(item for item in anchors if item.candidate_id == candidate.id)
    assert candidate.id in locked_ids
    assert anchor.body_span == expected_span
    assert anchor.payload[DETERMINISTIC_SEMANTIC_ANCHOR_KEY]["body_span"] == list(
        expected_span
    )


def _assert_specialized_but_unlocked(
    body: list[str], *, kind: str, number: str, expected_rule: str
) -> None:
    _text, doc, scanned, candidate = _scan_case(
        body, kind=kind, number=number
    )
    assert candidate.rule_id == expected_rule
    decisions, ambiguous = build_rule_decisions(doc, scanned, kinds={kind})
    assert all(item.candidate_id != candidate.id for item in decisions)
    assert any(item.get("candidate_id") == candidate.id for item in ambiguous)

    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert candidate.id not in locked_ids
    assert all(item.candidate_id != candidate.id for item in anchors)


def test_host_page_anchor_extends_real_lemma_44_exactly():
    _assert_exact_rule_and_lock(
        _lemma_44_body(),
        kind="theorem-like",
        number="4.4",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
        expected_span=(7, 16),
    )


def test_host_page_anchor_extends_real_theorem_48_exactly():
    _assert_exact_rule_and_lock(
        _theorem_48_body(),
        kind="theorem-like",
        number="4.8",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
        expected_span=(7, 13),
    )


def test_host_page_anchor_extends_real_definition_104_exactly():
    _assert_exact_rule_and_lock(
        _definition_104_body(),
        kind="theorem-like",
        number="10.4",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
        expected_span=(7, 11),
    )


def test_host_page_anchor_extends_real_page_initial_proof_exactly():
    _assert_exact_rule_and_lock(
        _proof_61_body(),
        kind="proof",
        number="",
        expected_rule=_PAGE_ANCHOR_PROOF_RULE,
        expected_span=(7, 21),
    )


@pytest.mark.parametrize(
    "bad_anchor",
    [
        r"\hypertarget{custom-page-000016}{}",
        r"\hypertarget{ocr-page-00016}{}",
        r"\hypertarget{ocr-page-000016}{nonempty}",
    ],
)
def test_custom_or_malformed_page_anchor_never_enters_specialized_lock(bad_anchor):
    body = _lemma_44_body()
    body[2] = bad_anchor
    _text, doc, scanned, candidate = _scan_case(
        body, kind="theorem-like", number="4.4"
    )
    assert candidate.rule_id != _PAGE_ANCHOR_THEOREM_RULE
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert candidate.id not in locked_ids
    assert all(item.candidate_id != candidate.id for item in anchors)


def test_narrative_before_host_page_anchor_disables_specialized_lock():
    body = _lemma_44_body()
    body.insert(2, "Narrative material in the same paragraph must not be ignored.")
    _text, doc, scanned, candidate = _scan_case(
        body, kind="theorem-like", number="4.4"
    )
    assert candidate.rule_id != _PAGE_ANCHOR_THEOREM_RULE
    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert candidate.id not in locked_ids
    assert all(item.candidate_id != candidate.id for item in anchors)


@pytest.mark.parametrize(
    "exit_text",
    [
        "The proof of Lemma 4.5 is roughly as follows: choose a fingerprint.",
        "The proof of Theorem 4.4 is roughly as follows: choose a fingerprint.",
    ],
)
def test_page_anchor_lemma_rejects_wrong_proof_type_or_number(exit_text):
    body = _lemma_44_body()
    body[14] = exit_text
    _assert_specialized_but_unlocked(
        body,
        kind="theorem-like",
        number="4.4",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
    )


def test_page_anchor_definition_rejects_generic_definition_discussion_exit():
    body = _definition_104_body()
    body[9] = "This definition is useful in the discussion of the next construction."
    _assert_specialized_but_unlocked(
        body,
        kind="theorem-like",
        number="10.4",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
    )


@pytest.mark.parametrize(
    "intermediate",
    [
        ["Moreover, the same conclusion holds under a weaker assumption."],
        [r"\textit{In fact, the same conclusion holds under a weaker assumption.}"],
        [r"\[", r"x=x.", r"\]"],
    ],
    ids=["moreover", "styled", "math"],
)
def test_page_anchor_theorem_rejects_noncanonical_intermediate_atom(intermediate):
    body = _theorem_48_body()
    body[11:12] = intermediate
    _assert_specialized_but_unlocked(
        body,
        kind="theorem-like",
        number="4.8",
        expected_rule=_PAGE_ANCHOR_THEOREM_RULE,
    )


@pytest.mark.parametrize(
    "tamper",
    ["candidate-source", "anchor-source", "finding-source", "finding-anchor-id"],
)
def test_page_anchor_lock_rejects_formal_inventory_binding_tamper(tamper):
    _text, doc, original, original_candidate = _scan_case(
        _lemma_44_body(), kind="theorem-like", number="4.4"
    )
    assert original_candidate.rule_id == _PAGE_ANCHOR_THEOREM_RULE
    scanned = copy.deepcopy(original)
    candidate = _candidate(scanned, kind="theorem-like", number="4.4")
    anchor_id = candidate.payload["formal_anchor_id"]
    finding_id = candidate.payload["formal_finding_id"]

    if tamper == "candidate-source":
        candidate.payload["source_sha256"] = "0" * 64
    elif tamper == "anchor-source":
        anchor = next(
            item for item in scanned.formal_inventory["anchors"]
            if item["id"] == anchor_id
        )
        anchor["source_sha256"] = "1" * 64
    elif tamper == "finding-source":
        finding = next(
            item for item in scanned.formal_inventory["findings"]
            if item["id"] == finding_id
        )
        finding["source_sha256"] = "2" * 64
    else:
        finding = next(
            item for item in scanned.formal_inventory["findings"]
            if item["id"] == finding_id
        )
        finding["anchor_id"] = "formal-anchor:tampered"

    anchors, locked_ids = _build_ocr_semantic_anchors(
        doc, scanned, _build_context(doc)
    )
    assert candidate.id not in locked_ids
    assert all(item.candidate_id != candidate.id for item in anchors)


def test_page_anchor_locked_decision_rejects_cached_source_hash_tamper():
    _text, doc, scanned, candidate = _scan_case(
        _lemma_44_body(), kind="theorem-like", number="4.4"
    )
    ctx = _build_context(doc)
    anchors, locked_ids = _build_ocr_semantic_anchors(doc, scanned, ctx)
    assert candidate.id in locked_ids
    anchor = next(item for item in anchors if item.candidate_id == candidate.id)
    tampered = copy.deepcopy(anchor)
    tampered.payload[DETERMINISTIC_SEMANTIC_ANCHOR_KEY]["source_sha256"] = "0" * 64

    ambiguous: list[dict] = []
    _out, applied, _rejected, _dropped = _apply_decisions(
        doc,
        [tampered],
        ctx,
        ambiguous,
        {item.id: item for item in scanned.candidates},
    )
    assert applied == []
    assert any("源内容或数学文本已变化" in item["reason"] for item in ambiguous)
