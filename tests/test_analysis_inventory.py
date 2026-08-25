from __future__ import annotations

import hashlib
from textwrap import dedent

import pytest

from latexstruct.core.analysis_inventory import (
    ANALYSIS_INVENTORY_CATEGORIES,
    AnalysisInventoryAuthorization,
    AnalysisInventoryError,
    AnalysisInventoryGateError,
    AnalysisNativeSourceBlock,
    InventoryAuthorizationAction,
    InventoryResidualKind,
    InventoryStatus,
    build_analysis_inventory_bundle,
    build_host_inventory_authorizations,
    evaluate_analysis_inventory_gate,
    require_analysis_inventory_gate,
)


PAGE_MAP = {1: (1,), 2: (2, 3)}


def _authorization(
    category: str,
    action: InventoryAuthorizationAction,
) -> AnalysisInventoryAuthorization:
    return AnalysisInventoryAuthorization(
        authorization_id=f"host-policy:{category}:{action.value.casefold()}",
        category=category,
        action=action,
        evidence_id="verification:host-required-structure-v2",
    )


def _document(body: str, *, preamble: str = "") -> str:
    return dedent(
        rf"""
        \documentclass{{book}}
        {preamble}
        \begin{{document}}
        % LaTeXStruct-Page: page_id=ocr-page-000001 source_page=1
        \hypertarget{{ocr-page-000001}}{{}}
        {body}
        % LaTeXStruct-Page: page_id=ocr-page-000002 source_page=2
        \hypertarget{{ocr-page-000002}}{{}}
        \end{{document}}
        """
    ).strip()


def _all_categories_document() -> str:
    return _document(
        r"""
        \frontmatter
        \maketitle
        \tableofcontents
        \mainmatter
        \chapter{1. Introduction}\label{chap:intro}
        \begin{theorem}[Theorem 1.1]\label{thm:one}
        Statement one.
        \end{theorem}
        \begin{proof}
        Proof text. \qed
        \end{proof}
        \begin{equation}\label{eq:one} x=1 \tag{1}\end{equation}
        See \ref{thm:one} and \cite{smith}.
        Text\footnote{Footnote text.}
        \begin{figure}
        \includegraphics[width=.5\textwidth]{plot.pdf}
        \caption{Figure 1. Plot}\label{fig:plot}
        \end{figure}
        \begin{table}
        \caption{Table 1. Values}\label{tab:values}
        \begin{tabular}{c}x\end{tabular}
        \end{table}
        \begin{thebibliography}{9}
        \bibitem{smith} A. Smith, A reference.
        \end{thebibliography}
        """,
        preamble=r"""
        \title{Ramsey Notes}
        \author{A. Author}
        \addbibresource{refs.bib}
        """,
    )


def _kinds(category) -> set[InventoryResidualKind]:
    return {item.kind for item in category.residual}


def test_identical_full_document_has_all_categories_and_passes_gate() -> None:
    tex = _all_categories_document()

    first = build_analysis_inventory_bundle(tex, tex, PAGE_MAP)
    second = build_analysis_inventory_bundle(tex, tex, PAGE_MAP)

    assert tuple(item.category for item in first.categories) == ANALYSIS_INVENTORY_CATEGORIES
    assert all(item.scanner_executed for item in first.categories)
    assert all(item.status is InventoryStatus.PASS for item in first.categories)
    assert all(item.baseline_total > 0 for item in first.categories)
    assert all(item.baseline_total == item.current_total for item in first.categories)
    assert first.baseline_page_sequence == (1, 2)
    assert first.current_page_sequence == (1, 2)
    assert first.mapping_status is InventoryStatus.PASS
    assert first.digest == second.digest
    assert first.as_dict() == second.as_dict()

    gate = evaluate_analysis_inventory_gate(first)
    assert gate.passed is True
    assert gate.status is InventoryStatus.PASS
    assert gate.residual_total == 0
    assert require_analysis_inventory_gate(first) == gate


def test_empty_categories_are_not_applicable_not_false_passes() -> None:
    tex = _document("Plain prose only.")
    bundle = build_analysis_inventory_bundle(tex, tex, PAGE_MAP)

    assert all(
        category.status is InventoryStatus.NOT_APPLICABLE
        for category in bundle.categories
    )
    assert all(category.scanner_executed for category in bundle.categories)
    assert bundle.gate().status is InventoryStatus.PASS


def test_missing_added_and_duplicate_items_are_residuals() -> None:
    baseline = _document(r"A\footnote{Keep me.} See \cite{one}.")
    candidate = _document(r"See \cite{one} and \cite{one} and \cite{two}.")

    bundle = build_analysis_inventory_bundle(baseline, candidate, PAGE_MAP)

    assert InventoryResidualKind.MISSING in _kinds(bundle.category("footnote"))
    assert InventoryResidualKind.DUPLICATE in _kinds(bundle.category("citation"))
    assert InventoryResidualKind.ADDED in _kinds(bundle.category("citation"))
    assert bundle.gate().status is InventoryStatus.RESIDUAL
    with pytest.raises(AnalysisInventoryGateError):
        require_analysis_inventory_gate(bundle)


def test_renumber_and_relabel_preserve_semantic_identity_but_block() -> None:
    baseline = _document(
        r"\begin{equation}\label{eq:a}x=1\tag{1}\end{equation}"
    )
    candidate = _document(
        r"\begin{equation}\label{eq:b}x=1\tag{2}\end{equation}"
    )

    category = build_analysis_inventory_bundle(
        baseline, candidate, PAGE_MAP
    ).category("equation")

    assert category.baseline_items[0].stable_id == category.current_items[0].stable_id
    assert _kinds(category) == {
        InventoryResidualKind.NUMBER_CHANGED,
        InventoryResidualKind.LABEL_CHANGED,
    }
    assert category.status is InventoryStatus.RESIDUAL


def test_duplicate_equation_number_and_label_are_detected() -> None:
    baseline = _document(
        r"\begin{equation}\label{eq:a}x=1\tag{1}\end{equation}"
    )
    candidate = _document(
        r"""
        \begin{equation}\label{eq:a}x=1\tag{1}\end{equation}
        \begin{equation}\label{eq:a}y=2\tag{1}\end{equation}
        """
    )

    category = build_analysis_inventory_bundle(
        baseline, candidate, PAGE_MAP
    ).category("equation")

    assert InventoryResidualKind.DUPLICATE in _kinds(category)
    assert InventoryResidualKind.ADDED in _kinds(category)


@pytest.mark.parametrize(
    ("body", "category"),
    [
        (r"Text\footnote{unterminated", "footnote"),
        (r"\begin{equation}x=1", "equation"),
    ],
)
def test_malformed_relevant_tex_fails_closed(body: str, category: str) -> None:
    baseline = _document("Plain prose.")
    candidate = _document(body)

    bundle = build_analysis_inventory_bundle(baseline, candidate, PAGE_MAP)
    evidence = bundle.category(category)

    assert evidence.scanner_executed is True
    assert evidence.status is InventoryStatus.FAILED
    assert InventoryResidualKind.SCAN_FAILED in _kinds(evidence)
    assert bundle.gate().status is InventoryStatus.FAILED


def test_native_page_map_is_bound_and_exact_page_sequence_is_required() -> None:
    baseline = _document(r"\section{One}")
    candidate = baseline.replace(
        "% LaTeXStruct-Page: page_id=ocr-page-000002 source_page=2\n"
        "\\hypertarget{ocr-page-000002}{}\n",
        "",
    )

    bundle = build_analysis_inventory_bundle(baseline, candidate, PAGE_MAP)

    assert bundle.mapping_status is InventoryStatus.RESIDUAL
    assert bundle.current_page_sequence == (1,)
    assert {item.kind for item in bundle.mapping_residual} == {
        InventoryResidualKind.PAGE_MAP_MISMATCH
    }
    assert "page_map" in bundle.gate().blocked_categories


def test_comments_protected_text_preamble_and_escaped_commands_are_inactive() -> None:
    tex = _document(
        r"""
        % \section{Commented}
        \begin{verbatim}
        \section{Protected}
        \end{verbatim}
        \\section{Escaped}
        \section{Real}
        """,
        preamble=r"\newcommand{\fake}{\section{Preamble}}",
    )

    heading = build_analysis_inventory_bundle(tex, tex, PAGE_MAP).category("heading")

    assert heading.status is InventoryStatus.PASS
    assert heading.baseline_total == 1
    assert heading.baseline_items[0].title == "Real"


def test_crlf_and_lf_have_deterministic_normalized_inventory() -> None:
    baseline = _document(r"\section{Stable}")
    candidate = baseline.replace("\n", "\r\n")

    bundle = build_analysis_inventory_bundle(baseline, candidate, PAGE_MAP)

    assert bundle.category("heading").status is InventoryStatus.PASS
    assert bundle.category("heading").baseline_items == bundle.category("heading").current_items


def test_legacy_production_page_markers_bind_only_through_native_map() -> None:
    tex = dedent(
        r"""
        \documentclass{article}
        \begin{document}
        % Page 1
        \section{Legacy production marker}
        % Page 2
        \end{document}
        """
    ).strip()

    bundle = build_analysis_inventory_bundle(tex, tex, PAGE_MAP)

    assert bundle.mapping_status is InventoryStatus.PASS
    assert bundle.baseline_page_sequence == (1, 2)
    assert bundle.baseline_tex_sha256 == bundle.current_tex_sha256
    assert bundle.category("heading").baseline_items[0].source_page == 1


def test_bundle_digest_binds_exact_baseline_and_candidate_tex_artifacts() -> None:
    baseline = _document(r"\section{Bound}")
    candidate = baseline.replace("Bound", "Changed")

    bundle = build_analysis_inventory_bundle(baseline, candidate, PAGE_MAP)

    assert bundle.baseline_tex_sha256 != bundle.current_tex_sha256
    assert bundle.as_dict()["baseline_tex_sha256"] == bundle.baseline_tex_sha256
    assert bundle.as_dict()["current_tex_sha256"] == bundle.current_tex_sha256


def test_naked_formal_heading_is_an_unstructured_residual() -> None:
    tex = _document("Theorem 1. A naked statement.")

    formal = build_analysis_inventory_bundle(tex, tex, PAGE_MAP).category("formal")

    assert InventoryResidualKind.UNSTRUCTURED in _kinds(formal)
    assert formal.status is InventoryStatus.RESIDUAL


def test_naked_baseline_formal_becomes_pass_after_correct_structuring() -> None:
    baseline = _document("Theorem 1. A naked statement.")
    candidate = _document(
        r"""
        \begin{theorem}[Theorem 1]
        A naked statement.
        \end{theorem}
        """
    )

    formal = build_analysis_inventory_bundle(
        baseline,
        candidate,
        PAGE_MAP,
        authorizations=(
            _authorization("formal", InventoryAuthorizationAction.STRUCTURE_WRAPPER),
        ),
    ).category("formal")

    assert formal.status is InventoryStatus.PASS
    assert formal.baseline_total == formal.current_total == 1
    assert formal.baseline_items[0].stable_id == formal.current_items[0].stable_id


def test_formal_missing_wrong_extra_and_nested_structures_fail_closed() -> None:
    baseline = _document("Theorem 1. Preserve this statement.")
    candidates = {
        "missing": _document("Preserve this statement."),
        "wrong": _document(
            r"\begin{definition}[Theorem 1]Preserve this statement.\end{definition}"
        ),
        "extra": _document(
            r"""
            \begin{theorem}[Theorem 1]Preserve this statement.\end{theorem}
            \begin{theorem}[Theorem 1]Preserve this statement.\end{theorem}
            """
        ),
        "nested": _document(
            r"""
            \begin{theorem}[Theorem 1]
            \begin{theorem}[Theorem 1]Preserve this statement.\end{theorem}
            \end{theorem}
            """
        ),
    }

    observed = {
        name: build_analysis_inventory_bundle(
            baseline, candidate, PAGE_MAP
        ).category("formal")
        for name, candidate in candidates.items()
    }

    assert InventoryResidualKind.MISSING in _kinds(observed["missing"])
    assert InventoryResidualKind.KIND_CHANGED in _kinds(observed["wrong"])
    assert InventoryResidualKind.DUPLICATE in _kinds(observed["extra"])
    assert InventoryResidualKind.DUPLICATE in _kinds(observed["nested"])
    assert all(item.status is InventoryStatus.RESIDUAL for item in observed.values())


def test_native_heading_block_authorizes_plain_to_section_without_line_heuristics() -> None:
    plain = "1. Introduction"
    baseline = _document(plain)
    candidate = _document(r"\section{Introduction}")
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="block-0001",
        block_type="HEADING_TEXT",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )
    authorization = _authorization(
        "heading", InventoryAuthorizationAction.STRUCTURE_WRAPPER
    )

    bundle = build_analysis_inventory_bundle(
        baseline,
        candidate,
        PAGE_MAP,
        native_source_blocks=(block,),
        authorizations=(authorization,),
        require_native_heading_inventory=True,
    )

    heading = bundle.category("heading")
    assert heading.status is InventoryStatus.PASS
    assert heading.baseline_total == heading.current_total == 1
    assert heading.applied_authorization_ids == (authorization.authorization_id,)
    assert bundle.gate().status is InventoryStatus.PASS


def test_native_heading_structure_requires_authorization_and_preserves_level() -> None:
    plain = "1. Introduction"
    baseline = _document(plain)
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="block-0001",
        block_type="HEADING_TEXT",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )
    unauthorized = build_analysis_inventory_bundle(
        baseline,
        _document(r"\section{Introduction}"),
        PAGE_MAP,
        native_source_blocks=(block,),
        require_native_heading_inventory=True,
    ).category("heading")
    wrong_level = build_analysis_inventory_bundle(
        baseline,
        _document(r"\subsection{Introduction}"),
        PAGE_MAP,
        native_source_blocks=(block,),
        authorizations=(
            _authorization("heading", InventoryAuthorizationAction.STRUCTURE_WRAPPER),
        ),
        require_native_heading_inventory=True,
    ).category("heading")

    assert InventoryResidualKind.REPRESENTATION_CHANGED in _kinds(unauthorized)
    assert InventoryResidualKind.KIND_CHANGED in _kinds(wrong_level)


def test_required_native_heading_inventory_fails_closed_when_absent() -> None:
    tex = _document("Ordinary text.")
    heading = build_analysis_inventory_bundle(
        tex,
        tex,
        PAGE_MAP,
        require_native_heading_inventory=True,
    ).category("heading")

    assert heading.status is InventoryStatus.FAILED
    assert InventoryResidualKind.SCAN_FAILED in _kinds(heading)


def test_explicit_complete_empty_native_inventory_is_not_missing() -> None:
    tex = _document("Ordinary text.")
    heading = build_analysis_inventory_bundle(
        tex,
        tex,
        PAGE_MAP,
        native_source_blocks=(),
        require_native_heading_inventory=True,
    ).category("heading")

    assert heading.status is InventoryStatus.NOT_APPLICABLE


def test_native_heading_blocks_route_once_to_heading_formal_and_proof() -> None:
    source_texts = (
        ("heading-1", "1. Introduction"),
        ("formal-1", "Lemma 6.3. Every red graph has the property."),
        ("proof-1", "Proof. This follows immediately."),
    )
    baseline = _document("\n".join(text for _identifier, text in source_texts))
    candidate = _document(
        r"""
        \section{Introduction}
        \begin{lemma}[Lemma 6.3]
        Every red graph has the property.
        \end{lemma}
        \begin{proof}
        This follows immediately.
        \end{proof}
        """
    )
    blocks = tuple(
        AnalysisNativeSourceBlock(
            page_id="ocr-page-000001",
            source_page=1,
            block_id=block_id,
            block_type="HEADING_TEXT",
            plain_text=text,
            source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        for block_id, text in source_texts
    )
    authorizations = tuple(
        _authorization(category, InventoryAuthorizationAction.STRUCTURE_WRAPPER)
        for category in ("heading", "formal", "proof")
    )

    bundle = build_analysis_inventory_bundle(
        baseline,
        candidate,
        PAGE_MAP,
        native_source_blocks=blocks,
        authorizations=authorizations,
        require_native_heading_inventory=True,
    )

    assert {
        category: bundle.category(category).baseline_total
        for category in ("heading", "formal", "proof")
    } == {"heading": 1, "formal": 1, "proof": 1}
    assert all(
        bundle.category(category).status is InventoryStatus.PASS
        for category in ("heading", "formal", "proof")
    )


def test_native_formal_visible_text_matches_tex_literal_escapes_symmetrically() -> None:
    plain = "Theorem 3.1. Let A = {x}_n and retain 100% of it."
    escaped = r"Theorem 3.1. Let A = \{x\}\_n and retain 100\% of it."
    tex = _document(escaped)
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="escaped-formal-1",
        block_type="HEADING_TEXT",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )

    identical = build_analysis_inventory_bundle(
        tex,
        tex,
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("formal")
    structured = build_analysis_inventory_bundle(
        tex,
        _document(
            r"\begin{theorem}[Theorem 3.1]"
            r"Let A = \{x\}\_n and retain 100\% of it."
            r"\end{theorem}"
        ),
        PAGE_MAP,
        native_source_blocks=(block,),
        authorizations=(
            _authorization("formal", InventoryAuthorizationAction.STRUCTURE_WRAPPER),
        ),
    ).category("formal")

    assert identical.baseline_items == identical.current_items
    assert identical.baseline_total == identical.current_total == 1
    assert identical.status is InventoryStatus.RESIDUAL
    assert _kinds(identical) == {InventoryResidualKind.UNSTRUCTURED}
    assert structured.status is InventoryStatus.PASS


def test_native_display_math_is_a_plain_equation_inventory_identity() -> None:
    plain = "x ≤ 1"
    digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="native-display-1",
        block_type="DISPLAY_MATH",
        plain_text=plain,
        source_sha256=digest,
    )

    equation = build_analysis_inventory_bundle(
        _document(plain),
        _document(plain),
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("equation")

    assert equation.baseline_total == equation.current_total == 1
    assert equation.baseline_items[0].kind == "display-math"
    assert equation.baseline_items[0].representation == "plain"
    assert equation.current_items[0].representation == "plain"
    assert equation.baseline_items[0].source_sha256 == digest
    assert equation.current_items[0].source_sha256 == digest
    assert equation.status is InventoryStatus.RESIDUAL
    assert _kinds(equation) == {InventoryResidualKind.UNSTRUCTURED}


def test_native_display_math_allows_only_exact_visible_structure_wrapper() -> None:
    plain = "x ≤ 1"
    digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="native-display-2",
        block_type="DISPLAY_MATH",
        plain_text=plain,
        source_sha256=digest,
    )

    equation = build_analysis_inventory_bundle(
        _document(plain),
        _document(r"\begin{equation*}x \leq 1\end{equation*}"),
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("equation")

    assert equation.status is InventoryStatus.PASS
    assert equation.baseline_total == equation.current_total == 1
    assert equation.baseline_items[0].stable_id == equation.current_items[0].stable_id
    assert equation.baseline_items[0].source_sha256 == digest
    assert equation.baseline_items[0].representation == "plain"
    assert equation.current_items[0].representation == "syntax"
    assert equation.applied_authorization_ids == ()


def test_native_display_math_binds_verified_structured_baseline_by_page_order() -> None:
    plain = "PDF glyph extraction order is non-TeX"
    digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="native-display-structured-baseline",
        block_type="DISPLAY_MATH",
        plain_text=plain,
        source_sha256=digest,
    )
    tex = _document(r"\[R(\ell,k) \leq \binom{k+\ell-2}{\ell-1}\]")

    equation = build_analysis_inventory_bundle(
        tex,
        tex,
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("equation")

    assert equation.status is InventoryStatus.PASS
    assert equation.baseline_total == equation.current_total == 1
    assert equation.baseline_items[0].source_sha256 == digest
    assert equation.baseline_items[0].representation == "plain"
    assert equation.current_items[0].representation == "syntax"


@pytest.mark.parametrize("changed", ("x < 1", "X ≤ 1", "x ≤ 2"))
def test_native_display_math_content_tamper_is_never_authorized(changed: str) -> None:
    plain = "x ≤ 1"
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="native-display-tamper",
        block_type="DISPLAY_MATH",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )

    equation = build_analysis_inventory_bundle(
        _document(plain),
        _document(rf"\[{changed}\]"),
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("equation")

    assert equation.status is InventoryStatus.RESIDUAL
    assert InventoryResidualKind.MISSING in _kinds(equation)
    assert InventoryResidualKind.ADDED in _kinds(equation)


def test_native_display_math_duplicate_candidate_is_residual() -> None:
    plain = "x=1"
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="native-display-duplicate",
        block_type="DISPLAY_MATH",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )

    equation = build_analysis_inventory_bundle(
        _document(plain),
        _document(r"\[x=1\]" + "\n" + r"\[x=1\]"),
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category("equation")

    assert equation.baseline_total == 1
    assert equation.current_total == 2
    assert equation.status is InventoryStatus.RESIDUAL
    assert InventoryResidualKind.DUPLICATE in _kinds(equation)


def test_inline_and_mixed_native_math_never_become_equation_items() -> None:
    blocks = tuple(
        AnalysisNativeSourceBlock(
            page_id="ocr-page-000001",
            source_page=1,
            block_id=f"native-{block_type.casefold()}",
            block_type=block_type,
            plain_text=text,
            source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        for block_type, text in (
            ("INLINE_MATH", "x=1"),
            ("MIXED_TEXT_MATH", "For x=1 the claim follows."),
        )
    )
    tex = _document("\n".join(block.plain_text for block in blocks))

    equation = build_analysis_inventory_bundle(
        tex,
        tex,
        PAGE_MAP,
        native_source_blocks=blocks,
    ).category("equation")

    assert equation.baseline_total == equation.current_total == 0
    assert equation.status is InventoryStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("category", "block_type", "plain", "candidate_body"),
    [
        ("footnote", "FOOTNOTE", "1 Footnote text.", r"Body\footnote{Footnote text.}"),
        (
            "bibliography",
            "BIBLIOGRAPHY_ITEM",
            "[1] A. Smith, A reference.",
            r"""
            \begin{thebibliography}{9}
            \bibitem{smith} A. Smith, A reference.
            \end{thebibliography}
            """,
        ),
        (
            "caption",
            "CAPTION",
            "Figure 1. Ramsey plot.",
            r"\begin{figure}\caption{Ramsey plot.}\end{figure}",
        ),
    ],
)
def test_native_plain_blocks_allow_only_authorized_structure_wrappers(
    category: str,
    block_type: str,
    plain: str,
    candidate_body: str,
) -> None:
    baseline_body = "Body.\n" + plain if category == "footnote" else plain
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id=f"native-{category}-1",
        block_type=block_type,
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )
    authorization = _authorization(
        category, InventoryAuthorizationAction.STRUCTURE_WRAPPER
    )

    authorized = build_analysis_inventory_bundle(
        _document(baseline_body),
        _document(candidate_body),
        PAGE_MAP,
        native_source_blocks=(block,),
        authorizations=(authorization,),
    ).category(category)
    unauthorized = build_analysis_inventory_bundle(
        _document(baseline_body),
        _document(candidate_body),
        PAGE_MAP,
        native_source_blocks=(block,),
    ).category(category)

    assert authorized.status is InventoryStatus.PASS
    assert authorization.authorization_id in authorized.applied_authorization_ids
    assert unauthorized.status is InventoryStatus.RESIDUAL
    assert InventoryResidualKind.REPRESENTATION_CHANGED in _kinds(unauthorized)


def test_native_plain_block_content_change_is_not_authorized() -> None:
    cases = (
        ("footnote", "FOOTNOTE", "1 Keep this footnote.", r"\footnote{Changed footnote.}"),
        (
            "bibliography", "BIBLIOGRAPHY_ITEM", "[1] Keep this citation.",
            r"\begin{thebibliography}{9}\bibitem{x} Changed citation.\end{thebibliography}",
        ),
        ("caption", "CAPTION", "Figure 1. Keep caption.", r"\caption{Changed caption.}"),
    )
    for category, block_type, plain, candidate_body in cases:
        block = AnalysisNativeSourceBlock(
            page_id="ocr-page-000001",
            source_page=1,
            block_id=f"changed-{category}",
            block_type=block_type,
            plain_text=plain,
            source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
        )
        evidence = build_analysis_inventory_bundle(
            _document(plain),
            _document(candidate_body),
            PAGE_MAP,
            native_source_blocks=(block,),
            authorizations=(
                _authorization(category, InventoryAuthorizationAction.STRUCTURE_WRAPPER),
            ),
        ).category(category)
        assert evidence.status is InventoryStatus.RESIDUAL
        assert InventoryResidualKind.MISSING in _kinds(evidence)


def test_ambiguous_native_footnote_fragments_fail_closed() -> None:
    fragments = ("continued first fragment", "continued second fragment")
    blocks = tuple(
        AnalysisNativeSourceBlock(
            page_id="ocr-page-000001",
            source_page=1,
            block_id=f"footnote-fragment-{index}",
            block_type="FOOTNOTE",
            plain_text=text,
            source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        for index, text in enumerate(fragments, start=1)
    )
    tex = _document("\n".join(fragments))

    category = build_analysis_inventory_bundle(
        tex, tex, PAGE_MAP, native_source_blocks=blocks
    ).category("footnote")

    assert category.status is InventoryStatus.FAILED
    assert InventoryResidualKind.SCAN_FAILED in _kinds(category)
    assert "fragment grouping" in " ".join(category.scan_errors)


def test_host_authorization_builder_binds_policy_blocks_and_ocr_manifest() -> None:
    plain = "1. Introduction"
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="heading-policy-1",
        block_type="HEADING_TEXT",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )
    first = build_host_inventory_authorizations(
        (block,), ocr_manifest_sha256="a" * 64
    )
    second = build_host_inventory_authorizations(
        (block,), ocr_manifest_sha256="b" * 64
    )

    assert {(item.category, item.action) for item in first} == {
        ("heading", InventoryAuthorizationAction.STRUCTURE_WRAPPER),
        ("frontmatter", InventoryAuthorizationAction.GENERATED_TOC),
    }
    assert {item.evidence_id for item in first}.isdisjoint(
        {item.evidence_id for item in second}
    )
    assert all("latexstruct-host-inventory-policy" not in item.evidence_id for item in first)


def test_host_structure_policy_never_authorizes_math_content_changes() -> None:
    plain = "1. Introduction"
    block = AnalysisNativeSourceBlock(
        page_id="ocr-page-000001",
        source_page=1,
        block_id="heading-policy-1",
        block_type="HEADING_TEXT",
        plain_text=plain,
        source_sha256=hashlib.sha256(plain.encode("utf-8")).hexdigest(),
    )
    authorizations = build_host_inventory_authorizations(
        (block,), ocr_manifest_sha256="c" * 64
    )
    baseline = _document(plain + r"\[x=1\]")
    candidate = _document(r"\section{Introduction}\[x=2\]\tableofcontents")

    bundle = build_analysis_inventory_bundle(
        baseline,
        candidate,
        PAGE_MAP,
        native_source_blocks=(block,),
        authorizations=authorizations,
        require_native_heading_inventory=True,
    )

    assert bundle.category("heading").status is InventoryStatus.PASS
    assert bundle.category("frontmatter").status is InventoryStatus.PASS
    assert bundle.category("equation").status is InventoryStatus.RESIDUAL
    assert bundle.gate().passed is False


def test_generated_toc_requires_narrow_host_policy_authorization() -> None:
    baseline = _document("Plain prose.")
    candidate = _document(r"\tableofcontents" + "\nPlain prose.")
    unauthorized = build_analysis_inventory_bundle(
        baseline, candidate, PAGE_MAP
    ).category("frontmatter")
    authorization = _authorization(
        "frontmatter", InventoryAuthorizationAction.GENERATED_TOC
    )
    authorized = build_analysis_inventory_bundle(
        baseline,
        candidate,
        PAGE_MAP,
        authorizations=(authorization,),
    ).category("frontmatter")

    assert InventoryResidualKind.ADDED in _kinds(unauthorized)
    assert authorized.status is InventoryStatus.PASS
    assert authorized.applied_authorization_ids == (authorization.authorization_id,)


@pytest.mark.parametrize(
    "page_map",
    [
        {},
        {0: (1,)},
        {2: (2,), 1: (1,)},
        {1: ()},
        {1: (2, 1)},
        {1: (1, 1)},
    ],
)
def test_invalid_native_page_maps_are_rejected(page_map) -> None:
    tex = _document("Plain prose.")
    with pytest.raises(AnalysisInventoryError):
        build_analysis_inventory_bundle(tex, tex, page_map)
