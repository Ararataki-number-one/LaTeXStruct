# -*- coding: utf-8 -*-
"""All-page visual review authority and fail-closed tests."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pymupdf

from latexstruct.core import visual_review
from latexstruct.core.formal_inventory import (
    FormalAnchor,
    FormalEnvironment,
    FormalFinding,
    FormalInventory,
)
from latexstruct.core.visual_quality import (
    CANDIDATE_SCOPE_REFLOW,
    GEOMETRY_POLICY_TEMPLATE_REFLOW,
    evaluate_visual_quality,
)


class _FakeDocument:
    def __init__(self, page_count: int):
        self.page_count = page_count
        self.closed = False

    def close(self):
        self.closed = True


class _FakeRenderer:
    def __init__(self, source_pages: int, candidate_pages: int):
        self.source_pages = source_pages
        self.candidate_pages = candidate_pages
        self.documents = []

    def open(self, *, stream, filetype):
        assert filetype == "pdf"
        count = self.source_pages if stream == b"source" else self.candidate_pages
        document = _FakeDocument(count)
        self.documents.append(document)
        return document


class _FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.cfg = SimpleNamespace(model="test-vision")

    def chat_vision_json_bytes(self, system, request, image, schema):
        payload = json.loads(request)
        self.requests.append({
            "system": system,
            "request": payload,
            "image": image,
            "schema": schema,
        })
        response = self.responses[len(self.requests) - 1]
        if callable(response):
            response = response(payload)
        return response, {"prompt_tokens": 2, "completion_tokens": 1}


def _response(
    source_page,
    candidate_page,
    verdict="ok",
    issues=None,
    reason="checked",
    checked_finding_codes=None,
):
    return {
        "source_page": source_page,
        "candidate_page": candidate_page,
        "verdict": verdict,
        "issues": list(issues or []),
        "reason": reason,
        "checked_finding_codes": list(checked_finding_codes or []),
    }


def _issue(inventory_id, problem, env, confidence=0.99, evidence="visible evidence"):
    return {
        "inventory_id": inventory_id,
        "problem": problem,
        "env": env,
        "confidence": confidence,
        "evidence": evidence,
    }


def _anchor(item_id: str, line: int, env: str) -> FormalAnchor:
    return FormalAnchor(
        id=item_id,
        start_line=line,
        end_line=line,
        raw_text=f"{env} title",
        visible_text=f"{env} title",
        label=env.title(),
        number="1.1",
        suggested_env=env,
        original_env="",
        source_sha256=(item_id.encode("utf-8").hex() + "0" * 64)[:64],
        block_id=line,
        strong=True,
    )


def _environment(item_id: str, line: int, env: str) -> FormalEnvironment:
    return FormalEnvironment(
        id=item_id,
        start_line=line,
        end_line=line,
        original_env=env,
        suggested_env=env,
        optional_title="",
        source_sha256=(item_id.encode("utf-8").hex() + "0" * 64)[:64],
    )


def _finding(item_id: str, kind: str, environment_id: str, suggested_env: str):
    return FormalFinding(
        id=item_id,
        kind=kind,
        start_line=1,
        end_line=1,
        original_env="lemma" if kind == "wrong-env" else "theorem",
        suggested_env=suggested_env,
        source_sha256="0" * 64,
        reason="host evidence",
        environment_id=environment_id,
    )


def _install_renderer(monkeypatch, source_pages: int, candidate_pages: int):
    renderer = _FakeRenderer(source_pages, candidate_pages)
    monkeypatch.setattr(visual_review, "_load_renderer", lambda: renderer)
    monkeypatch.setattr(
        visual_review,
        "_composite_page_png",
        lambda _module, _source, _candidate, source_page, candidate_page, source_label="SOURCE PDF": (
            f"source={source_page};candidate={candidate_page}".encode("ascii")
        ),
    )
    return renderer


def _pdf_bytes(pages):
    document = pymupdf.open()
    try:
        for index, text in enumerate(pages, 1):
            page = document.new_page(width=595, height=842)
            page.insert_text((72, 84), f"{index}. {text}", fontsize=11)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def test_all_aligned_pages_are_reviewed_once(monkeypatch):
    renderer = _install_renderer(monkeypatch, 3, 3)
    client = _FakeClient([
        lambda request: _response(request["source_page"], request["candidate_page"]),
    ] * 3)
    progress = []

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nA\n% Page 2\nB\n% Page 3\nC",
        inventory=FormalInventory(),
        progress_callback=progress.append,
    )

    assert result.checked is True
    assert result.ok is True
    assert result.page_count == 3
    assert [item["source_page"] for item in result.pages] == [1, 2, 3]
    assert [item["request"]["source_page"] for item in client.requests] == [1, 2, 3]
    assert [item["done"] for item in progress] == [1, 2, 3]
    assert result.usage["calls"] == 3
    assert all(document.closed for document in renderer.documents)


def test_default_batch_reviews_all_pages_beyond_legacy_80_page_limit(monkeypatch):
    renderer = _install_renderer(monkeypatch, 81, 81)
    client = _FakeClient([
        lambda request: _response(request["source_page"], request["candidate_page"]),
    ] * 81)
    progress = []

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        progress_callback=progress.append,
    )

    assert result.checked is True
    assert result.ok is True
    assert result.page_count == 81
    assert len(client.requests) == 81
    assert [item["request"]["source_page"] for item in client.requests] == list(
        range(1, 82)
    )
    assert progress[-1]["done"] == progress[-1]["total"] == 81
    assert result.usage["calls"] == 81
    assert all(document.closed for document in renderer.documents)


def test_any_invalid_page_beyond_legacy_limit_fails_complete_audit(monkeypatch):
    _install_renderer(monkeypatch, 100, 100)
    responses = [
        lambda request: _response(request["source_page"], request["candidate_page"]),
    ] * 100
    responses[-1] = lambda request: _response(99, request["candidate_page"])
    client = _FakeClient(responses)

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
    )

    assert len(client.requests) == 100
    assert result.page_count == 100
    assert result.checked is False
    assert result.ok is False
    assert result.pages[-1]["source_page"] == 100
    assert result.pages[-1]["valid"] is False
    assert any(item["page"] == 100 for item in result.invalid)


def test_selected_range_scope_rejects_extra_candidate_pages_without_model_calls(
    monkeypatch,
):
    _install_renderer(monkeypatch, 100, 100)
    client = _FakeClient([])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range={"start": 21, "end": 40},
        source_text="% Page 21\nSelected OCR range",
        inventory=FormalInventory(),
        candidate_scope="selected_range",
    )

    assert result.checked is False
    assert result.ok is False
    assert result.page_count == 0
    assert client.requests == []
    assert "期望 20 页，实际 100 页" in result.unresolved[0]["reason"]
    assert result.unresolved[0]["candidate_scope"] == "selected_range"


def test_image_source_uses_explicit_source_image_visual_header(monkeypatch):
    renderer = _FakeRenderer(1, 1)
    monkeypatch.setattr(visual_review, "_load_renderer", lambda: renderer)
    labels = []

    def capture_composite(
        _module,
        _source,
        _candidate,
        source_page,
        candidate_page,
        source_label="SOURCE PDF",
    ):
        labels.append(source_label)
        return f"source={source_page};candidate={candidate_page}".encode("ascii")

    monkeypatch.setattr(visual_review, "_composite_page_png", capture_composite)
    client = _FakeClient([_response(1, 1)])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"wrapped-image-pdf",
        candidate_pdf_bytes=b"candidate",
        page_range=(1, 1),
        source_text="% Page 1\nImage OCR text",
        inventory=FormalInventory(),
        source_label="SOURCE IMAGE",
    )

    assert result.ok is True
    assert labels == ["SOURCE IMAGE"]
    assert client.requests[0]["request"]["source_visual_label"] == "SOURCE IMAGE"


def test_legal_anchor_and_environment_suggestions_are_inventory_bound(monkeypatch):
    _install_renderer(monkeypatch, 5, 5)
    source_text = (
        "% Page 1\nTheorem 1.1. A.\n"
        "% Page 2\nLemma 1.1. B.\n"
        "% Page 3\nRemark. C.\n"
        "% Page 4\nExisting lemma.\n"
        "% Page 5\nExisting theorem."
    )
    inventory = FormalInventory(
        anchors=(
            _anchor("anchor-missing", 2, "theorem"),
            _anchor("anchor-wrong", 4, "lemma"),
            _anchor("anchor-over", 6, "remark"),
        ),
        environments=(
            _environment("env-wrong", 8, "lemma"),
            _environment("env-over", 10, "theorem"),
        ),
        findings=(
            _finding("finding-wrong", "wrong-env", "env-wrong", "theorem"),
            _finding("finding-duplicate", "duplicate", "env-over", "theorem"),
        ),
    )
    issues = [
        _issue("anchor-missing", "missing-env", "theorem"),
        _issue("anchor-wrong", "wrong-env", "lemma"),
        _issue("anchor-over", "overwrapped", ""),
        _issue("env-wrong", "wrong-env", "theorem"),
        _issue("env-over", "overwrapped", "theorem"),
    ]
    client = _FakeClient([
        _response(index, index, verdict="repair", issues=[issue])
        for index, issue in enumerate(issues, 1)
    ])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text=source_text,
        inventory=inventory,
    )

    assert result.checked is True
    assert result.ok is False
    assert result.invalid == []
    assert result.unresolved == []
    assert [
        (item.inventory_id, item.problem, item.env)
        for item in result.suggestions
    ] == [
        ("anchor-missing", "missing-env", "theorem"),
        ("anchor-wrong", "wrong-env", "lemma"),
        ("anchor-over", "overwrapped", ""),
        ("env-wrong", "wrong-env", "theorem"),
        ("env-over", "overwrapped", "theorem"),
    ]
    requested = [
        item["request"]["inventory_items_on_source_page"][0]
        for item in client.requests
    ]
    assert all(item["allowed_visual_repairs"] for item in requested)
    assert "raw_text" not in requested[0]


def test_unknown_illegal_and_coordinate_bearing_targets_are_rejected(monkeypatch):
    _install_renderer(monkeypatch, 1, 1)
    inventory = FormalInventory(anchors=(_anchor("anchor-1", 2, "theorem"),))
    coordinate_issue = _issue("anchor-1", "missing-env", "theorem")
    coordinate_issue["body_span"] = [2, 9]
    client = _FakeClient([_response(
        1,
        1,
        verdict="repair",
        issues=[
            _issue("unknown", "missing-env", "theorem"),
            _issue("anchor-1", "wrong-env", "lemma"),
            _issue("anchor-1", "overwrapped", "theorem"),
            _issue("anchor-1", "missing-env", "theorem", confidence=2),
            coordinate_issue,
        ],
    )])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nTheorem 1.1. A.",
        inventory=inventory,
    )

    assert result.checked is False
    assert result.ok is False
    assert result.suggestions == []
    assert len(result.invalid) == 5
    assert result.pages[0]["valid"] is False


def test_layout_problem_stays_unresolved_and_is_never_a_structure_suggestion(monkeypatch):
    _install_renderer(monkeypatch, 1, 1)
    client = _FakeClient([_response(
        1,
        1,
        verdict="manual",
        issues=[_issue("", "layout", "", confidence=0.7, evidence="bottom clipped")],
    )])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nText",
        inventory=FormalInventory(),
    )

    assert result.checked is True
    assert result.ok is False
    assert result.invalid == []
    assert result.suggestions == []
    assert result.unresolved == [{
        "page": 1,
        "problem": "layout",
        "reason": "bottom clipped",
    }]


def test_missing_candidate_page_is_not_reported_as_a_complete_audit(monkeypatch):
    _install_renderer(monkeypatch, 3, 2)
    client = _FakeClient([
        lambda request: _response(request["source_page"], request["candidate_page"]),
    ] * 2)

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nA\n% Page 2\nB\n% Page 3\nC",
        inventory=FormalInventory(),
    )

    assert result.checked is False
    assert result.ok is False
    assert result.page_count == 2
    assert len(client.requests) == 2
    assert result.unresolved[0]["pages"] == [3]


def test_wrong_page_echo_leaves_that_page_unanswered(monkeypatch):
    _install_renderer(monkeypatch, 2, 2)
    client = _FakeClient([
        _response(1, 1),
        _response(1, 2),
    ])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nA\n% Page 2\nB",
        inventory=FormalInventory(),
    )

    assert result.checked is False
    assert result.ok is False
    assert result.page_count == 2
    assert result.pages[0]["valid"] is True
    assert result.pages[1]["valid"] is False
    assert any("页码映射" in item["reason"] for item in result.invalid)


def test_deterministic_review_warning_must_be_explicitly_closed(monkeypatch):
    _install_renderer(monkeypatch, 1, 1)
    deterministic = {
        "findings": [{
            "code": "SOURCE_TEXT_LAYER_UNAVAILABLE",
            "message": "source has no text layer",
            "needs_model_review": True,
        }],
        "pages": [],
    }
    missing = _FakeClient([_response(1, 1)])
    result = visual_review.audit_compiled_pages(
        missing,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nText",
        inventory=FormalInventory(),
        deterministic_report=deterministic,
    )
    assert result.checked is False
    assert any("逐条关闭" in item["reason"] for item in result.invalid)

    complete = _FakeClient([_response(
        1,
        1,
        checked_finding_codes=["SOURCE_TEXT_LAYER_UNAVAILABLE"],
    )])
    result = visual_review.audit_compiled_pages(
        complete,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nText",
        inventory=FormalInventory(),
        deterministic_report=deterministic,
    )
    assert result.checked is True
    assert result.ok is True


def test_reflow_ai_audit_reuses_frozen_mapping_and_reviews_every_candidate():
    source = _pdf_bytes(["alpha theorem", "beta proof"])
    candidate = _pdf_bytes(["contents", "alpha theorem", "beta proof"])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()

    def close_frozen_findings(request):
        return _response(
            request["source_page"],
            request["candidate_page"],
            checked_finding_codes=[
                item["code"]
                for item in request["deterministic_findings_to_close"]
            ],
        )

    client = _FakeClient([close_frozen_findings] * 3)
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=None,
        source_text="% Page 1\nalpha theorem\n% Page 2\nbeta proof",
        inventory=FormalInventory(),
        deterministic_report=deterministic,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    )

    frozen_pairs = [
        (item["source_page"], item["candidate_page"])
        for item in deterministic["page_alignment"]["mappings"]
    ]
    requested_pairs = [
        (item["request"]["source_page"], item["request"]["candidate_page"])
        for item in client.requests
    ]
    assert result.checked is True
    assert result.ok is True
    assert requested_pairs == frozen_pairs
    assert len(requested_pairs) == 3
    assert {candidate_page for _source_page, candidate_page in requested_pairs} == {
        1, 2, 3,
    }
    assert result.alignment_sha256 == deterministic["page_alignment"][
        "mapping_sha256"
    ]


def test_tampered_frozen_reflow_mapping_fails_before_model_call():
    source = _pdf_bytes(["alpha theorem", "beta proof"])
    candidate = _pdf_bytes(["contents", "alpha theorem", "beta proof"])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()
    deterministic["page_alignment"]["mappings"][0]["candidate_page"] = 2
    client = _FakeClient([])

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=None,
        source_text="% Page 1\nalpha theorem\n% Page 2\nbeta proof",
        inventory=FormalInventory(),
        deterministic_report=deterministic,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    )

    assert result.checked is False
    assert result.ok is False
    assert result.page_count == 0
    assert client.requests == []
    assert "篡改" in result.invalid[0]["reason"]
