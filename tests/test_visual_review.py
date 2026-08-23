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


class _FakeBatchClient(_FakeClient):
    def __init__(self, batch_response=None):
        super().__init__([])
        self.batch_response = batch_response
        self.last_usage = {}

    def chat_vision_json_bytes(self, system, request, image, schema):
        payload = json.loads(request)
        self.requests.append({
            "system": system,
            "request": payload,
            "images": [image],
            "schema": schema,
        })
        return _response(payload["source_page"], payload["candidate_page"]), {
            "prompt_tokens": 2,
            "completion_tokens": 1,
        }

    def chat_vision_json_images_bytes(self, system, request, images, schema):
        payload = json.loads(request)
        self.requests.append({
            "system": system,
            "request": payload,
            "images": list(images),
            "schema": schema,
        })
        if callable(self.batch_response):
            response = self.batch_response(payload)
        elif self.batch_response is not None:
            response = self.batch_response
        else:
            response = {
                "pages": [
                    _response(item["source_page"], item["candidate_page"])
                    for item in payload["page_requests"]
                ]
            }
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


def test_three_full_resolution_page_pairs_share_one_transport_call(monkeypatch):
    renderer = _install_renderer(monkeypatch, 7, 7)
    client = _FakeBatchClient()
    progress = []

    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
        progress_callback=progress.append,
    )

    assert result.checked is True
    assert result.ok is True
    assert result.page_count == 7
    assert len(client.requests) == 3
    assert [len(item["images"]) for item in client.requests] == [3, 3, 1]
    assert [item["done"] for item in progress] == [3, 6, 7]
    assert result.usage["calls"] == 3
    assert all(document.closed for document in renderer.documents)


def test_batch_missing_page_echo_fails_closed(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    def omit_last(payload):
        return {
            "pages": [
                _response(item["source_page"], item["candidate_page"])
                for item in payload["page_requests"][:-1]
            ]
        }

    result = visual_review.audit_compiled_pages(
        _FakeBatchClient(omit_last),
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
    )

    assert result.checked is False
    assert result.ok is False
    assert any("漏答" in item["reason"] for item in result.invalid)


def test_batch_duplicate_page_echo_fails_closed(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    def duplicate_first(payload):
        pages = [
            _response(item["source_page"], item["candidate_page"])
            for item in payload["page_requests"]
        ]
        pages.append(dict(pages[0]))
        return {"pages": pages}

    result = visual_review.audit_compiled_pages(
        _FakeBatchClient(duplicate_first),
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
    )

    assert result.checked is False
    assert result.ok is False
    assert any("重复" in item["reason"] for item in result.invalid)


def test_batch_unknown_page_echo_fails_closed(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    def append_unknown(payload):
        pages = [
            _response(item["source_page"], item["candidate_page"])
            for item in payload["page_requests"]
        ]
        pages.append(_response(99, 99))
        return {"pages": pages}

    result = visual_review.audit_compiled_pages(
        _FakeBatchClient(append_unknown),
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
    )

    assert result.checked is False
    assert result.ok is False
    assert any("未知页码映射" in item["reason"] for item in result.invalid)


def test_batch_transport_failure_retries_individual_full_resolution_pages(
    monkeypatch,
):
    renderer = _install_renderer(monkeypatch, 3, 3)

    def reject_multiple_images(_payload):
        raise visual_review.LLMError("provider does not accept multiple images")

    client = _FakeBatchClient(reject_multiple_images)
    client.last_usage = {"prompt_tokens": 5, "completion_tokens": 1}
    progress = []
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
        progress_callback=progress.append,
    )

    assert result.checked is True
    assert result.ok is True
    assert [len(item["images"]) for item in client.requests] == [3, 1, 1, 1]
    assert result.usage["calls"] == 4
    assert result.usage["prompt_tokens"] == 11
    assert result.usage["completion_tokens"] == 4
    assert [item["done"] for item in progress] == [3]
    assert all(document.closed for document in renderer.documents)


def test_batch_auth_failure_does_not_multiply_single_page_requests(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    def reject_authentication(_payload):
        raise visual_review.LLMError("未配置 API Key")

    client = _FakeBatchClient(reject_authentication)
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
    )

    assert result.checked is False
    assert result.ok is False
    assert result.usage["calls"] == 1
    assert any("API Key" in item["reason"] for item in result.unresolved)
    assert [len(item["images"]) for item in client.requests] == [3]


def test_batch_malformed_protocol_failure_does_not_fallback(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    for message in (
        "响应 JSON 无法解析：第 1 行第 8 列",
        "视觉 JSON 批量复核失败: 服务返回了非 JSON 响应",
    ):
        def reject_protocol(_payload, *, _message=message):
            raise visual_review.LLMError(_message)

        client = _FakeBatchClient(reject_protocol)
        result = visual_review.audit_compiled_pages(
            client,
            source_pdf_bytes=b"source",
            candidate_pdf_bytes=b"candidate",
            page_range=None,
            source_text="% Page 1\nLong document",
            inventory=FormalInventory(),
            vision_batch_size=3,
        )
        assert result.checked is False
        assert result.ok is False
        assert result.usage["calls"] == 1
        assert any(message in item["reason"] for item in result.unresolved)
        assert [len(item["images"]) for item in client.requests] == [3]


def test_batch_timeout_and_explicit_truncation_each_fallback_once(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    for message in (
        "视觉 JSON 批量复核失败: 网络错误: timed out",
        "模型输出因达到 max_tokens 上限而被截断，本页将重试",
    ):
        def reject_bounded_batch(_payload, *, _message=message):
            raise visual_review.LLMError(_message)

        client = _FakeBatchClient(reject_bounded_batch)
        result = visual_review.audit_compiled_pages(
            client,
            source_pdf_bytes=b"source",
            candidate_pdf_bytes=b"candidate",
            page_range=None,
            source_text="% Page 1\nLong document",
            inventory=FormalInventory(),
            vision_batch_size=3,
        )
        assert result.checked is True
        assert result.ok is True
        assert [len(item["images"]) for item in client.requests] == [3, 1, 1, 1]
        assert result.usage["calls"] == 4


def test_batch_fallback_midway_failure_preserves_every_attempt_usage(monkeypatch):
    _install_renderer(monkeypatch, 3, 3)

    class MidwayFailureClient(_FakeBatchClient):
        def __init__(self):
            super().__init__()
            self.single_calls = 0

        def chat_vision_json_images_bytes(self, system, request, images, schema):
            payload = json.loads(request)
            self.requests.append({
                "system": system,
                "request": payload,
                "images": list(images),
                "schema": schema,
            })
            self.last_usage = {"prompt_tokens": 5, "completion_tokens": 1}
            raise visual_review.LLMError("provider accepts only one image")

        def chat_vision_json_bytes(self, system, request, image, schema):
            payload = json.loads(request)
            self.requests.append({
                "system": system,
                "request": payload,
                "images": [image],
                "schema": schema,
            })
            self.single_calls += 1
            if self.single_calls == 2:
                self.last_usage = {"prompt_tokens": 7}
                raise visual_review.LLMError("未配置 API Key")
            self.last_usage = {"prompt_tokens": 2, "completion_tokens": 1}
            return _response(payload["source_page"], payload["candidate_page"]), (
                dict(self.last_usage)
            )

    client = MidwayFailureClient()
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=b"source",
        candidate_pdf_bytes=b"candidate",
        page_range=None,
        source_text="% Page 1\nLong document",
        inventory=FormalInventory(),
        vision_batch_size=3,
    )

    assert result.checked is False
    assert result.ok is False
    assert [len(item["images"]) for item in client.requests] == [3, 1, 1]
    assert result.usage["calls"] == 3
    assert result.usage["prompt_tokens"] == 14
    assert result.usage["completion_tokens"] == 2
    assert any("API Key" in item["reason"] for item in result.unresolved)


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
    frozen_pairs.extend(
        (None, page)
        for page in deterministic["page_alignment"]["candidate_only_pages"]
    )
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


def test_equal_count_generated_toc_uses_frozen_covering_warp():
    source = _pdf_bytes([
        "alpha unique theorem statement and introduction",
        "beta unique lemma statement and complete proof",
        "gamma unique proposition statement and discussion",
        "delta unique references bibliography closing paragraph",
    ])
    candidate = _pdf_bytes([
        "alpha unique theorem statement and introduction",
        "contents alpha beta gamma delta generated navigation",
        "beta unique lemma statement and complete proof",
        (
            "gamma unique proposition statement and discussion "
            "delta unique references bibliography closing paragraph"
        ),
    ])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()
    mappings = deterministic["page_alignment"]["mappings"]
    candidate_only = deterministic["page_alignment"]["candidate_only_pages"]
    assert len(mappings) == 4
    assert candidate_only == [2]

    def close_frozen_findings(request):
        return _response(
            request["source_page"],
            request["candidate_page"],
            checked_finding_codes=[
                item["code"]
                for item in request["deterministic_findings_to_close"]
            ],
        )

    result = visual_review.audit_compiled_pages(
        _FakeClient(
            [close_frozen_findings] * (len(mappings) + len(candidate_only))
        ),
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=None,
        source_text=(
            "% Page 1\nalpha\n% Page 2\nbeta\n"
            "% Page 3\ngamma\n% Page 4\ndelta"
        ),
        inventory=FormalInventory(),
        deterministic_report=deterministic,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    )

    assert result.checked is True
    assert result.ok is True
    assert result.page_count == len(mappings) + len(candidate_only)


def test_split_source_page_shares_inventory_and_deduplicates_same_repair():
    source = _pdf_bytes([
        "Theorem 1. Unique formal title followed by a long complete statement body",
    ])
    candidate = _pdf_bytes([
        "Theorem 1. Unique formal title",
        "followed by a long complete statement body",
    ])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()
    mappings = deterministic["page_alignment"]["mappings"]
    assert [(item["source_page"], item["candidate_page"]) for item in mappings] == [
        (1, 1),
        (1, 2),
    ]

    def report_same_repair(request):
        return _response(
            request["source_page"],
            request["candidate_page"],
            verdict="repair",
            issues=[_issue("anchor-split", "missing-env", "theorem")],
            checked_finding_codes=[
                item["code"]
                for item in request["deterministic_findings_to_close"]
            ],
        )

    client = _FakeClient([report_same_repair] * len(mappings))
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=None,
        source_text="% Page 1\nTheorem 1. Unique formal title",
        inventory=FormalInventory(anchors=(_anchor("anchor-split", 2, "theorem"),)),
        deterministic_report=deterministic,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    )

    assert result.checked is True
    assert len(result.suggestions) == 1
    assert result.suggestions[0].inventory_id == "anchor-split"
    assert all(
        request["request"]["inventory_items_on_source_page"][0]["id"]
        == "anchor-split"
        for request in client.requests
    )


def test_split_source_page_conflicting_repairs_fail_closed():
    source = _pdf_bytes(["Theorem 1. Unique formal title and statement body"])
    candidate = _pdf_bytes([
        "Theorem 1. Unique formal title",
        "and statement body",
    ])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()
    mappings = deterministic["page_alignment"]["mappings"]

    def report_conflict(request):
        issue = (
            _issue("anchor-conflict", "missing-env", "theorem")
            if request["candidate_page"] == 1
            else _issue("anchor-conflict", "overwrapped", "")
        )
        return _response(
            request["source_page"],
            request["candidate_page"],
            verdict="repair",
            issues=[issue],
            checked_finding_codes=[
                item["code"]
                for item in request["deterministic_findings_to_close"]
            ],
        )

    client = _FakeClient([report_conflict] * len(mappings))
    result = visual_review.audit_compiled_pages(
        client,
        source_pdf_bytes=source,
        candidate_pdf_bytes=candidate,
        page_range=None,
        source_text="% Page 1\nTheorem 1. Unique formal title",
        inventory=FormalInventory(
            anchors=(_anchor("anchor-conflict", 2, "theorem"),)
        ),
        deterministic_report=deterministic,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
    )

    assert result.checked is True
    assert result.ok is False
    assert result.suggestions == []
    assert any("冲突修复建议" in item["reason"] for item in result.invalid)


def test_tampered_frozen_reflow_mapping_fails_before_model_call():
    source = _pdf_bytes(["alpha theorem", "beta proof"])
    candidate = _pdf_bytes(["contents", "alpha theorem", "beta proof"])
    deterministic = evaluate_visual_quality(
        source,
        candidate,
        candidate_scope=CANDIDATE_SCOPE_REFLOW,
        geometry_policy=GEOMETRY_POLICY_TEMPLATE_REFLOW,
    ).to_dict()
    deterministic["page_alignment"]["mappings"][0]["candidate_page"] = 3
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
