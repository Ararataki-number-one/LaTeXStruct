# -*- coding: utf-8 -*-
"""Strict, network-free tests for the production analysis dependency bridge."""

from __future__ import annotations

import json

import pymupdf
import pytest

from latexstruct.core import analysis_production
from latexstruct.core.analysis_orchestrator import CallbackContractError, MachineVerificationFacts
from latexstruct.core.analysis_production import ProductionAnalysisError, run_production_analysis
from latexstruct.core.analysis_schema import AnalysisFinalStatus, sha256_text


TARGET = "Every graph has a vertex."
BASELINE_TEX = (
    f"\\documentclass{{article}}\n\\begin{{document}}\n% Page 1\n{TARGET}\n\\end{{document}}\n"
)


def _pdf(text: str = "page one") -> bytes:
    document = pymupdf.open()
    try:
        page = document.new_page(width=300, height=400)
        page.insert_text((30, 50), text)
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _multi_page_pdf(count: int, prefix: str) -> bytes:
    document = pymupdf.open()
    try:
        for page_number in range(1, count + 1):
            page = document.new_page(width=300, height=400)
            page.insert_text((30, 50), f"{prefix} {page_number}")
        return document.tobytes(garbage=4, deflate=True)
    finally:
        document.close()


def _empty_finding(binding):
    return {"binding": binding, "findings": []}


class FakeTextClient:
    model = "fake-text-v2"

    def __init__(self, events, *, conflict=False, broken_role=""):
        self.events = events
        self.conflict = conflict
        self.broken_role = broken_role
        self.system_prompts = []
        self.user_requests = []

    def chat_json(self, system, user):
        self.system_prompts.append(system)
        assert "HOST AUTHORITY AND EVIDENCE RULES" in system
        assert "COMPLETE OUTPUT JSON SCHEMA" in system
        assert '"additionalProperties": false' in system
        lowered_system = system.lower()
        assert "ordinary expository prose" in lowered_system
        assert "proof starts only" in lowered_system
        assert "vertical" in lowered_system and "composite" in lowered_system
        lowered_user = user.lower()
        assert "authorization" not in lowered_user
        assert "api_key" not in lowered_user
        assert "c:\\\\users\\\\" not in lowered_user
        request = json.loads(user)
        self.user_requests.append(request)
        binding = request["binding"]
        role = binding["role"]
        self.events.append(role if role != "AI-5" else "AI-5-text")
        if role == self.broken_role:
            return {"binding": binding}, {}
        if role in {"AI-1", "AI-2"}:
            if role == "AI-2" and not self.conflict:
                return _empty_finding(binding), {"input_tokens": 3}
            if role == "AI-2" and self.conflict:
                issue_type = "PROSE_ONLY"
            else:
                issue_type = "FORMAL_BOUNDARY"
            finding = {
                "issue_type": issue_type,
                "severity": "HIGH",
                "exact_quotes": [TARGET],
                "source_pdf_regions": [],
                "description": "formal boundary differs",
                "suggestion": "wrap only the exact formal statement",
                "blocker_reason": "",
            }
            return {"binding": binding, "findings": [finding]}, {"input_tokens": 5}
        if role == "AI-4":
            return {
                "binding": binding,
                "patch": {
                    "operations": [
                        {
                            "operation": "wrap_environment",
                            "start_anchor": TARGET,
                            "end_anchor": TARGET,
                            "exact_old_text": TARGET,
                            "replacement": (f"\\begin{{theorem}}\n{TARGET}\n\\end{{theorem}}"),
                            "reason": "restore the theorem boundary",
                        }
                    ]
                },
            }, {"output_tokens": 8}
        if role == "AI-6":
            return {
                "binding": binding,
                "judgments": [
                    {
                        "keep": index == 0,
                        "reason": "first interpretation has exact boundary evidence",
                    }
                    for index, _issue in enumerate(request["issues"])
                ],
                "resolved": True,
                "explanation": "retain one host-bound interpretation",
            }, {"output_tokens": 2}
        raise AssertionError(role)


class SchemaAwareTextClient(FakeTextClient):
    def __init__(self, events, *, conflict=False):
        super().__init__(events, conflict=conflict)
        self.schema_calls = []

    def chat_json(self, _system, _user):
        raise AssertionError("schema-aware clients must receive the host schema")

    def chat_json_schema(self, system, user, schema):
        request = json.loads(user)
        self.schema_calls.append((request["binding"]["role"], schema))
        return FakeTextClient.chat_json(self, system, user)


class FakeVisionClient:
    model = "fake-vision-v2"

    def __init__(self, events):
        self.events = events
        self.system_prompts = []
        self.schemas = []

    def chat_vision_json_images_bytes(self, system, user, images, schema=None):
        self.system_prompts.append(system)
        self.schemas.append(schema)
        assert "HOST AUTHORITY AND EVIDENCE RULES" in system
        assert "COMPLETE OUTPUT JSON SCHEMA" in system
        assert "table of contents" in system
        assert isinstance(schema, dict)
        assert schema.get("additionalProperties") is False
        lowered_user = user.lower()
        assert "authorization" not in lowered_user
        assert "api_key" not in lowered_user
        assert "c:\\\\users\\\\" not in lowered_user
        assert len(images) == 2
        assert all(image.startswith(b"\x89PNG\r\n\x1a\n") for image in images)
        request = json.loads(user)
        binding = request["binding"]
        role = binding["role"]
        if role == "AI-3":
            self.events.append("AI-3")
            return _empty_finding(binding), {"input_tokens": 7}
        assert role == "AI-5"
        if "pass_number" in request:
            number = request["pass_number"]
            self.events.append(f"AI-5-final-{number}")
            assert request["prior_pass_conclusion"] == "WITHHELD_BY_HOST"
            return {
                "binding": binding,
                "content_conservation_ok": True,
                "math_conservation_ok": True,
                "visual_review_ok": True,
                "formal_inventory_ok": True,
                "new_high_risk_issues": 0,
                "prior_pass_conclusion_visible": False,
            }, {"input_tokens": 11}
        self.events.append("AI-5-issue")
        return {
            "binding": binding,
            "content_conservation_ok": True,
            "math_conservation_ok": True,
            "visual_review_ok": True,
            "result": "PASS",
            "new_high_priority_issues": 0,
        }, {"input_tokens": 9}


class FakeCompiler:
    def __init__(self, pdf, events):
        self.pdf = pdf
        self.events = events
        self.extra_files_seen = []

    def __call__(self, tex, *, extra_files):
        patched = "\\begin{theorem}" in tex
        self.events.append("compile-patched" if patched else "compile-baseline")
        self.extra_files_seen.append(dict(extra_files))
        return {
            "ok": True,
            "pdf_bytes": self.pdf,
            "page_count": 1,
            "engine": "fake-xelatex",
            "log": "real compile succeeded",
        }


def _facts(request, *, omissions=0):
    page_ids = tuple(page_id for page_id, _payload in request.compile_result.page_pdf_bytes)
    return MachineVerificationFacts(
        candidate_hash=request.candidate_hash,
        checked_page_ids=page_ids,
        silent_page_omissions=omissions,
        silent_text_losses=0,
        unauthorized_math_changes=0,
        formal_errors=0,
        toc_complete_and_ordered=True,
        severe_equation_number_errors=0,
        silent_footnote_losses=0,
        silent_figure_caption_losses=0,
        silent_bibliography_losses=0,
    )


def _run(
    tmp_path,
    *,
    text_client=None,
    verifier=_facts,
    candidate_page_map=None,
    concurrency_limit=3,
):
    events = []
    pdf = _pdf()
    text = text_client or FakeTextClient(events)
    vision = FakeVisionClient(events)
    compiler = FakeCompiler(pdf, events)
    result = run_production_analysis(
        run_id="production-analysis-run-1",
        project_id="project-1",
        source_pdf=pdf,
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=pdf,
        page_range=(1,),
        candidate_page_map=candidate_page_map or {1: 1},
        candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: (
            candidate_page_map or {1: 1}
        ),
        text_clients={
            "AI-1": text,
            "AI-2": text,
            "AI-4": text,
            "AI-6": text,
        },
        vision_clients={"AI-3": vision, "AI-5": vision},
        compiler=compiler,
        machine_verifier=verifier,
        candidate_root=tmp_path / "candidates",
        compile_extra_files={"figures/a.png": b"trusted-extra"},
        raw_ocr_frozen=True,
        concurrency_limit=concurrency_limit,
        max_macro_rounds=1,
    )
    return result, events, compiler


def test_production_bridge_calls_real_roles_in_order_and_compiles_each_candidate_twice(
    tmp_path, monkeypatch
):
    host_patch_arguments = []
    patch_operation = analysis_production.PatchOperation

    def capture_host_patch(**kwargs):
        host_patch_arguments.append(dict(kwargs))
        return patch_operation(**kwargs)

    monkeypatch.setattr(analysis_production, "PatchOperation", capture_host_patch)
    result, events, compiler = _run(tmp_path)

    assert events == [
        "compile-baseline",
        "compile-baseline",
        "AI-1",
        "AI-2",
        "AI-3",
        "AI-4",
        "compile-patched",
        "compile-patched",
        "AI-5-issue",
        "AI-5-final-1",
        "AI-5-final-2",
    ]
    assert result.orchestration.decision.status == AnalysisFinalStatus.VERIFIED
    assert result.snapshot.concurrency_limit == 3
    assert result.orchestration.decision.verified is True
    assert len(result.compile_invocations) == 4
    assert [item.run_number for item in result.compile_invocations] == [1, 2, 1, 2]
    assert len(result.transport_invocations) == 7
    assert all(
        extra_files == {"figures/a.png": b"trusted-extra"}
        for extra_files in compiler.extra_files_seen
    )
    assert result.page_inputs[0].source_pdf_page.startswith(b"\x89PNG")
    assert result.orchestration.current_pdf.startswith(b"%PDF-")
    assert result.current_compile_log == (
        "real compile succeeded\nreal compile succeeded"
    )

    # The simulated model response contains no id, offset, page mapping, or
    # digest fields outside the immutable binding.  A successful typed ledger
    # and patch therefore prove that these values were derived by the host.
    issue = result.orchestration.ledger[0]
    source_page_id = result.snapshot.page_map[0].source_page_id
    region = BASELINE_TEX[BASELINE_TEX.index("% Page 1") :]
    expected_start = region.index(TARGET)
    assert issue.issue_id.startswith("ISS-")
    assert issue.source_page_ids == (source_page_id,)
    assert issue.tex_anchors[0].start_offset == expected_start
    assert issue.tex_anchors[0].end_offset == expected_start + len(TARGET)
    assert issue.tex_anchors[0].text_hash == sha256_text(TARGET)
    assert issue.evidence_hashes == (sha256_text(region),)
    assert issue.proposed_patch_id.startswith("PATCH-")
    assert host_patch_arguments == [
        {
            "operation": analysis_production.PatchOperationKind.WRAP_ENVIRONMENT,
            "issue_ids": (issue.issue_id,),
            "start_anchor": TARGET,
            "end_anchor": TARGET,
            "expected_old_hash": sha256_text(TARGET),
            "replacement": f"\\begin{{theorem}}\n{TARGET}\n\\end{{theorem}}",
            "source_page_ids": (source_page_id,),
            "reason": "restore the theorem boundary",
        }
    ]


def test_production_text_roles_receive_their_exact_host_schemas(tmp_path):
    events = []
    text = SchemaAwareTextClient(events, conflict=True)

    result, _observed, _compiler = _run(tmp_path, text_client=text)

    assert result.orchestration.decision.verified is True
    schemas_by_role = {role: schema for role, schema in text.schema_calls}
    assert schemas_by_role["AI-1"] == analysis_production._FINDING_RESPONSE_SCHEMA
    assert schemas_by_role["AI-2"] == analysis_production._FINDING_RESPONSE_SCHEMA
    assert schemas_by_role["AI-4"] == analysis_production._PATCH_RESPONSE_SCHEMA
    assert schemas_by_role["AI-6"] == analysis_production._ADJUDICATION_RESPONSE_SCHEMA


def test_production_schemas_avoid_codex_unsupported_keywords():
    schemas = (
        analysis_production._FINDING_RESPONSE_SCHEMA,
        analysis_production._PATCH_RESPONSE_SCHEMA,
        analysis_production._ISSUE_REVIEW_RESPONSE_SCHEMA,
        analysis_production._FINAL_REVIEW_RESPONSE_SCHEMA,
        analysis_production._ADJUDICATION_RESPONSE_SCHEMA,
    )
    encoded = json.dumps(schemas, sort_keys=True)
    assert '"oneOf"' not in encoded
    assert '"uniqueItems"' not in encoded


def test_host_rejects_a_finding_without_bound_evidence(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def remove_evidence(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = []
            response["findings"][0]["source_pdf_regions"] = []
        return response, usage

    client.chat_json = remove_evidence
    with pytest.raises(CallbackContractError, match="no bound evidence"):
        _run(tmp_path, text_client=client)


def test_host_rejects_duplicate_exact_quotes(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def duplicate_evidence(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = [TARGET, TARGET]
        return response, usage

    client.chat_json = duplicate_evidence
    with pytest.raises(CallbackContractError, match="duplicate exact quotes"):
        _run(tmp_path, text_client=client)


def test_changed_candidate_uses_its_own_live_page_map_for_review(tmp_path):
    events = []
    baseline_pdf = _multi_page_pdf(2, "baseline")
    patched_pdf = _multi_page_pdf(2, "patched")
    text = FakeTextClient(events)

    class RecordingVision(FakeVisionClient):
        def __init__(self, target_events):
            super().__init__(target_events)
            self.page_numbers = []

        def chat_vision_json_images_bytes(self, system, user, images, schema=None):
            request = json.loads(user)
            self.page_numbers.append((
                request["binding"]["role"],
                tuple(request["candidate_pdf_page_numbers"]),
            ))
            return super().chat_vision_json_images_bytes(
                system, user, images, schema=schema
            )

    vision = RecordingVision(events)

    def compiler(tex, *, extra_files):
        del extra_files
        pdf = patched_pdf if "\\begin{theorem}" in tex else baseline_pdf
        return {
            "ok": True,
            "pdf_bytes": pdf,
            "page_count": 2,
            "engine": "fake-xelatex",
            "log": "ok",
        }

    baseline_hash = sha256_text(BASELINE_TEX)
    mapping_calls = []

    def mapper(candidate_hash, pdf_bytes):
        mapping_calls.append((candidate_hash, pdf_bytes))
        return {1: (1,)} if candidate_hash == baseline_hash else {1: (2,)}

    result = run_production_analysis(
        run_id="production-live-map-run",
        project_id="project-live-map",
        source_pdf=_pdf(),
        raw_ocr_tex=BASELINE_TEX,
        baseline_tex=BASELINE_TEX,
        baseline_pdf=baseline_pdf,
        page_range=(1,),
        candidate_page_map={1: (1,)},
        candidate_page_mapper=mapper,
        text_clients={
            "AI-1": text,
            "AI-2": text,
            "AI-4": text,
            "AI-6": text,
        },
        vision_clients={"AI-3": vision, "AI-5": vision},
        compiler=compiler,
        machine_verifier=_facts,
        candidate_root=tmp_path / "live-map-candidates",
        raw_ocr_frozen=True,
        max_macro_rounds=1,
    )

    assert result.orchestration.decision.verified is True
    assert len(mapping_calls) == 2
    assert ("AI-3", (1,)) in vision.page_numbers
    assert any(role == "AI-5" and pages == (2,) for role, pages in vision.page_numbers)
    assert not any(role == "AI-5" and pages == (1,) for role, pages in vision.page_numbers)


def test_changed_candidate_without_live_mapper_fails_closed(tmp_path):
    events = []
    pdf = _pdf()
    with pytest.raises(ProductionAnalysisError, match="live host page mapper"):
        run_production_analysis(
            run_id="production-missing-live-map",
            project_id="project-missing-live-map",
            source_pdf=pdf,
            raw_ocr_tex=BASELINE_TEX,
            baseline_tex=BASELINE_TEX,
            baseline_pdf=pdf,
            page_range=(1,),
            candidate_page_map={1: 1},
            text_clients={
                "AI-1": FakeTextClient(events),
                "AI-2": FakeTextClient(events),
                "AI-4": FakeTextClient(events),
                "AI-6": FakeTextClient(events),
            },
            vision_clients={
                "AI-3": FakeVisionClient(events),
                "AI-5": FakeVisionClient(events),
            },
            compiler=FakeCompiler(pdf, events),
            machine_verifier=_facts,
            candidate_root=tmp_path / "missing-live-map-candidates",
            raw_ocr_frozen=True,
            max_macro_rounds=1,
        )


def test_live_baseline_map_must_match_immutable_snapshot(tmp_path):
    events = []
    pdf = _multi_page_pdf(2, "candidate")

    def compiler(_tex, *, extra_files):
        del extra_files
        return {
            "ok": True,
            "pdf_bytes": pdf,
            "page_count": 2,
            "engine": "fake-xelatex",
            "log": "ok",
        }

    with pytest.raises(ProductionAnalysisError, match="immutable snapshot"):
        run_production_analysis(
            run_id="production-stale-baseline-map",
            project_id="project-stale-baseline-map",
            source_pdf=_pdf(),
            raw_ocr_tex=BASELINE_TEX,
            baseline_tex=BASELINE_TEX,
            baseline_pdf=pdf,
            page_range=(1,),
            candidate_page_map={1: 1},
            candidate_page_mapper=lambda _candidate_hash, _pdf_bytes: {1: 2},
            text_clients={
                "AI-1": FakeTextClient(events),
                "AI-2": FakeTextClient(events),
                "AI-4": FakeTextClient(events),
                "AI-6": FakeTextClient(events),
            },
            vision_clients={
                "AI-3": FakeVisionClient(events),
                "AI-5": FakeVisionClient(events),
            },
            compiler=compiler,
            machine_verifier=_facts,
            candidate_root=tmp_path / "stale-baseline-map-candidates",
            raw_ocr_frozen=True,
            max_macro_rounds=1,
        )


def test_strict_model_schema_rejects_missing_findings_before_next_role(tmp_path):
    events = []
    text = FakeTextClient(events, broken_role="AI-1")
    with pytest.raises(CallbackContractError, match="JSON schema"):
        _run(tmp_path, text_client=text)
    # Calls already present in the bounded discovery wave may finish, while
    # the host rejects the whole wave before mutating its issue ledger.
    assert set(events).issubset({"AI-1", "AI-2", "AI-3"})
    assert "AI-1" in events


def test_production_parallelism_has_a_hard_three_call_ceiling(tmp_path):
    with pytest.raises(ProductionAnalysisError, match="concurrency_limit must be in 1..3"):
        _run(tmp_path, concurrency_limit=4)


def test_missing_candidate_page_mapping_fails_before_models_or_compile(tmp_path):
    with pytest.raises(ProductionAnalysisError, match="cover the selected pages exactly"):
        _run(tmp_path, candidate_page_map={2: 1})


def test_machine_failures_remain_unverified_and_cannot_be_promoted(tmp_path):
    result, _events, _compiler = _run(
        tmp_path, verifier=lambda request: _facts(request, omissions=1)
    )

    assert result.orchestration.decision.verified is False
    assert result.orchestration.decision.status == AnalysisFinalStatus.COMPLETED_WITH_ISSUES
    assert "silent_page_omission" in result.orchestration.decision.failures


def test_invalid_machine_status_field_is_rejected_instead_of_trusted(tmp_path):
    def invalid(request):
        facts = as_mapping(_facts(request))
        facts["verified"] = True
        return facts

    with pytest.raises(CallbackContractError, match="extra=verified"):
        _run(tmp_path, verifier=invalid)


def as_mapping(value):
    return {
        "candidate_hash": value.candidate_hash,
        "checked_page_ids": list(value.checked_page_ids),
        "silent_page_omissions": value.silent_page_omissions,
        "silent_text_losses": value.silent_text_losses,
        "unauthorized_math_changes": value.unauthorized_math_changes,
        "formal_errors": value.formal_errors,
        "toc_complete_and_ordered": value.toc_complete_and_ordered,
        "severe_equation_number_errors": value.severe_equation_number_errors,
        "silent_footnote_losses": value.silent_footnote_losses,
        "silent_figure_caption_losses": value.silent_figure_caption_losses,
        "silent_bibliography_losses": value.silent_bibliography_losses,
    }


def test_ai6_is_a_real_transport_call_only_when_conflict_requires_it(tmp_path):
    events = []
    text = FakeTextClient(events, conflict=True)
    result, _observed, _compiler = _run(tmp_path, text_client=text)

    assert "AI-6" in events
    assert any(item.operation == "adjudication" for item in result.transport_invocations)
    assert sum(item.operation == "adjudication" for item in result.transport_invocations) == 1


def test_model_cannot_supply_host_owned_finding_hash_or_offset_fields(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def inject_host_field(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["evidence_hashes"] = [sha256_text("invented")]
        return response, usage

    client.chat_json = inject_host_field
    with pytest.raises(CallbackContractError, match="extra=evidence_hashes"):
        _run(tmp_path, text_client=client)


@pytest.mark.parametrize("quote", ["not present in the supplied region", "e"])
def test_missing_or_non_unique_finding_quote_fails_closed(tmp_path, quote):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def bad_quote(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-1":
            response = json.loads(json.dumps(response))
            response["findings"][0]["exact_quotes"] = [quote]
        return response, usage

    client.chat_json = bad_quote
    with pytest.raises(CallbackContractError, match="does not resolve exactly once"):
        _run(tmp_path, text_client=client)


@pytest.mark.parametrize("anchor", ["not present in the supplied region", "e"])
def test_missing_or_non_unique_patch_anchor_fails_closed(tmp_path, anchor):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def bad_anchor(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            response["patch"]["operations"][0]["start_anchor"] = anchor
            response["patch"]["operations"][0]["end_anchor"] = anchor
            response["patch"]["operations"][0]["exact_old_text"] = anchor
        return response, usage

    client.chat_json = bad_anchor
    with pytest.raises(CallbackContractError, match="anchors do not resolve exactly once"):
        _run(tmp_path, text_client=client)


def test_model_cannot_supply_patch_hash_ids_or_page_mapping(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def inject_host_fields(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            operation = response["patch"]["operations"][0]
            operation["expected_old_hash"] = sha256_text(TARGET)
            operation["issue_ids"] = ["ISS-model-owned"]
            operation["source_page_ids"] = ["source-model-owned"]
        return response, usage

    client.chat_json = inject_host_fields
    with pytest.raises(CallbackContractError, match="extra="):
        _run(tmp_path, text_client=client)


def test_patch_replacement_cannot_cross_host_page_scope(tmp_path):
    events = []
    client = FakeTextClient(events)
    original = client.chat_json

    def cross_page_boundary(system, user):
        response, usage = original(system, user)
        if json.loads(user)["binding"]["role"] == "AI-4":
            response = json.loads(json.dumps(response))
            response["patch"]["operations"][0]["replacement"] += (
                "\n% Page 999999\nforeign page content"
            )
        return response, usage

    client.chat_json = cross_page_boundary
    with pytest.raises(CallbackContractError, match="host page or document boundary"):
        _run(tmp_path, text_client=client)


def test_reflow_mapping_skips_candidate_only_toc_and_preserves_two_candidate_pages(tmp_path):
    source_pdf = _multi_page_pdf(2, "source")
    candidate_pdf = _multi_page_pdf(4, "candidate")
    baseline_tex = (
        "\\documentclass{article}\n"
        "\\begin{document}\n"
        "% Page 1\nFirst source page.\n"
        "% Page 2\nSecond source page reflows.\n"
        "\\end{document}\n"
    )
    calls = []

    class EmptyTextClient:
        model = "empty-text"

        def chat_json(self, system, user):
            del system
            request = json.loads(user)
            assert request["binding"]["role"] in {"AI-1", "AI-2"}
            return _empty_finding(request["binding"]), {}

    class MappingVisionClient:
        model = "mapping-vision"

        def chat_vision_json_images_bytes(self, system, user, images, schema=None):
            del system, schema
            request = json.loads(user)
            with pymupdf.open(stream=images[1], filetype="png") as image_document:
                pixmap = image_document[0].get_pixmap()
                current_height = pixmap.height
                samples = pixmap.samples
                has_blue_boundary = any(
                    samples[index + 2] >= samples[index] + 15
                    for index in range(0, len(samples), pixmap.n)
                )
            calls.append(
                (
                    request["binding"]["source_page_id"],
                    tuple(request["candidate_pdf_page_numbers"]),
                    request["current_render_is_composite"],
                    current_height,
                    has_blue_boundary,
                )
            )
            if request["binding"]["role"] == "AI-3":
                return _empty_finding(request["binding"]), {}
            return {
                "binding": request["binding"],
                "content_conservation_ok": True,
                "math_conservation_ok": True,
                "visual_review_ok": True,
                "formal_inventory_ok": True,
                "new_high_risk_issues": 0,
                "prior_pass_conclusion_visible": False,
            }, {}

    compile_calls = []

    def compiler(tex, *, extra_files):
        del tex, extra_files
        compile_calls.append("compile")
        return {
            "ok": True,
            "pdf_bytes": candidate_pdf,
            "page_count": 4,
            "engine": "fake-xelatex",
            "log": "ok",
        }

    result = run_production_analysis(
        run_id="production-reflow-run",
        project_id="project-reflow",
        source_pdf=source_pdf,
        raw_ocr_tex=baseline_tex,
        baseline_tex=baseline_tex,
        baseline_pdf=candidate_pdf,
        page_range=(1, 2),
        candidate_page_map={1: 1, 2: (3, 4)},
        text_clients={
            "AI-1": EmptyTextClient(),
            "AI-2": EmptyTextClient(),
            "AI-4": EmptyTextClient(),
        },
        vision_clients={"AI-3": MappingVisionClient(), "AI-5": MappingVisionClient()},
        compiler=compiler,
        machine_verifier=_facts,
        candidate_root=tmp_path / "reflow-candidates",
        raw_ocr_frozen=True,
        max_macro_rounds=1,
    )

    assert compile_calls == ["compile", "compile"]
    assert result.snapshot.page_map[0].candidate_pdf_page_ids == ("candidate-page-000001",)
    assert result.snapshot.page_map[1].candidate_pdf_page_ids == (
        "candidate-page-000003",
        "candidate-page-000004",
    )
    assert all(
        2 not in page_numbers for _page_id, page_numbers, _composite, _height, _boundary in calls
    )
    single_heights = [
        height for _page_id, pages, _composite, height, _boundary in calls if pages == (1,)
    ]
    composite_heights = [
        height
        for _page_id, pages, composite, height, _boundary in calls
        if pages == (3, 4) and composite
    ]
    assert single_heights and composite_heights
    assert min(composite_heights) > max(single_heights) + 80
    assert all(
        boundary
        for _page_id, pages, composite, _height, boundary in calls
        if pages == (3, 4) and composite
    )
    assert result.orchestration.decision.verified is True
