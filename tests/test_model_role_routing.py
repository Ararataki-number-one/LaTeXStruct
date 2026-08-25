# -*- coding: utf-8 -*-
"""Network-free checks for audited primary/triage Codex model routing."""

from __future__ import annotations

from copy import deepcopy

import pytest

from latexstruct.config import AppConfig, _validate_codex_settings
from latexstruct.core import analysis_production
from latexstruct.core.analysis_budget import BudgetLimits
from latexstruct.core.analysis_schema import ModelBinding
from latexstruct.core.codex_cli import CodexCLIClient
from latexstruct.core.ocr_runtime import (
    OcrRunSnapshot,
    frozen_ocr_model_binding,
    make_run_snapshot,
)
from latexstruct.server.app import (
    _analysis_v2_client_bindings,
    _codex_model_selector_from_snapshot,
    _frozen_ocr_model_binding,
    _ocr_model_binding,
)


def _codex_config() -> AppConfig:
    return AppConfig(
        analysis_backend="codex_cli",
        codex_model="gpt-5.4",
        codex_reasoning_effort="high",
        codex_triage_model="gpt-5.4-mini",
        codex_triage_reasoning_effort="high",
    )


def _ocr_snapshot(effort: str = "high") -> OcrRunSnapshot:
    return make_run_snapshot(
        source_bytes=b"%PDF-1.7\nrole-routing",
        source_type="pdf",
        original_filename="math.pdf",
        source_total_pages=1,
        selected_pages=(1,),
        ocr_model="gpt-5.4",
        api_backend="codex_cli",
        app_version="2.0.0",
        runtime_options={"reasoning_effort": effort},
        run_id="a" * 32,
        started_at="2026-08-25T00:00:00+00:00",
    )


def test_triage_override_is_scoped_to_initial_structure_findings():
    cfg = _codex_config()

    assert cfg.codex_binding_for_operation("structure-findings") == (
        "gpt-5.4-mini",
        "high",
    )
    for operation in (
        "structure-recheck",
        "content-math-findings",
        "visual-findings",
        "local-patch",
        "issue-review",
        "final-review-1",
        "final-review-2",
        "adjudication",
    ):
        assert cfg.codex_binding_for_operation(operation) == ("gpt-5.4", "high")


def test_authoritative_server_keeps_ai1_on_primary_model_without_starting_codex():
    text_clients, vision_clients, model_ids = _analysis_v2_client_bindings(
        _codex_config()
    )

    assert text_clients["AI-1"].model == "gpt-5.4"
    assert text_clients["AI-1"].reasoning_effort == "high"
    assert model_ids["AI-1"] == "gpt-5.4"
    for role in ("AI-2", "AI-4", "AI-6"):
        assert text_clients[role].model == "gpt-5.4"
        assert text_clients[role].reasoning_effort == "high"
        assert model_ids[role] == "gpt-5.4"
    for role in ("AI-3", "AI-5"):
        assert vision_clients[role].model == "gpt-5.4"
        assert vision_clients[role].reasoning_effort == "high"
        assert model_ids[role] == "gpt-5.4"


def test_empty_triage_fields_preserve_primary_binding():
    cfg = AppConfig(
        analysis_backend="codex_cli",
        codex_model="gpt-5.4",
        codex_reasoning_effort="high",
    )
    assert cfg.codex_binding_for_operation("structure-findings") == (
        "gpt-5.4",
        "high",
    )


def test_codex_default_selector_round_trips_without_passing_display_sentinel():
    assert _codex_model_selector_from_snapshot("codex-cli-default") == ""
    assert _codex_model_selector_from_snapshot("gpt-5.4") == "gpt-5.4"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("codex_triage_model", "bad model id"),
        ("codex_triage_reasoning_effort", "maximum"),
    ),
)
def test_invalid_triage_selector_is_rejected(field: str, value: str):
    cfg = _codex_config()
    setattr(cfg, field, value)
    with pytest.raises(ValueError):
        _validate_codex_settings(cfg)


def test_analysis_model_binding_freezes_reasoning_effort():
    high = ModelBinding(
        "AI-1",
        "gpt-5.4-mini",
        ("json", "initial-structure-triage"),
        "HIGH",
    )
    assert high.reasoning_effort == "high"
    with pytest.raises(ValueError):
        ModelBinding("AI-1", "gpt-5.4-mini", ("json",), "maximum")


def test_analysis_transport_contract_freezes_task_operations_and_effort():
    text_clients, vision_clients, model_ids = _analysis_v2_client_bindings(
        _codex_config()
    )
    limits = BudgetLimits(0, 0, 0.0, 0, 0, 120.0)
    clients = {**text_clients, **vision_clients}
    contracts = {
        role: analysis_production._transport_contract(
            role=role,
            model_id=model_ids[role],
            client=clients[role],
            limits=limits,
        )
        for role in model_ids
    }

    assert contracts["AI-1"]["model_id"] == "gpt-5.4"
    assert contracts["AI-1"]["reasoning_effort"] == "high"
    assert contracts["AI-1"]["operations"] == [
        "structure-findings",
        "structure-recheck",
    ]
    assert contracts["AI-2"]["operations"] == [
        "content-math-findings",
        "content-math-recheck",
    ]
    assert contracts["AI-3"]["operations"] == [
        "visual-findings",
        "visual-recheck",
        "visual-triage",
    ]
    assert contracts["AI-4"]["operations"] == ["local-patch"]
    assert contracts["AI-5"]["operations"] == [
        "final-review-1",
        "final-review-2",
        "issue-review",
    ]
    assert contracts["AI-6"]["operations"] == ["adjudication"]
    for role in ("AI-1", "AI-2", "AI-3", "AI-4", "AI-5", "AI-6"):
        assert contracts[role]["model_id"] == "gpt-5.4"
        assert contracts[role]["reasoning_effort"] == "high"
    assert all(
        not any(
            secret_name in str(key).casefold()
            for secret_name in ("api_key", "authorization", "credential")
        )
        for contract in contracts.values()
        for key in contract
    )


def test_ocr_snapshot_binds_primary_model_effort_and_hash():
    high = _ocr_snapshot("high")
    medium = _ocr_snapshot("medium")

    binding = frozen_ocr_model_binding(high)
    assert binding == {
        "role": "OCR",
        "operations": ["math-ocr-transcription"],
        "model_id": "gpt-5.4",
        "reasoning_effort": "high",
        "backend": "codex_cli",
        "capabilities": ["vision", "math-ocr", "structured-output"],
    }
    assert high.config_sha256 != medium.config_sha256


def test_ocr_resume_binding_rejects_effort_drift_without_model_call():
    frozen = _ocr_snapshot("high")
    current = CodexCLIClient(model="gpt-5.4", reasoning_effort="medium")

    assert _frozen_ocr_model_binding(frozen) != _ocr_model_binding(
        current, current.cfg.model, "codex_cli"
    )


def test_tampered_ocr_binding_model_is_rejected():
    payload = deepcopy(_ocr_snapshot().to_dict())
    payload["pipeline_contract"]["model_bindings"][0]["model_id"] = (
        "gpt-5.4-mini"
    )
    with pytest.raises(ValueError):
        OcrRunSnapshot.from_dict(payload)


def test_ocr_snapshot_rejects_contract_effort_that_differs_from_runtime():
    medium_binding = deepcopy(
        _ocr_snapshot("medium").to_dict()["pipeline_contract"]["model_bindings"]
    )
    with pytest.raises(ValueError, match="differs from runtime_options"):
        make_run_snapshot(
            source_bytes=b"%PDF-1.7\nrole-routing",
            source_type="pdf",
            original_filename="math.pdf",
            source_total_pages=1,
            selected_pages=(1,),
            ocr_model="gpt-5.4",
            api_backend="codex_cli",
            app_version="2.0.0",
            runtime_options={"reasoning_effort": "high"},
            pipeline_contract={"model_bindings": medium_binding},
            run_id="b" * 32,
            started_at="2026-08-25T00:00:00+00:00",
        )
