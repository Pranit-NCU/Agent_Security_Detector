"""Mocked integration tests for production Gemini judge behavior."""

from __future__ import annotations

import io
import json
from typing import Any
from urllib import error

import pytest

from src.llm.base_judge import JudgeConfig
from src.llm.gemini_judge import GeminiJudge


class _FakeHTTPResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload.encode("utf-8")

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def _build_gemini_provider_payload(model_text: str) -> str:
    return json.dumps(
        {
            "candidates": [
                {
                    "content": {"parts": [{"text": model_text}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 123,
                "candidatesTokenCount": 45,
                "totalTokenCount": 168,
            },
        }
    )


def test_gemini_success_with_usage_and_normalization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    response_json = _build_gemini_provider_payload(
        json.dumps(
            {
                "is_vulnerable": True,
                "cwe": "CWE-89",
                "severity": "HIGH",
                "confidence": 0.9,
                "reasoning": "User input reaches SQL execution path and attacker-controlled input is unsanitized.",
                "exploitability": "",
                "recommended_fix": "Use parameterized queries",
                "false_positive_probability": 0.1,
            }
        )
    )

    def _fake_urlopen(request_obj: Any, timeout: float) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(response_json)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    judge = GeminiJudge(JudgeConfig(model_name="gemini-2.5-flash", max_retries=1))
    result = judge.analyze_code(
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_id}\"",
        sast_findings=[{"type": "SQL Injection", "cwe": "CWE-89", "confidence": 0.95}],
    )

    assert result.is_vulnerable is True
    assert result.cwe == "CWE-89"
    assert result.confidence == 0.9
    assert result.exploitability != ""

    benchmark_fields = judge.benchmark_fields()
    assert benchmark_fields["provider"] == "gemini"
    assert benchmark_fields["prompt_tokens"] == 123
    assert benchmark_fields["candidate_tokens"] == 45
    assert benchmark_fields["total_tokens"] == 168


def test_gemini_retries_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    model_json = json.dumps(
        {
            "is_vulnerable": False,
            "cwe": "CWE-89",
            "severity": "LOW",
            "confidence": 0.2,
            "reasoning": "Query execution appears parameterized.",
            "exploitability": "Not exploitable in current context.",
            "recommended_fix": "No action required",
            "false_positive_probability": 0.85,
        }
    )
    response_json = _build_gemini_provider_payload(model_json)

    call_count = {"value": 0}

    def _fake_urlopen(request_obj: Any, timeout: float) -> _FakeHTTPResponse:
        call_count["value"] += 1
        if call_count["value"] == 1:
            raise error.HTTPError(
                url="https://example.test",
                code=429,
                msg="rate limited",
                hdrs=None,
                fp=io.BytesIO(b"rate limit"),
            )
        return _FakeHTTPResponse(response_json)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)

    judge = GeminiJudge(JudgeConfig(model_name="gemini-2.5-flash", max_retries=2))
    result = judge.analyze_code(
        code_snippet="cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
        sast_findings=[{"type": "SQL Injection", "cwe": "CWE-89"}],
    )

    assert call_count["value"] == 2
    assert result.is_vulnerable is False


def test_gemini_rejects_non_strict_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    model_text = (
        "Here is your analysis: "
        + json.dumps(
            {
                "is_vulnerable": True,
                "cwe": "CWE-89",
                "severity": "HIGH",
                "confidence": 0.8,
                "reasoning": "x",
                "exploitability": "x",
                "recommended_fix": "x",
                "false_positive_probability": 0.2,
            }
        )
    )

    response_json = _build_gemini_provider_payload(model_text)

    def _fake_urlopen(request_obj: Any, timeout: float) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(response_json)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    judge = GeminiJudge(JudgeConfig(model_name="gemini-2.5-flash", max_retries=0))
    with pytest.raises(ValueError, match="strict JSON-only"):
        judge.analyze_code(
            code_snippet="query = user_input",
            sast_findings=[{"type": "SQL Injection", "cwe": "CWE-89"}],
        )


def test_confidence_normalization_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    response_json = _build_gemini_provider_payload(
        json.dumps(
            {
                "is_vulnerable": True,
                "cwe": "CWE-89",
                "severity": "HIGH",
                "confidence": 1.0,
                "reasoning": "attacker control remains",
                "exploitability": "direct",
                "recommended_fix": "sanitize",
                "false_positive_probability": 1.0,
            }
        )
    )

    def _fake_urlopen(request_obj: Any, timeout: float) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(response_json)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    judge = GeminiJudge(JudgeConfig(model_name="gemini-2.5-flash", max_retries=0))
    result = judge.analyze_code(
        code_snippet="dangerous()",
        sast_findings=[{"type": "SQL Injection", "cwe": "CWE-89"}],
    )

    assert 0.0 <= result.confidence <= 1.0
