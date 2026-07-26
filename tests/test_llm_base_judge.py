"""Unit tests for base LLM judge contracts and schema validation."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

import pytest

from src.llm.base_judge import BaseLLMJudge, JudgeConfig


class DummyJudge(BaseLLMJudge):
    @property
    def provider_name(self) -> str:
        return "dummy"

    def _invoke_model(self, prompt: str) -> str:
        return (
            "{"
            '"is_vulnerable": true, '
            '"cwe": "CWE-89", '
            '"severity": "HIGH", '
            '"confidence": 0.9, '
            '"reasoning": "unsafe SQL string interpolation", '
            '"exploitability": "direct user input reaches query", '
            '"recommended_fix": "parameterize query", '
            '"false_positive_probability": 0.1'
            "}"
        )


def test_analyze_code_returns_typed_result() -> None:
    judge = DummyJudge(JudgeConfig(model_name="dummy-model"))
    result = judge.analyze_code(
        code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
        sast_findings=[{"type": "SQL Injection", "cwe": "CWE-89"}],
    )

    assert result.model_name == "dummy-model"
    assert result.is_vulnerable is True
    assert result.cwe == "CWE-89"
    assert result.vulnerability_type == "SQL Injection"
    assert 0.0 <= result.confidence <= 1.0
    assert result.latency_ms >= 0.0


def test_validate_output_rejects_invalid_confidence() -> None:
    judge = DummyJudge(JudgeConfig(model_name="dummy-model"))
    with pytest.raises(ValueError, match="confidence"):
        judge.validate_output(
            {
                "is_vulnerable": True,
                "cwe": "CWE-89",
                "severity": "HIGH",
                "confidence": 1.5,
                "reasoning": "x",
                "exploitability": "x",
                "recommended_fix": "x",
                "false_positive_probability": 0.1,
            }
        )
