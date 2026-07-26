"""Unit tests for multi-judge consensus engine behavior."""

from __future__ import annotations

from src.llm.base_judge import JudgeResult
from src.llm.consensus_engine import ConsensusConfig, ConsensusEngine


def _result(model: str, vuln: bool, confidence: float, cwe: str = "CWE-89") -> JudgeResult:
    return JudgeResult(
        model_name=model,
        is_vulnerable=vuln,
        vulnerability_type="SQL Injection",
        cwe=cwe,
        severity="HIGH",
        confidence=confidence,
        reasoning="r",
        exploitability="e",
        remediation="m",
        raw_response="{}",
        latency_ms=1.0,
    )


def test_consensus_majority_and_weighted_score() -> None:
    engine = ConsensusEngine(
        ConsensusConfig(model_weights={"gemini": 1.0, "ollama": 1.0, "hf": 1.0})
    )
    results = [
        _result("gemini", True, 0.9),
        _result("ollama", True, 0.7),
        _result("hf", False, 0.8),
    ]

    consensus = engine.aggregate(results)
    assert consensus.disagreement is True
    assert consensus.majority_vote_ratio == 2 / 3
    assert 0.0 <= consensus.weighted_vote_score <= 1.0


def test_consensus_with_sast_weight() -> None:
    engine = ConsensusEngine(ConsensusConfig(sast_weight=0.4, vulnerability_threshold=0.5))
    results = [_result("gemini", True, 0.6), _result("ollama", False, 0.6)]

    consensus = engine.aggregate(results, sast_confidence=0.9)
    assert consensus.final_score >= 0.0
    assert consensus.final_score <= 1.0
