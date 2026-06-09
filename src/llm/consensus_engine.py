"""Consensus strategies for combining SAST and multi-model LLM judgments."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Dict, Iterable, List, Mapping, Sequence

from .base_judge import JudgeResult


@dataclass(frozen=True)
class ConsensusConfig:
    """Configuration for vote fusion and uncertainty calculations."""

    model_weights: Mapping[str, float] = field(default_factory=dict)
    sast_weight: float = 0.0
    vulnerability_threshold: float = 0.5

    def __post_init__(self) -> None:
        if self.sast_weight < 0.0:
            raise ValueError("sast_weight must be >= 0.0")
        if not 0.0 <= self.vulnerability_threshold <= 1.0:
            raise ValueError("vulnerability_threshold must be in [0.0, 1.0]")
        for model, weight in self.model_weights.items():
            if weight < 0.0:
                raise ValueError(f"model weight must be >= 0.0, got {model}={weight}")


@dataclass(frozen=True)
class ConsensusResult:
    """Final fused decision for one candidate vulnerability."""

    is_vulnerable: bool
    final_score: float
    uncertainty: float
    disagreement: bool
    majority_vote_ratio: float
    weighted_vote_score: float
    agreed_cwe: str
    supporting_models: List[str]


class ConsensusEngine:
    """Fuse multiple JudgeResult objects into one reproducible decision."""

    def __init__(self, config: ConsensusConfig | None = None) -> None:
        self.config = config or ConsensusConfig()

    def aggregate(
        self,
        judge_results: Sequence[JudgeResult],
        *,
        sast_confidence: float | None = None,
    ) -> ConsensusResult:
        """Compute majority vote, weighted confidence, and uncertainty."""
        if not judge_results and sast_confidence is None:
            raise ValueError("At least one judge result or sast_confidence is required")

        majority_vote_ratio = self._majority_vote_ratio(judge_results)
        weighted_vote_score = self._weighted_vote_score(judge_results)
        uncertainty = self._uncertainty_from_probability(weighted_vote_score)
        disagreement = self._is_disagreement(judge_results)

        final_score = weighted_vote_score
        if sast_confidence is not None:
            if not 0.0 <= sast_confidence <= 1.0:
                raise ValueError("sast_confidence must be in [0.0, 1.0]")
            llm_component = (1.0 - self.config.sast_weight) * weighted_vote_score
            sast_component = self.config.sast_weight * sast_confidence
            final_score = llm_component + sast_component

        agreed_cwe = self._majority_cwe(judge_results)
        supporting_models = [result.model_name for result in judge_results if result.is_vulnerable]

        return ConsensusResult(
            is_vulnerable=final_score >= self.config.vulnerability_threshold,
            final_score=final_score,
            uncertainty=uncertainty,
            disagreement=disagreement,
            majority_vote_ratio=majority_vote_ratio,
            weighted_vote_score=weighted_vote_score,
            agreed_cwe=agreed_cwe,
            supporting_models=supporting_models,
        )

    def _majority_vote_ratio(self, judge_results: Sequence[JudgeResult]) -> float:
        if not judge_results:
            return 0.0
        positives = sum(1 for result in judge_results if result.is_vulnerable)
        return positives / len(judge_results)

    def _weighted_vote_score(self, judge_results: Sequence[JudgeResult]) -> float:
        if not judge_results:
            return 0.0

        weighted_sum = 0.0
        total_weight = 0.0
        for result in judge_results:
            weight = self.config.model_weights.get(result.model_name, 1.0)
            probability = result.confidence if result.is_vulnerable else (1.0 - result.confidence)
            weighted_sum += weight * probability
            total_weight += weight

        if total_weight == 0.0:
            return 0.0
        return weighted_sum / total_weight

    def _is_disagreement(self, judge_results: Sequence[JudgeResult]) -> bool:
        if len(judge_results) < 2:
            return False
        decisions = {result.is_vulnerable for result in judge_results}
        return len(decisions) > 1

    def _majority_cwe(self, judge_results: Sequence[JudgeResult]) -> str:
        if not judge_results:
            return "UNKNOWN"
        cwe_counts: Dict[str, int] = {}
        for result in judge_results:
            cwe_counts[result.cwe] = cwe_counts.get(result.cwe, 0) + 1
        return max(cwe_counts.items(), key=lambda item: item[1])[0]

    def _uncertainty_from_probability(self, probability: float) -> float:
        bounded = min(max(probability, 1e-12), 1.0 - 1e-12)
        entropy = -(bounded * math.log2(bounded) + (1.0 - bounded) * math.log2(1.0 - bounded))
        return entropy
