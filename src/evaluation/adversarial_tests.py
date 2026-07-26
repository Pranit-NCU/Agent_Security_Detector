"""Adversarial evaluation interfaces for semantic vulnerability judges."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Mapping, Sequence

from src.llm.base_judge import JudgeResult


class AdversarialTechnique(Enum):
    """Supported adversarial transformation categories."""

    MISLEADING_COMMENTS = "misleading_comments"
    PROMPT_INJECTION = "prompt_injection"
    VARIABLE_OBFUSCATION = "variable_obfuscation"
    LOGIC_OBFUSCATION = "logic_obfuscation"
    DEAD_CODE_CAMOUFLAGE = "dead_code_camouflage"


@dataclass(frozen=True)
class AdversarialCaseResult:
    """Result of evaluating one adversarial transformation case."""

    sample_id: str
    technique: AdversarialTechnique
    baseline_detected: bool
    adversarial_detected: bool
    hallucinated_vulnerability: bool


@dataclass(frozen=True)
class AdversarialSummary:
    """Aggregate robustness metrics across adversarial techniques."""

    detection_degradation: float
    robustness_score: float
    hallucination_frequency: float


class AdversarialEvaluator:
    """Compute robustness metrics from baseline and adversarial outcomes."""

    def summarize(self, results: Sequence[AdversarialCaseResult]) -> AdversarialSummary:
        """Summarize degradation, robustness, and hallucination frequencies."""
        if not results:
            raise ValueError("results must not be empty")

        baseline_hits = sum(1 for result in results if result.baseline_detected)
        adversarial_hits = sum(1 for result in results if result.adversarial_detected)

        baseline_rate = baseline_hits / len(results)
        adversarial_rate = adversarial_hits / len(results)
        degradation = max(0.0, baseline_rate - adversarial_rate)
        robustness_score = 1.0 - degradation
        hallucination_frequency = (
            sum(1 for result in results if result.hallucinated_vulnerability) / len(results)
        )

        return AdversarialSummary(
            detection_degradation=degradation,
            robustness_score=robustness_score,
            hallucination_frequency=hallucination_frequency,
        )
