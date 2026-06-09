"""Metrics used across benchmark and adversarial evaluation workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Sequence


@dataclass(frozen=True)
class ConfusionMatrix:
    """Confusion matrix for binary vulnerability detection outcomes."""

    tp: int
    fp: int
    tn: int
    fn: int

    @classmethod
    def from_predictions(
        cls,
        *,
        expected: Sequence[bool],
        predicted: Sequence[bool],
    ) -> "ConfusionMatrix":
        """Build confusion matrix from expected and predicted labels."""
        if len(expected) != len(predicted):
            raise ValueError("expected and predicted must have equal length")

        tp = fp = tn = fn = 0
        for exp, pred in zip(expected, predicted):
            if exp and pred:
                tp += 1
            elif exp and not pred:
                fn += 1
            elif not exp and pred:
                fp += 1
            else:
                tn += 1
        return cls(tp=tp, fp=fp, tn=tn, fn=fn)

    def to_dict(self) -> Dict[str, int]:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn}


@dataclass(frozen=True)
class BinaryClassificationMetrics:
    """Derived binary classification metrics for security detection benchmarking."""

    precision: float
    recall: float
    f1_score: float
    accuracy: float

    @classmethod
    def from_confusion_matrix(
        cls,
        matrix: ConfusionMatrix,
    ) -> "BinaryClassificationMetrics":
        """Compute precision, recall, F1, and accuracy from confusion matrix."""
        precision = matrix.tp / (matrix.tp + matrix.fp) if (matrix.tp + matrix.fp) else 0.0
        recall = matrix.tp / (matrix.tp + matrix.fn) if (matrix.tp + matrix.fn) else 0.0
        f1_score = (
            (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        )
        total = matrix.tp + matrix.fp + matrix.tn + matrix.fn
        accuracy = (matrix.tp + matrix.tn) / total if total else 0.0
        return cls(precision=precision, recall=recall, f1_score=f1_score, accuracy=accuracy)

    def to_dict(self) -> Dict[str, float]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "accuracy": self.accuracy,
        }
