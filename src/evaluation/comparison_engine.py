"""Comparison engine for evaluating detector strategy variants."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Sequence

from .metrics import BinaryClassificationMetrics


@dataclass(frozen=True)
class StrategyComparison:
    """Named strategy metrics and analysis annotations."""

    strategy_name: str
    metrics: BinaryClassificationMetrics
    false_positive_rate: float
    disagreement_rate: float


class ComparisonEngine:
    """Build ranked comparisons across multiple detection strategies."""

    def compare(
        self,
        strategy_metrics: Mapping[str, BinaryClassificationMetrics],
        *,
        false_positive_rates: Mapping[str, float] | None = None,
        disagreement_rates: Mapping[str, float] | None = None,
    ) -> Sequence[StrategyComparison]:
        """Return ranked strategy rows sorted by F1 then precision then recall."""
        fp_rates = false_positive_rates or {}
        dg_rates = disagreement_rates or {}

        rows = [
            StrategyComparison(
                strategy_name=name,
                metrics=metrics,
                false_positive_rate=float(fp_rates.get(name, 0.0)),
                disagreement_rate=float(dg_rates.get(name, 0.0)),
            )
            for name, metrics in strategy_metrics.items()
        ]

        return sorted(
            rows,
            key=lambda row: (row.metrics.f1_score, row.metrics.precision, row.metrics.recall),
            reverse=True,
        )
