"""Benchmark orchestration for multi-judge semantic security evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

from src.evaluation.benchmark_dataset import BenchmarkDataset, BenchmarkSample
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix

from .base_judge import BaseLLMJudge, JudgeResult
from .consensus_engine import ConsensusEngine, ConsensusResult


@dataclass(frozen=True)
class BenchmarkRunConfig:
    """Configuration for reproducible benchmark runs."""

    run_name: str
    output_directory: Path
    include_consensus: bool = True


@dataclass
class BenchmarkSampleResult:
    """Per-sample benchmark output used in downstream evaluation reports."""

    sample_id: str
    expected_is_vulnerable: bool
    judge_results: List[JudgeResult] = field(default_factory=list)
    consensus_result: ConsensusResult | None = None


@dataclass
class BenchmarkRunResult:
    """Aggregate benchmark result with metrics and machine-readable tables."""

    run_name: str
    created_at_utc: str
    sample_results: List[BenchmarkSampleResult]
    per_model_metrics: Dict[str, BinaryClassificationMetrics]
    consensus_metrics: BinaryClassificationMetrics | None


class BenchmarkRunner:
    """Execute benchmark datasets against one or more LLM judges."""

    def __init__(self, judges: Sequence[BaseLLMJudge], consensus_engine: ConsensusEngine) -> None:
        if not judges:
            raise ValueError("At least one judge is required")
        self.judges = list(judges)
        self.consensus_engine = consensus_engine

    def run(self, dataset: BenchmarkDataset, config: BenchmarkRunConfig) -> BenchmarkRunResult:
        """Run full benchmark pipeline and return aggregate run result."""
        sample_results: List[BenchmarkSampleResult] = []
        for sample in dataset.samples:
            judge_results = self._evaluate_sample(sample)
            consensus = self.consensus_engine.aggregate(judge_results) if config.include_consensus else None
            sample_results.append(
                BenchmarkSampleResult(
                    sample_id=sample.sample_id,
                    expected_is_vulnerable=sample.expected_is_vulnerable,
                    judge_results=judge_results,
                    consensus_result=consensus,
                )
            )

        per_model_metrics = self._calculate_per_model_metrics(sample_results)
        consensus_metrics = self._calculate_consensus_metrics(sample_results)

        run_result = BenchmarkRunResult(
            run_name=config.run_name,
            created_at_utc=datetime.now(timezone.utc).isoformat(),
            sample_results=sample_results,
            per_model_metrics=per_model_metrics,
            consensus_metrics=consensus_metrics,
        )
        self._write_outputs(run_result, config.output_directory)
        return run_result

    def _evaluate_sample(self, sample: BenchmarkSample) -> List[JudgeResult]:
        results: List[JudgeResult] = []
        for judge in self.judges:
            result = judge.analyze_code(
                code_snippet=sample.code,
                sast_findings=sample.sast_findings,
            )
            results.append(result)
        return results

    def _calculate_per_model_metrics(
        self,
        sample_results: Sequence[BenchmarkSampleResult],
    ) -> Dict[str, BinaryClassificationMetrics]:
        metrics_by_model: Dict[str, BinaryClassificationMetrics] = {}
        for judge in self.judges:
            expected = [result.expected_is_vulnerable for result in sample_results]
            predicted = [
                next(item for item in result.judge_results if item.model_name == judge.config.model_name).is_vulnerable
                for result in sample_results
            ]
            matrix = ConfusionMatrix.from_predictions(expected=expected, predicted=predicted)
            metrics_by_model[judge.config.model_name] = BinaryClassificationMetrics.from_confusion_matrix(matrix)
        return metrics_by_model

    def _calculate_consensus_metrics(
        self,
        sample_results: Sequence[BenchmarkSampleResult],
    ) -> BinaryClassificationMetrics | None:
        consensus_items = [result for result in sample_results if result.consensus_result is not None]
        if not consensus_items:
            return None

        expected = [item.expected_is_vulnerable for item in consensus_items]
        predicted = [bool(item.consensus_result and item.consensus_result.is_vulnerable) for item in consensus_items]
        matrix = ConfusionMatrix.from_predictions(expected=expected, predicted=predicted)
        return BinaryClassificationMetrics.from_confusion_matrix(matrix)

    def _write_outputs(self, run_result: BenchmarkRunResult, output_directory: Path) -> None:
        output_directory.mkdir(parents=True, exist_ok=True)

        summary_path = output_directory / "benchmark_summary.json"
        payload = {
            "run_name": run_result.run_name,
            "created_at_utc": run_result.created_at_utc,
            "per_model_metrics": {
                model: metrics.to_dict() for model, metrics in run_result.per_model_metrics.items()
            },
            "consensus_metrics": run_result.consensus_metrics.to_dict()
            if run_result.consensus_metrics
            else None,
            "samples": [
                {
                    "sample_id": sample.sample_id,
                    "expected_is_vulnerable": sample.expected_is_vulnerable,
                    "judge_results": [
                        {
                            "model_name": judge_result.model_name,
                            "is_vulnerable": judge_result.is_vulnerable,
                            "cwe": judge_result.cwe,
                            "severity": judge_result.severity,
                            "confidence": judge_result.confidence,
                            "latency_ms": judge_result.latency_ms,
                        }
                        for judge_result in sample.judge_results
                    ],
                    "consensus_result": {
                        "is_vulnerable": sample.consensus_result.is_vulnerable,
                        "final_score": sample.consensus_result.final_score,
                        "uncertainty": sample.consensus_result.uncertainty,
                        "disagreement": sample.consensus_result.disagreement,
                    }
                    if sample.consensus_result
                    else None,
                }
                for sample in run_result.sample_results
            ],
        }
        summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
