"""Unit tests for dataset and metric evaluation framework contracts."""

from __future__ import annotations

import json
from pathlib import Path

from src.evaluation.benchmark_dataset import BenchmarkDataset, DifficultyLevel
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix


def test_confusion_metrics_computation() -> None:
    matrix = ConfusionMatrix.from_predictions(
        expected=[True, True, False, False],
        predicted=[True, False, True, False],
    )
    assert matrix.tp == 1
    assert matrix.fn == 1
    assert matrix.fp == 1
    assert matrix.tn == 1

    metrics = BinaryClassificationMetrics.from_confusion_matrix(matrix)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.f1_score == 0.5
    assert metrics.accuracy == 0.5


def test_dataset_loading(tmp_path: Path) -> None:
    dataset_payload = [
        {
            "sample_id": "s1",
            "code": "query = f'SELECT * FROM users WHERE id={user_id}'",
            "vulnerability_label": "SQL Injection",
            "cwe": "CWE-89",
            "expected_is_vulnerable": True,
            "difficulty": "hard",
            "source_metadata": {"source": "curated"},
            "sast_findings": [{"type": "SQL Injection", "confidence": 0.95}],
        },
        {
            "sample_id": "s2",
            "code": "cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
            "vulnerability_label": "None",
            "cwe": "CWE-89",
            "expected_is_vulnerable": False,
            "difficulty": "easy",
            "source_metadata": {"source": "curated"},
            "sast_findings": [],
        },
    ]
    dataset_path = tmp_path / "benchmark.json"
    dataset_path.write_text(json.dumps(dataset_payload), encoding="utf-8")

    dataset = BenchmarkDataset.from_json(dataset_path)
    assert dataset.name == "benchmark"
    assert len(dataset.samples) == 2
    assert len(dataset.vulnerable_samples()) == 1
    assert len(dataset.secure_samples()) == 1
    assert len(dataset.by_difficulty(DifficultyLevel.EASY)) == 1
