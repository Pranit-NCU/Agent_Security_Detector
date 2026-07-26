"""Dataset definitions and loaders for reproducible security benchmark experiments."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


class DifficultyLevel(Enum):
    """Difficulty levels for benchmark stratification."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    ADVERSARIAL = "adversarial"


@dataclass(frozen=True)
class BenchmarkSample:
    """Single labeled benchmark sample used for model and detector evaluation."""

    sample_id: str
    code: str
    vulnerability_label: str
    cwe: str
    expected_is_vulnerable: bool
    difficulty: DifficultyLevel
    source_metadata: Mapping[str, Any] = field(default_factory=dict)
    sast_findings: Sequence[Mapping[str, Any]] = field(default_factory=list)
    paired_sample_id: str | None = None

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError("sample_id is required")
        if not self.code.strip():
            raise ValueError("code must not be empty")
        if not self.vulnerability_label:
            raise ValueError("vulnerability_label is required")
        if not self.cwe:
            raise ValueError("cwe is required")


@dataclass(frozen=True)
class BenchmarkDataset:
    """Collection of benchmark samples with helper methods for filtering and analysis."""

    name: str
    samples: Sequence[BenchmarkSample]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("dataset name is required")
        if not self.samples:
            raise ValueError("dataset samples must not be empty")

    @classmethod
    def from_json(cls, path: Path, *, dataset_name: str | None = None) -> "BenchmarkDataset":
        """Load benchmark dataset from a JSON array file."""
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Dataset JSON must be an array")

        samples: List[BenchmarkSample] = []
        for entry in payload:
            if not isinstance(entry, dict):
                raise ValueError("Each dataset item must be an object")
            samples.append(_sample_from_mapping(entry))

        return cls(name=dataset_name or path.stem, samples=samples)

    def vulnerable_samples(self) -> List[BenchmarkSample]:
        """Return samples expected to be vulnerable."""
        return [sample for sample in self.samples if sample.expected_is_vulnerable]

    def secure_samples(self) -> List[BenchmarkSample]:
        """Return samples expected to be secure."""
        return [sample for sample in self.samples if not sample.expected_is_vulnerable]

    def by_difficulty(self, difficulty: DifficultyLevel) -> List[BenchmarkSample]:
        """Filter samples by difficulty level."""
        return [sample for sample in self.samples if sample.difficulty == difficulty]


def _sample_from_mapping(entry: Mapping[str, Any]) -> BenchmarkSample:
    difficulty = DifficultyLevel(str(entry["difficulty"]).lower())
    source_metadata = entry.get("source_metadata", {})
    sast_findings = entry.get("sast_findings", [])

    return BenchmarkSample(
        sample_id=str(entry["sample_id"]),
        code=str(entry["code"]),
        vulnerability_label=str(entry["vulnerability_label"]),
        cwe=str(entry["cwe"]),
        expected_is_vulnerable=bool(entry["expected_is_vulnerable"]),
        difficulty=difficulty,
        source_metadata=source_metadata if isinstance(source_metadata, dict) else {},
        sast_findings=sast_findings if isinstance(sast_findings, list) else [],
        paired_sample_id=str(entry["paired_sample_id"]) if entry.get("paired_sample_id") else None,
    )
