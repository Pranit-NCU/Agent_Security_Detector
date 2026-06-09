"""Evaluation components for benchmarking hybrid SAST + LLM detection."""

from .benchmark_dataset import BenchmarkDataset, BenchmarkSample, DifficultyLevel
from .metrics import BinaryClassificationMetrics, ConfusionMatrix

# Phase 2 — benchmark dataset framework
from .dataset_models import (
    CodePair,
    CodeSample,
    DatasetBundle,
    DatasetSplit,
    FixType,
    ProvenanceInfo,
)
from .dataset_loaders import (
    AbstractDatasetLoader,
    BigVulDatasetLoader,
    DiverseVulDatasetLoader,
    JulietDatasetLoader,
    LoaderConfig,
    SyntheticDatasetLoader,
    get_loader,
)
from .dataset_normalizer import DatasetNormalizer

__all__ = [
    # Phase 1 — unchanged
    "BenchmarkDataset",
    "BenchmarkSample",
    "DifficultyLevel",
    "BinaryClassificationMetrics",
    "ConfusionMatrix",
    # Phase 2 — data models
    "CodePair",
    "CodeSample",
    "DatasetBundle",
    "DatasetSplit",
    "FixType",
    "ProvenanceInfo",
    # Phase 2 — loaders
    "AbstractDatasetLoader",
    "BigVulDatasetLoader",
    "DiverseVulDatasetLoader",
    "JulietDatasetLoader",
    "LoaderConfig",
    "SyntheticDatasetLoader",
    "get_loader",
    # Phase 2 — normaliser
    "DatasetNormalizer",
]
