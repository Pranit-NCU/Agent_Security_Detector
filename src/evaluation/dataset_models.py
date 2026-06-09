"""Core data models for the Phase 2 benchmark dataset framework.

Design Rationale
----------------
CodeSample is the atomic unit of this framework, analogous to the existing
BenchmarkSample but enriched with four dimensions required for dissertation rigor:

  ProvenanceInfo
    Records the exact origin of every sample (source_url, commit, acquisition_date,
    license).  Without this, experiment results cannot be independently reproduced
    because datasets are externally hosted and subject to version drift.

  DatasetSplit
    Assigns every sample to TRAIN / VALIDATION / TEST deterministically via a
    SHA-256 hash of the sample_id.  Even though no ML model is being trained,
    strict test/validation separation prevents experimental contamination:
    samples used to tune detection thresholds must not appear in the final
    reported benchmark.

  source_dataset
    Identifies which dataset contributed a sample so that multi-dataset statistics
    and per-source breakdown tables can be generated for dissertation figures.

  difficulty (DifficultyLevel)
    Stratifies samples for fine-grained analysis of detection difficulty.  Reuses
    the existing DifficultyLevel enum from benchmark_dataset.py to remain
    compatible with BenchmarkRunner and all downstream evaluation code.

CodePair is a FIRST-CLASS CONCEPT, not a convenience container.  The dissertation's
primary evaluation question is:

    "Can a model correctly distinguish vulnerable code from its patched version?"

This is structurally enforced: CodePair.__post_init__ rejects construction unless
  - vulnerable_sample.is_vulnerable is True
  - fixed_sample.is_vulnerable is False
  - Both samples share the same CWE

DatasetBundle is named deliberately to avoid collision with the existing
BenchmarkDataset in benchmark_dataset.py.  The bridge method to_benchmark_samples()
converts the entire bundle to the format expected by BenchmarkRunner with no
changes to existing evaluation code.

Integration Points
------------------
  CodeSample.to_benchmark_sample()        → BenchmarkRunner.run()
  DatasetBundle.to_benchmark_samples()    → BenchmarkRunner.run()
  CodePair.vulnerable_sample/.fixed_sample → Experiment E discrimination evaluation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from .benchmark_dataset import BenchmarkSample, DifficultyLevel  # noqa: F401 – re-exported

__all__ = [
    "DatasetSplit",
    "ProvenanceInfo",
    "DifficultyLevel",  # re-exported for single-import convenience
    "CodeSample",
    "FixType",
    "CodePair",
    "DatasetBundle",
]


# ---------------------------------------------------------------------------
# DatasetSplit
# ---------------------------------------------------------------------------


class DatasetSplit(Enum):
    """Partition assignment for benchmark contamination prevention.

    Splits are assigned deterministically using a SHA-256 hash of the sample_id
    so that every loader produces identical splits regardless of traversal order
    or operating system.  Default ratios: 70 % train, 15 % validation, 15 % test.

    Although no ML model is being trained, the TEST split is the only split used
    for reported dissertation benchmark figures.  VALIDATION is reserved for
    detector threshold tuning and sanity checks.  TRAIN is available for any
    future learning-based extensions.
    """

    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


# ---------------------------------------------------------------------------
# ProvenanceInfo
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceInfo:
    """Origin metadata required for full dissertation reproducibility.

    Every CodeSample must carry a ProvenanceInfo so that any reader of the
    dissertation can locate, download, and re-ingest the exact data that
    produced a reported result.

    Attributes:
        source_url:        Canonical download URL for the originating dataset.
        source_commit:     Git commit hash or dataset version tag at time of
                           acquisition.  Empty string when not applicable
                           (e.g., NIST Juliet which uses versioned ZIP archives).
        acquisition_date:  ISO-8601 date string (YYYY-MM-DD) recording when the
                           data was ingested.  Set automatically by the loader.
        license:           SPDX license identifier or short description (e.g.,
                           "Public Domain", "MIT", "CC-BY-4.0").
    """

    source_url: str
    source_commit: str
    acquisition_date: str  # ISO-8601: YYYY-MM-DD
    license: str

    def __post_init__(self) -> None:
        if not self.source_url:
            raise ValueError("ProvenanceInfo.source_url is required")
        if not self.license:
            raise ValueError("ProvenanceInfo.license is required")

    def to_dict(self) -> Dict[str, str]:
        return {
            "source_url": self.source_url,
            "source_commit": self.source_commit,
            "acquisition_date": self.acquisition_date,
            "license": self.license,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProvenanceInfo":
        return cls(
            source_url=str(data.get("source_url", "unknown")),
            source_commit=str(data.get("source_commit", "")),
            acquisition_date=str(data.get("acquisition_date", "")),
            license=str(data.get("license", "unknown")),
        )

    @classmethod
    def unknown(cls) -> "ProvenanceInfo":
        """Return a sentinel ProvenanceInfo for synthetic or test samples."""
        return cls(
            source_url="unknown",
            source_commit="",
            acquisition_date="",
            license="unknown",
        )


# ---------------------------------------------------------------------------
# CodeSample
# ---------------------------------------------------------------------------


@dataclass
class CodeSample:
    """Atomic benchmark unit with full provenance and experimental metadata.

    Fields beyond BenchmarkSample
    ------------------------------
    source_dataset    Identifies which ingested dataset contributed this sample.
                      Used for multi-dataset comparative statistics.
    language          Programming language of the code snippet.
    severity          Vulnerability severity: "critical" / "high" / "medium" /
                      "low" / "info" / "unknown".  Normalised by DatasetNormalizer.
    split             DatasetSplit assignment (deterministic, hash-based).
    provenance        Full origin traceability for reproducibility.
    metadata          Free-form dict for loader-specific fields (e.g.,
                      juliet_file, pair_sample_id, project, commit_id).

    Bridge method
    -------------
    to_benchmark_sample() converts this CodeSample to a BenchmarkSample so
    that any List[CodeSample] can feed directly into the existing BenchmarkRunner
    pipeline without modifying a single line of existing code.
    """

    sample_id: str
    source_dataset: str
    language: str
    code: str
    is_vulnerable: bool
    cwe: str
    severity: str
    difficulty: DifficultyLevel
    split: DatasetSplit
    provenance: ProvenanceInfo
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.sample_id:
            raise ValueError("CodeSample.sample_id is required")
        if not self.code.strip():
            raise ValueError(f"CodeSample '{self.sample_id}': code must not be empty")
        if not self.cwe:
            raise ValueError(f"CodeSample '{self.sample_id}': cwe is required")
        if not self.source_dataset:
            raise ValueError(f"CodeSample '{self.sample_id}': source_dataset is required")
        if not self.language:
            raise ValueError(f"CodeSample '{self.sample_id}': language is required")

    # ------------------------------------------------------------------
    # Bridge adapter
    # ------------------------------------------------------------------

    def to_benchmark_sample(self) -> BenchmarkSample:
        """Convert to BenchmarkSample for direct use with BenchmarkRunner.

        This is the primary integration point between the new dataset
        framework and the existing Phase 2 evaluation infrastructure.
        No existing code needs to be modified.

        The source_metadata dict carries all dataset-layer fields so
        that downstream reporters can reconstruct provenance from the
        BenchmarkSample when needed.
        """
        return BenchmarkSample(
            sample_id=self.sample_id,
            code=self.code,
            vulnerability_label=self.cwe if self.is_vulnerable else "None",
            cwe=self.cwe,
            expected_is_vulnerable=self.is_vulnerable,
            difficulty=self.difficulty,
            source_metadata={
                "source_dataset": self.source_dataset,
                "language": self.language,
                "severity": self.severity,
                "split": self.split.value,
                "provenance": self.provenance.to_dict(),
                **self.metadata,
            },
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "source_dataset": self.source_dataset,
            "language": self.language,
            "code": self.code,
            "is_vulnerable": self.is_vulnerable,
            "cwe": self.cwe,
            "severity": self.severity,
            "difficulty": self.difficulty.value,
            "split": self.split.value,
            "provenance": self.provenance.to_dict(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CodeSample":
        return cls(
            sample_id=str(data["sample_id"]),
            source_dataset=str(data["source_dataset"]),
            language=str(data["language"]),
            code=str(data["code"]),
            is_vulnerable=bool(data["is_vulnerable"]),
            cwe=str(data["cwe"]),
            severity=str(data.get("severity", "unknown")),
            difficulty=DifficultyLevel(str(data.get("difficulty", "medium")).lower()),
            split=DatasetSplit(str(data.get("split", "test")).lower()),
            provenance=ProvenanceInfo.from_dict(data.get("provenance", {})),
            metadata=dict(data.get("metadata", {})),
        )


# ---------------------------------------------------------------------------
# FixType
# ---------------------------------------------------------------------------


class FixType(Enum):
    """Semantic classification of how a vulnerability was remediated.

    Used in Experiment E (vulnerable vs fixed discrimination) to categorise
    the nature of the applied fix.  Enables stratified analysis: e.g., "are
    PARAMETER_BINDING fixes harder for detectors to recognise than API_REPLACEMENT
    fixes?"

    Juliet good() functions typically fall into PARAMETER_BINDING, API_REPLACEMENT,
    or LOGIC_CORRECTION.  DiverseVul func_after patches cover all categories.
    """

    PARAMETER_BINDING = "parameter_binding"  # SQL parameterisation, prepared statements
    INPUT_VALIDATION = "input_validation"  # sanitisation, escaping, allow-listing
    API_REPLACEMENT = "api_replacement"  # replace unsafe API with safe alternative
    LOGIC_CORRECTION = "logic_correction"  # fix flawed control flow or state check
    BOUNDS_CHECK = "bounds_check"  # add bounds, null, or length checks
    AUTHENTICATION = "authentication"  # add or strengthen authentication check
    CRYPTOGRAPHY = "cryptography"  # upgrade or replace cryptographic algorithm
    UNKNOWN = "unknown"  # fix type could not be determined from metadata


# ---------------------------------------------------------------------------
# CodePair
# ---------------------------------------------------------------------------


@dataclass
class CodePair:
    """First-class vulnerable ↔ fixed code pair for Experiment E.

    CodePair is the primary evaluation unit for the dissertation's core
    research question.  It is not merely a container: construction fails
    unless the following integrity constraints are satisfied:

        1. vulnerable_sample.is_vulnerable is True
        2. fixed_sample.is_vulnerable is False
        3. vulnerable_sample.cwe == fixed_sample.cwe
        4. pair.cwe == vulnerable_sample.cwe

    These constraints guarantee that all downstream evaluation code can
    treat (vulnerable_sample, fixed_sample) as a semantically aligned pair.

    Pair Sources
    ------------
    Juliet:      bad() → vulnerable_sample;  good() → fixed_sample.
                 Both extracted from the same test-case file.
    DiverseVul:  func_before → vulnerable_sample; func_after → fixed_sample.
                 Both extracted from the same CVE fix commit record.
    Synthetic:   Manually curated pairs.
    """

    pair_id: str
    vulnerable_sample: CodeSample
    fixed_sample: CodeSample
    cwe: str
    fix_type: FixType
    source_dataset: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.pair_id:
            raise ValueError("CodePair.pair_id is required")
        if not self.vulnerable_sample.is_vulnerable:
            raise ValueError(
                f"CodePair '{self.pair_id}': vulnerable_sample "
                f"'{self.vulnerable_sample.sample_id}' must have is_vulnerable=True"
            )
        if self.fixed_sample.is_vulnerable:
            raise ValueError(
                f"CodePair '{self.pair_id}': fixed_sample "
                f"'{self.fixed_sample.sample_id}' must have is_vulnerable=False"
            )
        if self.vulnerable_sample.cwe != self.fixed_sample.cwe:
            raise ValueError(
                f"CodePair '{self.pair_id}': CWE mismatch — "
                f"vulnerable={self.vulnerable_sample.cwe}, "
                f"fixed={self.fixed_sample.cwe}"
            )
        if self.cwe != self.vulnerable_sample.cwe:
            raise ValueError(
                f"CodePair '{self.pair_id}': pair CWE ({self.cwe}) does not match "
                f"sample CWE ({self.vulnerable_sample.cwe})"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "vulnerable_sample": self.vulnerable_sample.to_dict(),
            "fixed_sample": self.fixed_sample.to_dict(),
            "cwe": self.cwe,
            "fix_type": self.fix_type.value,
            "source_dataset": self.source_dataset,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CodePair":
        return cls(
            pair_id=str(data["pair_id"]),
            vulnerable_sample=CodeSample.from_dict(data["vulnerable_sample"]),
            fixed_sample=CodeSample.from_dict(data["fixed_sample"]),
            cwe=str(data["cwe"]),
            fix_type=FixType(str(data.get("fix_type", "unknown"))),
            source_dataset=str(data["source_dataset"]),
            metadata=dict(data.get("metadata", {})),
        )


# ---------------------------------------------------------------------------
# DatasetBundle
# ---------------------------------------------------------------------------


@dataclass
class DatasetBundle:
    """Top-level container for CodeSamples and CodePairs.

    Deliberately named DatasetBundle (not BenchmarkDataset) to avoid collision
    with the existing BenchmarkDataset in benchmark_dataset.py which is consumed
    by BenchmarkRunner and the existing test suite.

    The bundle is the primary argument to:
        - DatasetValidator.validate()
        - DatasetStatistics.compute()
        - PairGenerator.generate_pairs()
        - DatasetNormalizer.normalize_bundle()

    All six dissertation experiments are supported:

        Experiments A–D  via to_benchmark_samples() → BenchmarkRunner.run()
        Experiment E     via self.pairs (vulnerable vs fixed discrimination)
        Experiment F     via metadata["adversarial_variants"] on each sample

    Filtering helpers return new lists (not in-place mutations) so the bundle
    remains a stable, reproducible source of truth throughout a benchmark run.
    """

    name: str
    samples: List[CodeSample] = field(default_factory=list)
    pairs: List[CodePair] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("DatasetBundle.name is required")

    # ------------------------------------------------------------------
    # Sample filters
    # ------------------------------------------------------------------

    def vulnerable_samples(self) -> List[CodeSample]:
        """Return all samples with is_vulnerable=True."""
        return [s for s in self.samples if s.is_vulnerable]

    def secure_samples(self) -> List[CodeSample]:
        """Return all samples with is_vulnerable=False."""
        return [s for s in self.samples if not s.is_vulnerable]

    def by_split(self, split: DatasetSplit) -> List[CodeSample]:
        """Return samples assigned to the given DatasetSplit."""
        return [s for s in self.samples if s.split == split]

    def by_difficulty(self, difficulty: DifficultyLevel) -> List[CodeSample]:
        """Return samples at the given DifficultyLevel."""
        return [s for s in self.samples if s.difficulty == difficulty]

    def by_cwe(self, cwe: str) -> List[CodeSample]:
        """Return samples matching the given CWE identifier."""
        return [s for s in self.samples if s.cwe == cwe]

    def by_source(self, source_dataset: str) -> List[CodeSample]:
        """Return samples originating from the named source dataset."""
        return [s for s in self.samples if s.source_dataset == source_dataset]

    def by_language(self, language: str) -> List[CodeSample]:
        """Return samples in the given programming language."""
        return [s for s in self.samples if s.language == language]

    # ------------------------------------------------------------------
    # Pair filters
    # ------------------------------------------------------------------

    def pairs_by_cwe(self, cwe: str) -> List[CodePair]:
        """Return pairs matching the given CWE identifier."""
        return [p for p in self.pairs if p.cwe == cwe]

    def pairs_by_fix_type(self, fix_type: FixType) -> List[CodePair]:
        """Return pairs with the given FixType."""
        return [p for p in self.pairs if p.fix_type == fix_type]

    def pairs_by_source(self, source_dataset: str) -> List[CodePair]:
        """Return pairs from the given source dataset."""
        return [p for p in self.pairs if p.source_dataset == source_dataset]

    # ------------------------------------------------------------------
    # Bridge to existing evaluation infrastructure
    # ------------------------------------------------------------------

    def to_benchmark_samples(self) -> List[BenchmarkSample]:
        """Convert all CodeSamples to BenchmarkSamples for BenchmarkRunner.

        This is the zero-modification bridge to the existing Phase 2
        evaluation pipeline.  BenchmarkRunner.run() accepts the return
        value of this method directly.
        """
        return [s.to_benchmark_sample() for s in self.samples]

    # ------------------------------------------------------------------
    # Bundle operations
    # ------------------------------------------------------------------

    def merge(self, other: "DatasetBundle") -> "DatasetBundle":
        """Return a new DatasetBundle combining samples and pairs from both.

        Sample-level deduplication is not performed here; use
        DatasetValidator to detect and remove duplicates after merging.
        """
        return DatasetBundle(
            name=f"{self.name}+{other.name}",
            samples=list(self.samples) + list(other.samples),
            pairs=list(self.pairs) + list(other.pairs),
        )

    # ------------------------------------------------------------------
    # Inventory helpers
    # ------------------------------------------------------------------

    def sample_count(self) -> int:
        return len(self.samples)

    def pair_count(self) -> int:
        return len(self.pairs)

    def unique_cwes(self) -> List[str]:
        return sorted({s.cwe for s in self.samples})

    def unique_languages(self) -> List[str]:
        return sorted({s.language for s in self.samples})

    def unique_sources(self) -> List[str]:
        return sorted({s.source_dataset for s in self.samples})

    def unique_difficulties(self) -> List[DifficultyLevel]:
        return sorted({s.difficulty for s in self.samples}, key=lambda d: d.value)
