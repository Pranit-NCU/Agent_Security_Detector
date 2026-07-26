"""Dataset loaders for multi-source vulnerability benchmark ingestion.

Design Rationale
----------------
Every loader inherits from AbstractDatasetLoader which enforces a three-method
contract:

    load()              Ingest raw data and return List[CodeSample].
    validate_source()   Check that the expected files/directories exist on disk
                        before attempting to parse them.

LoaderConfig decouples configuration from implementation:
  - No paths are hardcoded in any loader.
  - split_ratios controls deterministic TEST / VALIDATION / TRAIN assignment via
    SHA-256 hash of sample_id (reproducible across platforms and Python versions).
  - max_samples, cwe_filter, language_filter allow lightweight subsetting during
    development without modifying loader logic.
  - acquisition_date is recorded automatically (today's date) for provenance unless
    overridden.
  - extra carries loader-specific flags (e.g., use_huggingface for DiverseVul).

Dataset priorities
------------------
  Tier 1  JulietDatasetLoader     NIST Juliet Test Suite (C/C++/Java)
  Tier 2  DiverseVulDatasetLoader DiverseVul (real-world C/C++ CVEs)
  Tier 3  SyntheticDatasetLoader  Curated synthetic samples (JSON)
  Tier 4  Adversarial variants    Generated at evaluation time (not a loader)
  Opt.    BigVulDatasetLoader     Stub — documented but not implemented

Pair metadata convention
------------------------
Loaders that can generate pairs (Juliet, DiverseVul) embed two keys in the
CodeSample.metadata dict so that PairGenerator can match them later:

    "pair_sample_id"          sample_id of the counterpart sample
    "<dataset>_function_type" "bad"/"good" (Juliet) or "func_before"/"func_after"

This avoids coupling the loader to PairGenerator while still making the
relationship explicit and machine-readable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .benchmark_dataset import DifficultyLevel
from .dataset_models import (
    CodeSample,
    DatasetSplit,
    FixType,
    ProvenanceInfo,
)

LOGGER = logging.getLogger(__name__)

__all__ = [
    "LoaderConfig",
    "AbstractDatasetLoader",
    "JulietDatasetLoader",
    "DiverseVulDatasetLoader",
    "SyntheticDatasetLoader",
    "BigVulDatasetLoader",
    "get_loader",
]


# ---------------------------------------------------------------------------
# LoaderConfig
# ---------------------------------------------------------------------------


@dataclass
class LoaderConfig:
    """Immutable configuration for any AbstractDatasetLoader.

    Attributes:
        data_dir:          Root directory containing the raw dataset files.
                           May be None only for loaders that fetch data from a
                           remote source (e.g., DiverseVul via HuggingFace).
        split_ratios:      Proportion of samples assigned to each split.
                           Must sum to 1.0.  Default: 70 % train, 15 % val, 15 % test.
        max_samples:       Hard cap on the number of CodeSamples returned by load().
                           Useful for rapid iteration during development.  None = no cap.
        cwe_filter:        If set, only samples whose normalised CWE appears in this
                           list are returned.  None = include all CWEs.
        language_filter:   If set, only samples in these languages are returned.
                           None = include all languages.
        acquisition_date:  ISO-8601 date (YYYY-MM-DD) recorded in ProvenanceInfo.
                           Defaults to today.
        extra:             Loader-specific settings.  Currently recognised keys:
                           - "use_huggingface" (bool, DiverseVulDatasetLoader only)
    """

    data_dir: Optional[Path]
    split_ratios: Dict[str, float] = field(
        default_factory=lambda: {"train": 0.70, "validation": 0.15, "test": 0.15}
    )
    max_samples: Optional[int] = None
    cwe_filter: Optional[List[str]] = None
    language_filter: Optional[List[str]] = None
    acquisition_date: str = field(default_factory=lambda: date.today().isoformat())
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        total = sum(self.split_ratios.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"LoaderConfig.split_ratios must sum to 1.0, got {total:.6f}"
            )
        if self.max_samples is not None and self.max_samples <= 0:
            raise ValueError("LoaderConfig.max_samples must be a positive integer")


# ---------------------------------------------------------------------------
# AbstractDatasetLoader
# ---------------------------------------------------------------------------


class AbstractDatasetLoader(ABC):
    """Base class for all dataset loaders.

    Subclasses implement load() and validate_source().  The helper methods
    _assign_split() and _make_provenance() are inherited and should be called
    from load() to ensure consistent provenance and split assignment across
    all loaders.
    """

    def __init__(self, config: LoaderConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def load(self) -> List[CodeSample]:
        """Ingest the dataset and return a list of CodeSamples.

        Raises:
            FileNotFoundError: If validate_source() would return False.
            ValueError:        If the data file is malformed.
        """

    @abstractmethod
    def validate_source(self) -> bool:
        """Return True if the expected data files/directories are present.

        This is a lightweight existence check only; it does not parse data.
        Call this before load() to surface configuration errors early.
        """

    @property
    @abstractmethod
    def dataset_name(self) -> str:
        """Short canonical name used in sample_id prefixes and statistics."""

    @property
    @abstractmethod
    def source_url(self) -> str:
        """Canonical download URL documented in ProvenanceInfo."""

    @property
    @abstractmethod
    def license(self) -> str:
        """SPDX license identifier or short description."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _assign_split(self, sample_id: str) -> DatasetSplit:
        """Deterministically assign a DatasetSplit using SHA-256 of sample_id.

        The assignment is stable: the same sample_id always maps to the same
        split regardless of when or where load() is called.

        Bucket arithmetic:
            bucket = SHA-256(sample_id) first 8 hex digits (mod 100)
            [0, train_pct)              → TRAIN
            [train_pct, train+val_pct)  → VALIDATION
            else                        → TEST
        """
        bucket = int(hashlib.sha256(sample_id.encode("utf-8")).hexdigest()[:8], 16) % 100
        train_pct = int(self.config.split_ratios.get("train", 0.70) * 100)
        val_pct = int(self.config.split_ratios.get("validation", 0.15) * 100)
        if bucket < train_pct:
            return DatasetSplit.TRAIN
        if bucket < train_pct + val_pct:
            return DatasetSplit.VALIDATION
        return DatasetSplit.TEST

    def _make_provenance(self, *, commit: str = "") -> ProvenanceInfo:
        """Build a ProvenanceInfo using loader metadata and config acquisition_date."""
        return ProvenanceInfo(
            source_url=self.source_url,
            source_commit=commit,
            acquisition_date=self.config.acquisition_date,
            license=self.license,
        )

    def _is_within_sample_cap(self, count: int) -> bool:
        """Return True if another sample may be added given max_samples."""
        return self.config.max_samples is None or count < self.config.max_samples

    def _passes_filters(self, cwe: str, language: str) -> bool:
        """Return True if the sample passes cwe_filter and language_filter."""
        if self.config.cwe_filter and cwe not in self.config.cwe_filter:
            return False
        if self.config.language_filter and language not in self.config.language_filter:
            return False
        return True


# ---------------------------------------------------------------------------
# JulietDatasetLoader
# ---------------------------------------------------------------------------


class JulietDatasetLoader(AbstractDatasetLoader):
    """Loader for the NIST Juliet Test Suite (Tier 1 primary dataset).

    Dataset overview
    ----------------
    The Juliet Test Suite is a collection of synthetic C/C++ and Java test cases
    purpose-built for evaluating static analysis tools.  Each test-case file
    contains two semantically paired functions:

        bad()   A deliberately vulnerable implementation of a specific CWE pattern.
        good()  A correctly fixed implementation of the same pattern.

    This built-in pairing makes Juliet the most controlled source of
    vulnerable ↔ fixed sample pairs in the dissertation framework.

    Download sources
    ----------------
    C/C++ (118 CWEs, ~64 000 test cases):
        https://samate.nist.gov/SARD/test-suites/112
    Java  (112 CWEs, ~28 000 test cases):
        https://samate.nist.gov/SARD/test-suites/111

    License: Public Domain (US Government work — not subject to copyright).

    Expected directory structure
    ----------------------------
    The loader walks data_dir recursively and identifies any .c / .cpp / .java
    file whose name begins with the pattern CWE<N>_:

        <data_dir>/
            C/testcases/CWE89_SQL_Injection/
                CWE89_SQL_Injection__char_connect_socket_01.c
                CWE89_SQL_Injection__char_connect_socket_02.c
                ...
            Java/src/testcases/CWE89_SQL_Injection/
                CWE89_SQL_Injection__connect_tcp_01.java

    A flat directory is equally valid; the exact subdirectory layout does not matter.

    CWE extraction
    --------------
    Parsed from the filename prefix:  CWE89_SQL_Injection__... → "CWE-89".

    Difficulty mapping (variant number)
    ------------------------------------
    The two-digit suffix before the file extension encodes the test variant:

        01           → EASY   (base/direct case; no control-flow indirection)
        02 – 10      → MEDIUM (constant folding, global/instance variables,
                               simple control-flow variants)
        11+          → HARD   (function pointers, data-flow through function
                               calls, complex inter-procedural paths)

    Pair metadata
    -------------
    Each bad() sample's metadata contains:
        pair_sample_id          = "juliet_{file_stem}_good"
        juliet_function_type    = "bad"

    Each good() sample's metadata contains:
        pair_sample_id          = "juliet_{file_stem}_bad"
        juliet_function_type    = "good"

    PairGenerator uses these keys to assemble CodePair objects.
    """

    # Mapping from file extension to canonical language string
    _LANG_MAP: Dict[str, str] = {".c": "c", ".cpp": "cpp", ".java": "java"}

    # Regex patterns for CWE and variant extraction
    _CWE_PATTERN = re.compile(r"^CWE(\d+)_", re.IGNORECASE)
    _VARIANT_PATTERN = re.compile(r"_(\d{2,3})\.(c|cpp|java)$", re.IGNORECASE)

    # Function signature patterns used by _extract_function_body()
    # Each pattern matches the signature portion up to (but not including) the '{'.
    # The '{' is located separately to handle both same-line and next-line styles.
    _BAD_FUNC_SIGNATURES: List[str] = [
        r"\bvoid\s+bad\s*\([^)]*\)",           # C/C++: void bad(void)
        r"\bpublic\s+void\s+bad\s*\([^)]*\)",  # Java:  public void bad()
    ]
    # Ordered by preference: good() is the entry point; fall back to variants
    _GOOD_FUNC_SIGNATURES: List[str] = [
        r"\bvoid\s+good\s*\(\s*(?:void\s*)?\)",          # C/C++: void good(void)
        r"\bpublic\s+void\s+good\s*\([^)]*\)",            # Java:  public void good()
        r"\bvoid\s+goodG2B\s*\([^)]*\)",                  # C/C++ variant
        r"\bvoid\s+goodB2G\s*\([^)]*\)",                  # C/C++ variant
        r"\bstatic\s+void\s+good1\s*\([^)]*\)",           # C/C++ helper
        r"\bprivate\s+void\s+good1\s*\([^)]*\)",          # Java  helper
        r"\bvoid\s+good1\s*\([^)]*\)",                     # generic helper
    ]

    @property
    def dataset_name(self) -> str:
        return "juliet"

    @property
    def source_url(self) -> str:
        return "https://samate.nist.gov/SARD/test-suites/112"

    @property
    def license(self) -> str:
        return "Public Domain"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def validate_source(self) -> bool:
        """Return True if data_dir exists and contains at least one Juliet file."""
        if self.config.data_dir is None or not self.config.data_dir.exists():
            return False
        try:
            first = next(self._iter_juliet_files())
            return first is not None
        except StopIteration:
            return False

    def load(self) -> List[CodeSample]:
        """Walk data_dir recursively and extract bad()/good() function bodies.

        Returns:
            List[CodeSample] — one per successfully extracted function body.
            Files where neither bad() nor good() can be extracted are skipped
            with a DEBUG log message.

        Raises:
            FileNotFoundError: If data_dir does not exist or contains no
                               Juliet-pattern files.
        """
        if not self.validate_source():
            raise FileNotFoundError(
                f"Juliet data directory not found or contains no CWE*.c/cpp/java files: "
                f"{self.config.data_dir}\n"
                "Download from:\n"
                "  C/C++: https://samate.nist.gov/SARD/test-suites/112\n"
                "  Java:  https://samate.nist.gov/SARD/test-suites/111"
            )

        allowed_langs = set(
            lang.lower() for lang in (self.config.language_filter or ["c", "cpp", "java"])
        )

        samples: List[CodeSample] = []
        count = 0

        for filepath in sorted(self._iter_juliet_files()):
            if not self._is_within_sample_cap(count):
                break

            lang = self._LANG_MAP.get(filepath.suffix.lower(), "unknown")
            if lang not in allowed_langs:
                continue

            cwe = self._extract_cwe_from_filename(filepath.name)
            if not self._passes_filters(cwe, lang):
                continue

            variant = self._extract_variant(filepath.name)
            difficulty = self._variant_to_difficulty(variant)

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                LOGGER.debug("Skipping %s — cannot read: %s", filepath, exc)
                continue

            file_stem = filepath.stem

            # --- bad() → vulnerable sample ----------------------------------
            bad_body = self._extract_function_body(content, self._BAD_FUNC_SIGNATURES)
            if bad_body and self._is_within_sample_cap(count):
                bad_id = f"juliet_{file_stem}_bad"
                samples.append(
                    CodeSample(
                        sample_id=bad_id,
                        source_dataset="juliet",
                        language=lang,
                        code=bad_body,
                        is_vulnerable=True,
                        cwe=cwe,
                        severity="unknown",  # DatasetNormalizer infers from CWE
                        difficulty=difficulty,
                        split=self._assign_split(bad_id),
                        provenance=self._make_provenance(),
                        metadata={
                            "juliet_file": file_stem,
                            "juliet_function_type": "bad",
                            "juliet_variant": variant,
                            "original_filename": filepath.name,
                            "pair_sample_id": f"juliet_{file_stem}_good",
                        },
                    )
                )
                count += 1
            elif not bad_body:
                LOGGER.debug("No bad() found in %s", filepath.name)

            # --- good() → fixed sample --------------------------------------
            good_body = self._extract_function_body(content, self._GOOD_FUNC_SIGNATURES)
            if good_body and self._is_within_sample_cap(count):
                good_id = f"juliet_{file_stem}_good"
                samples.append(
                    CodeSample(
                        sample_id=good_id,
                        source_dataset="juliet",
                        language=lang,
                        code=good_body,
                        is_vulnerable=False,
                        cwe=cwe,
                        severity="unknown",
                        difficulty=difficulty,
                        split=self._assign_split(good_id),
                        provenance=self._make_provenance(),
                        metadata={
                            "juliet_file": file_stem,
                            "juliet_function_type": "good",
                            "juliet_variant": variant,
                            "original_filename": filepath.name,
                            "pair_sample_id": f"juliet_{file_stem}_bad",
                        },
                    )
                )
                count += 1
            elif not good_body:
                LOGGER.debug("No good() found in %s", filepath.name)

        LOGGER.info(
            "JulietDatasetLoader: loaded %d samples from %s",
            len(samples),
            self.config.data_dir,
        )
        return samples

    # ------------------------------------------------------------------
    # Private helpers — file discovery
    # ------------------------------------------------------------------

    def _iter_juliet_files(self) -> Iterator[Path]:
        """Yield all Juliet test-case files under data_dir."""
        assert self.config.data_dir is not None
        for ext in ("*.c", "*.cpp", "*.java"):
            for filepath in self.config.data_dir.rglob(ext):
                if self._CWE_PATTERN.match(filepath.name):
                    yield filepath

    # ------------------------------------------------------------------
    # Private helpers — filename metadata
    # ------------------------------------------------------------------

    def _extract_cwe_from_filename(self, filename: str) -> str:
        """Extract CWE identifier from Juliet filename.

        Examples:
            CWE89_SQL_Injection__char_connect_socket_01.c → "CWE-89"
            CWE120_Buffer_Copy_without_Checking_Size_01.c → "CWE-120"
        """
        match = self._CWE_PATTERN.match(Path(filename).name)
        if match:
            return f"CWE-{match.group(1)}"
        return "CWE-UNKNOWN"

    def _extract_variant(self, filename: str) -> int:
        """Extract the two/three-digit variant number from a Juliet filename.

        Returns 1 if no variant number is found (treat as base case).
        """
        match = self._VARIANT_PATTERN.search(filename)
        if match:
            return int(match.group(1))
        return 1

    def _variant_to_difficulty(self, variant: int) -> DifficultyLevel:
        """Map Juliet variant number to DifficultyLevel.

        Variant 01   EASY   — direct/base case, single function
        Variants 02–10  MEDIUM — constant folding, global vars, basic control flow
        Variants 11+    HARD   — function pointers, data flow, inter-procedural paths
        """
        if variant <= 1:
            return DifficultyLevel.EASY
        if variant <= 10:
            return DifficultyLevel.MEDIUM
        return DifficultyLevel.HARD

    # ------------------------------------------------------------------
    # Private helpers — function body extraction
    # ------------------------------------------------------------------

    def _extract_function_body(
        self, source: str, signatures: List[str]
    ) -> Optional[str]:
        """Extract the first matching function body from source code.

        Tries each pattern in signatures in order.  Returns the full text
        from the function signature to the matching closing brace.

        The extraction is brace-aware: it handles:
            - Line comments  //
            - Block comments /* ... */
            - String literals  "..."
            - Character literals  '...'
            - Escaped characters inside literals

        Returns None if no matching signature is found or brace matching fails.
        """
        for pattern_str in signatures:
            pattern = re.compile(pattern_str, re.MULTILINE | re.DOTALL)
            match = pattern.search(source)
            if match is None:
                continue

            # Find the opening brace (same line or next line)
            brace_pos = source.find("{", match.end() - 1)
            if brace_pos == -1:
                continue

            end_pos = self._find_matching_brace(source, brace_pos)
            if end_pos == -1:
                LOGGER.debug(
                    "Brace matching failed for pattern '%s'", pattern_str
                )
                continue

            return source[match.start() : end_pos + 1].strip()
        return None

    def _find_matching_brace(self, source: str, open_pos: int) -> int:
        """Return the index of the closing brace matching the one at open_pos.

        Uses a state machine that tracks string literals, character literals,
        line comments, and block comments to avoid false brace counts inside
        non-code regions.

        Returns -1 if the source ends before the closing brace is found.
        """
        depth = 0
        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False
        i = open_pos

        while i < len(source):
            c = source[i]

            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if c == "*" and i + 1 < len(source) and source[i + 1] == "/":
                    in_block_comment = False
                    i += 1
            elif in_string:
                if c == "\\" and i + 1 < len(source):
                    i += 1  # skip escaped character
                elif c == '"':
                    in_string = False
            elif in_char:
                if c == "\\" and i + 1 < len(source):
                    i += 1
                elif c == "'":
                    in_char = False
            else:
                if c == "/" and i + 1 < len(source):
                    if source[i + 1] == "/":
                        in_line_comment = True
                        i += 1
                    elif source[i + 1] == "*":
                        in_block_comment = True
                        i += 1
                elif c == '"':
                    in_string = True
                elif c == "'":
                    in_char = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        return i
            i += 1

        return -1  # unmatched opening brace


# ---------------------------------------------------------------------------
# DiverseVulDatasetLoader
# ---------------------------------------------------------------------------


class DiverseVulDatasetLoader(AbstractDatasetLoader):
    """Loader for the DiverseVul dataset (Tier 2 primary dataset).

    Dataset overview
    ----------------
    DiverseVul is a large-scale real-world C/C++ vulnerability dataset collected
    from CVE fix commits across 797 open-source projects.  It contains:
        ~349 000 function-level samples
        ~18 945 vulnerable functions across 150+ CWE types

    Unlike Big-Vul, DiverseVul explicitly stores both the vulnerable (func_before)
    and fixed (func_after) versions of patched functions, making pair generation
    straightforward without network calls to GitHub.

    Download sources
    ----------------
    JSON release:
        https://github.com/wagner-group/diversevul/releases
    HuggingFace (alternative):
        https://huggingface.co/datasets/claudios/diversevul
        Requires: pip install datasets

    License: MIT

    Supported ingestion modes
    -------------------------
    Mode 1 — JSON file (default)
        Set config.data_dir to the directory containing the downloaded JSON/JSONL.
        Supported filenames (tried in order):
            diversevul.json, diversevul.jsonl, data.json, data.jsonl, *.json, *.jsonl

    Mode 2 — HuggingFace (optional)
        Set config.extra["use_huggingface"] = True.
        The loader will call datasets.load_dataset("claudios/diversevul").
        data_dir is not required in this mode.

    Expected JSON record schema
    ---------------------------
    {
        "func":         str   — function code (used when no func_before available)
        "target":       int   — 1 = vulnerable, 0 = not vulnerable
        "project":      str   — source project name
        "commit_id":    str   — git commit hash of the CVE fix
        "cwe_list":     list  — e.g. ["CWE-119"]   (may contain multiple CWEs)
        "cve_list":     list  — e.g. ["CVE-2021-1234"]
        "func_before":  str   — vulnerable function body (when target=1)
        "func_after":   str   — fixed function body     (when target=1)
        "message":      str   — commit message
        "func_key":     str   — optional unique key
    }

    Pair generation
    ---------------
    When target=1 AND func_before AND func_after are all present:
        → Two CodeSamples are generated (vulnerable + fixed) with matching
          pair_sample_id metadata keys.

    When target=1 but only func is present (no func_before/func_after):
        → One vulnerable CodeSample is generated (no pair).

    When target=0:
        → One non-vulnerable CodeSample is generated from func.

    CWE handling
    ------------
    cwe_list may contain multiple CWEs.  The first is used as the canonical
    CWE.  Remaining CWEs are stored in metadata["additional_cwes"] so no
    information is lost.
    """

    @property
    def dataset_name(self) -> str:
        return "diversevul"

    @property
    def source_url(self) -> str:
        return "https://github.com/wagner-group/diversevul/releases"

    @property
    def license(self) -> str:
        return "MIT"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def validate_source(self) -> bool:
        """Return True if data_dir is set and a JSON/JSONL file exists there,
        OR if use_huggingface mode is enabled (no local file required)."""
        if self.config.extra.get("use_huggingface"):
            return True  # network availability is checked at load() time
        if self.config.data_dir is None or not self.config.data_dir.exists():
            return False
        try:
            self._find_data_file()
            return True
        except FileNotFoundError:
            return False

    def load(self) -> List[CodeSample]:
        """Ingest DiverseVul and return List[CodeSample].

        Raises:
            FileNotFoundError: If validate_source() would return False.
            ImportError:       If use_huggingface=True but datasets is not installed.
            ValueError:        If the data file cannot be parsed.
        """
        if self.config.extra.get("use_huggingface"):
            return self._load_from_huggingface()
        return self._load_from_json()

    # ------------------------------------------------------------------
    # Ingestion modes
    # ------------------------------------------------------------------

    def _load_from_json(self) -> List[CodeSample]:
        if not self.validate_source():
            raise FileNotFoundError(
                f"DiverseVul data file not found in: {self.config.data_dir}\n"
                "Download from https://github.com/wagner-group/diversevul/releases\n"
                "or set config.extra['use_huggingface'] = True"
            )
        data_file = self._find_data_file()
        raw_records = self._read_records(data_file)
        return self._process_records(raw_records)

    def _load_from_huggingface(self) -> List[CodeSample]:
        try:
            from datasets import load_dataset  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'datasets' package is required for DiverseVul HuggingFace mode.\n"
                "Install with: pip install datasets\n"
                "Alternatively, download the JSON release and set data_dir."
            ) from exc

        LOGGER.info("DiverseVulDatasetLoader: streaming from HuggingFace Hub...")
        hf_dataset = load_dataset("claudios/diversevul", split="train")
        return self._process_records([dict(record) for record in hf_dataset])

    # ------------------------------------------------------------------
    # Record processing
    # ------------------------------------------------------------------

    def _process_records(self, records: List[Dict[str, Any]]) -> List[CodeSample]:
        """Convert raw JSON records to CodeSamples, applying filters and cap."""
        samples: List[CodeSample] = []
        count = 0

        for record in records:
            if not self._is_within_sample_cap(count):
                break
            new_samples = self._record_to_samples(record)
            for sample in new_samples:
                if not self._is_within_sample_cap(count):
                    break
                if not self._passes_filters(sample.cwe, sample.language):
                    continue
                samples.append(sample)
                count += 1

        LOGGER.info("DiverseVulDatasetLoader: loaded %d samples", len(samples))
        return samples

    def _record_to_samples(self, record: Dict[str, Any]) -> List[CodeSample]:
        """Convert one JSON record to one or two CodeSamples (pair if available)."""
        # --- CWE extraction ------------------------------------------------
        cwe_list: List[str] = record.get("cwe_list") or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        primary_cwe = cwe_list[0] if cwe_list else str(record.get("cwe", "CWE-UNKNOWN"))
        additional_cwes = cwe_list[1:] if len(cwe_list) > 1 else []

        # --- Identifiers ---------------------------------------------------
        project = str(record.get("project", "unknown"))
        commit_id = str(record.get("commit_id", ""))
        func_key = str(
            record.get("func_key", f"{project}_{commit_id[:8] if commit_id else 'unknown'}")
        )

        target = int(record.get("target", 0))
        is_vulnerable = target == 1

        base_metadata: Dict[str, Any] = {
            "project": project,
            "commit_id": commit_id,
            "cve_list": list(record.get("cve_list") or []),
            "additional_cwes": additional_cwes,
            "message": str(record.get("message", "")),
        }

        func_before: str = str(record.get("func_before", "") or "")
        func_after: str = str(record.get("func_after", "") or "")
        func: str = str(record.get("func", "") or "")

        provenance = self._make_provenance(commit=commit_id)

        # --- Paired samples (vulnerable + fixed) ---------------------------
        if is_vulnerable and func_before.strip() and func_after.strip():
            vuln_id = f"diversevul_{func_key}_vuln"
            fixed_id = f"diversevul_{func_key}_fixed"

            return [
                CodeSample(
                    sample_id=vuln_id,
                    source_dataset="diversevul",
                    language="c",
                    code=func_before,
                    is_vulnerable=True,
                    cwe=primary_cwe,
                    severity="unknown",
                    difficulty=DifficultyLevel.MEDIUM,  # normalizer refines via CWE
                    split=self._assign_split(vuln_id),
                    provenance=provenance,
                    metadata={
                        **base_metadata,
                        "diversevul_function_type": "func_before",
                        "pair_sample_id": fixed_id,
                    },
                ),
                CodeSample(
                    sample_id=fixed_id,
                    source_dataset="diversevul",
                    language="c",
                    code=func_after,
                    is_vulnerable=False,
                    cwe=primary_cwe,
                    severity="unknown",
                    difficulty=DifficultyLevel.MEDIUM,
                    split=self._assign_split(fixed_id),
                    provenance=provenance,
                    metadata={
                        **base_metadata,
                        "diversevul_function_type": "func_after",
                        "pair_sample_id": vuln_id,
                    },
                ),
            ]

        # --- Single sample (no pair available) ----------------------------
        code = (func_before if is_vulnerable and func_before.strip() else func).strip()
        if not code:
            LOGGER.debug("Skipping record with empty code: func_key=%s", func_key)
            return []

        sample_id = f"diversevul_{func_key}"
        return [
            CodeSample(
                sample_id=sample_id,
                source_dataset="diversevul",
                language="c",
                code=code,
                is_vulnerable=is_vulnerable,
                cwe=primary_cwe,
                severity="unknown",
                difficulty=DifficultyLevel.MEDIUM,
                split=self._assign_split(sample_id),
                provenance=provenance,
                metadata=base_metadata,
            )
        ]

    # ------------------------------------------------------------------
    # File discovery helpers
    # ------------------------------------------------------------------

    def _find_data_file(self) -> Path:
        """Locate the DiverseVul JSON/JSONL file in data_dir."""
        assert self.config.data_dir is not None
        data_dir = self.config.data_dir

        for name in ("diversevul.json", "diversevul.jsonl", "data.json", "data.jsonl"):
            candidate = data_dir / name
            if candidate.is_file():
                return candidate

        # Fall back to any .json or .jsonl file
        json_files = sorted(
            list(data_dir.glob("*.json")) + list(data_dir.glob("*.jsonl"))
        )
        if json_files:
            LOGGER.info(
                "DiverseVulDatasetLoader: using '%s' (first JSON file found)",
                json_files[0].name,
            )
            return json_files[0]

        raise FileNotFoundError(
            f"No JSON or JSONL file found in {data_dir}.\n"
            "Expected: diversevul.json or diversevul.jsonl\n"
            "Download from https://github.com/wagner-group/diversevul/releases"
        )

    @staticmethod
    def _read_records(filepath: Path) -> List[Dict[str, Any]]:
        """Parse a JSON array or JSONL file into a list of dicts."""
        content = filepath.read_text(encoding="utf-8", errors="replace")

        # Attempt JSON array
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
            # Some releases wrap in a top-level dict
            for key in ("data", "samples", "functions", "records"):
                if key in data and isinstance(data[key], list):
                    return data[key]  # type: ignore[return-value]
        except json.JSONDecodeError:
            pass

        # Attempt JSONL
        records: List[Dict[str, Any]] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError as exc:
                LOGGER.debug("Skipping malformed JSONL line %d: %s", line_number, exc)

        if records:
            return records

        raise ValueError(
            f"Could not parse '{filepath}' as a JSON array or JSONL file.\n"
            "Ensure the file is a valid JSON array or one JSON object per line."
        )


# ---------------------------------------------------------------------------
# SyntheticDatasetLoader
# ---------------------------------------------------------------------------


class SyntheticDatasetLoader(AbstractDatasetLoader):
    """Loader for curated synthetic code samples (Tier 3 supporting dataset).

    Dataset overview
    ----------------
    Synthetic samples are hand-crafted code snippets created specifically for
    the dissertation to cover:
      - CWE patterns under-represented in Juliet and DiverseVul
      - Python / JavaScript / mixed-language scenarios
      - Controlled complexity across all four DifficultyLevels
      - Clean vulnerable ↔ fixed pairs for Experiment E

    Expected file location
    ----------------------
    <data_dir>/synthetic.json

    Expected file schema
    --------------------
    A JSON array where each element is either:

    1. Full schema (matches CodeSample.to_dict()):
        {
            "sample_id":       "syn_001",
            "source_dataset":  "synthetic",
            "language":        "python",
            "code":            "...",
            "is_vulnerable":   true,
            "cwe":             "CWE-89",
            "severity":        "high",
            "difficulty":      "medium",
            "split":           "test",
            "provenance": {
                "source_url":       "local",
                "source_commit":    "",
                "acquisition_date": "2026-05-28",
                "license":          "project"
            },
            "metadata": { "pair_sample_id": "syn_001_fixed" }
        }

    2. Simplified schema (missing fields are defaulted):
        {
            "sample_id":     "syn_001",
            "code":          "...",
            "is_vulnerable": true,
            "cwe":           "CWE-89",
            "language":      "python"
        }

    For simplified records:
        source_dataset  defaults to "synthetic"
        severity        defaults to "unknown"  (normaliser infers from CWE)
        difficulty      defaults to "medium"
        split           assigned deterministically via SHA-256 hash
        provenance      defaults to ProvenanceInfo with source_url="local"
    """

    @property
    def dataset_name(self) -> str:
        return "synthetic"

    @property
    def source_url(self) -> str:
        return "local"

    @property
    def license(self) -> str:
        return "project"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def validate_source(self) -> bool:
        """Return True if the synthetic JSON file exists."""
        data_file = self._find_data_file()
        return data_file is not None and data_file.is_file()

    def load(self) -> List[CodeSample]:
        """Load all synthetic samples from the JSON file.

        Raises:
            FileNotFoundError: If no synthetic JSON file is found.
            ValueError:        If the JSON cannot be parsed.
        """
        data_file = self._find_data_file()
        if data_file is None or not data_file.is_file():
            raise FileNotFoundError(
                f"Synthetic dataset file not found in: {self.config.data_dir}\n"
                "Create a 'synthetic.json' file following the schema in the "
                "SyntheticDatasetLoader docstring."
            )

        raw = json.loads(data_file.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(
                f"synthetic.json must be a JSON array, got {type(raw).__name__}"
            )

        samples: List[CodeSample] = []
        count = 0

        for index, entry in enumerate(raw):
            if not self._is_within_sample_cap(count):
                break
            if not isinstance(entry, dict):
                LOGGER.warning("Skipping non-dict entry at index %d", index)
                continue

            sample = self._entry_to_sample(entry)
            if sample is None:
                continue
            if not self._passes_filters(sample.cwe, sample.language):
                continue
            samples.append(sample)
            count += 1

        LOGGER.info("SyntheticDatasetLoader: loaded %d samples", len(samples))
        return samples

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _find_data_file(self) -> Optional[Path]:
        """Locate synthetic.json or first .json file in data_dir."""
        if self.config.data_dir is None:
            return None
        data_dir = self.config.data_dir

        for name in ("synthetic.json", "curated.json", "samples.json"):
            candidate = data_dir / name
            if candidate.is_file():
                return candidate

        json_files = sorted(data_dir.glob("*.json"))
        return json_files[0] if json_files else None

    def _entry_to_sample(self, entry: Dict[str, Any]) -> Optional[CodeSample]:
        """Parse one JSON entry into a CodeSample.

        Accepts both the full CodeSample schema and a simplified schema.
        Returns None if required fields (sample_id, code, cwe) are missing.
        """
        sample_id = str(entry.get("sample_id", "")).strip()
        code = str(entry.get("code", "")).strip()
        cwe = str(entry.get("cwe", "")).strip()
        language = str(entry.get("language", "unknown")).strip()

        if not sample_id:
            LOGGER.warning("Skipping entry with missing sample_id")
            return None
        if not code:
            LOGGER.warning("Skipping entry '%s': empty code", sample_id)
            return None
        if not cwe:
            LOGGER.warning("Skipping entry '%s': missing cwe", sample_id)
            return None

        # Split: honour explicit value, otherwise assign deterministically
        split_raw = str(entry.get("split", "")).strip().lower()
        try:
            split = DatasetSplit(split_raw) if split_raw else self._assign_split(sample_id)
        except ValueError:
            split = self._assign_split(sample_id)

        # Difficulty: honour explicit value, otherwise default to MEDIUM
        difficulty_raw = str(entry.get("difficulty", "medium")).strip().lower()
        try:
            difficulty = DifficultyLevel(difficulty_raw)
        except ValueError:
            difficulty = DifficultyLevel.MEDIUM

        # Provenance: use explicit value or build default
        provenance_raw = entry.get("provenance")
        if isinstance(provenance_raw, dict):
            provenance = ProvenanceInfo.from_dict(provenance_raw)
        else:
            provenance = self._make_provenance()

        return CodeSample(
            sample_id=sample_id,
            source_dataset=str(entry.get("source_dataset", "synthetic")),
            language=language,
            code=code,
            is_vulnerable=bool(entry.get("is_vulnerable", True)),
            cwe=cwe,
            severity=str(entry.get("severity", "unknown")),
            difficulty=difficulty,
            split=split,
            provenance=provenance,
            metadata=dict(entry.get("metadata", {})),
        )


# ---------------------------------------------------------------------------
# BigVulDatasetLoader  (optional future loader — not implemented)
# ---------------------------------------------------------------------------


class BigVulDatasetLoader(AbstractDatasetLoader):
    """OPTIONAL FUTURE LOADER — Big-Vul dataset.

    This loader is intentionally not implemented.  It serves as an architectural
    placeholder that documents the ingestion strategy for Big-Vul should it
    be required in future research.

    Decision rationale
    ------------------
    Big-Vul is excluded from the primary dissertation evaluation because:
      1. Juliet provides clean built-in bad()/good() pairs.
      2. DiverseVul provides real-world func_before/func_after pairs.
      3. Together they provide sufficient coverage for all six dissertation
         experiments without requiring GitHub patch reconstruction.
      4. Big-Vul's paired fixed functions are NOT pre-extracted in the CSV.
         Recovering them requires fetching from GitHub API using commit_id,
         introducing network dependency, rate-limiting, and repository
         availability risk.

    When to implement
    -----------------
    If future work requires Big-Vul (e.g., for additional scale or specific
    CWE coverage), implement the methods below.

    Download source
    ---------------
    https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
    File: MSR_data_cleaned.csv (~350 MB)
    License: MIT

    Field mapping
    -------------
    CSV column          CodeSample field
    ─────────────────   ────────────────────────────────
    func                code
    Vulnerability (1/0) is_vulnerable
    CWE ID (int)        cwe  (after "CWE-{id}" normalisation)
    CVEDetailID         metadata["cve_id"]
    commit_id           provenance.source_commit
    func_name           metadata["func_name"]

    Preprocessing requirements
    --------------------------
    1. pip install pandas
    2. pandas.read_csv("MSR_data_cleaned.csv")
    3. Normalise CWE: int 119 → "CWE-119"
    4. Deduplicate on SHA-256 of normalised code
    5. Stratify sample to address ~6 % vulnerable class imbalance
    6. Optional: fetch fixed functions from GitHub API via commit_id
    """

    @property
    def dataset_name(self) -> str:
        return "bigvul"

    @property
    def source_url(self) -> str:
        return "https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset"

    @property
    def license(self) -> str:
        return "MIT"

    def validate_source(self) -> bool:
        raise NotImplementedError(
            "BigVulDatasetLoader is not implemented. "
            "See class docstring for implementation guidance."
        )

    def load(self) -> List[CodeSample]:
        raise NotImplementedError(
            "BigVulDatasetLoader is not implemented. "
            "Use JulietDatasetLoader (Tier 1) or DiverseVulDatasetLoader (Tier 2) "
            "for primary dissertation evaluation.\n"
            "See class docstring for full implementation guidance."
        )


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def get_loader(name: str, config: LoaderConfig) -> AbstractDatasetLoader:
    """Return a concrete loader instance by name.

    Args:
        name:   One of "juliet", "diversevul", "synthetic", "bigvul".
        config: A LoaderConfig instance.

    Returns:
        Concrete AbstractDatasetLoader subclass.

    Raises:
        ValueError: If name is not a recognised loader.
    """
    registry: Dict[str, type] = {
        "juliet": JulietDatasetLoader,
        "diversevul": DiverseVulDatasetLoader,
        "synthetic": SyntheticDatasetLoader,
        "bigvul": BigVulDatasetLoader,
    }
    if name not in registry:
        raise ValueError(
            f"Unknown loader '{name}'. "
            f"Available loaders: {sorted(registry.keys())}"
        )
    return registry[name](config)
