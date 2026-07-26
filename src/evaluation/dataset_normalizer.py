"""Normalisation layer for multi-source vulnerability dataset ingestion.

Design Rationale
----------------
Raw CodeSamples returned by loaders carry fields in whatever form the source
dataset used.  Before any benchmarking experiment can proceed, those raw values
must be converted to canonical forms so that:

  1. CWE identifiers from different sources can be compared (e.g., "89",
     "CWE89", "CWE-89", "cwe-89" all mean the same thing).
  2. Language names are consistent across loaders ("C++" vs "cpp" vs "c++").
  3. Severity values have a predictable vocabulary for statistics and
     dissertation tables.
  4. Difficulty levels can be inferred when a loader cannot determine them
     (e.g., DiverseVul has no explicit difficulty field).
  5. The final export dictionary format is stable and machine-readable,
     matching the Step 8 benchmark export schema.

Normalisation is performed by a stateless DatasetNormalizer class.  Each
method is a pure function: it never mutates its input and always returns a
new object.  This design makes normalisation fully testable in isolation.

CWE Normalisation
-----------------
Input variations handled:
    "89"          → "CWE-89"    (plain integer string)
    "CWE89"       → "CWE-89"    (missing hyphen)
    "CWE-89"      → "CWE-89"    (already canonical — passthrough)
    "cwe-89"      → "CWE-89"    (lowercase)
    "CWE_89"      → "CWE-89"    (underscore separator)
    "CWE 89"      → "CWE-89"    (space separator)
    ""  / "none"  → "CWE-UNKNOWN"

Severity Normalisation
----------------------
Output vocabulary: "critical" / "high" / "medium" / "low" / "info" / "unknown"
Inputs handled:
    - String labels in any case   ("Critical", "HIGH", "low")
    - CVSS v3.x numeric strings   ("9.8", "7.5", "4.0", "2.1", "0.0")
    - Empty or None               → inferred from CWE via _CWE_SEVERITY_MAP

Difficulty Inference
--------------------
DiverseVul and generic loaders cannot determine difficulty without code analysis.
infer_difficulty_from_cwe() provides a CWE-level heuristic based on the typical
reasoning complexity required to exploit or detect each vulnerability class.

This heuristic is intentionally conservative: it defaults to MEDIUM for any
CWE not in the lookup table rather than mis-classifying hard vulnerabilities
as easy.

Export Dictionary (Step 8 Schema)
----------------------------------
to_export_dict() produces:
    {
        "sample_id":           str,
        "dataset":             str,
        "language":            str,
        "cwe":                 str,     # canonical "CWE-N"
        "difficulty":          str,     # "easy" / "medium" / "hard" / "adversarial"
        "split":               str,     # "train" / "validation" / "test"
        "vulnerable":          bool,
        "severity":            str,
        "code":                str,
        "fixed_version":       None,    # populated by PairGenerator
        "adversarial_variants": [],     # populated by adversarial generator
        "provenance":          dict,
        "metadata":            dict
    }

pair_to_export_dict() extends the above with:
    "fixed_version":  str   (fixed_sample.code)
    "fix_type":       str
    "pair_id":        str

Integration Points
------------------
  normalize_bundle()      → DatasetValidator.validate()
  normalize_bundle()      → DatasetStatistics.compute()
  to_export_dict()        → benchmark export (dataset_builder.py CLI)
  pair_to_export_dict()   → Experiment E evaluation reports
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .benchmark_dataset import DifficultyLevel
from .dataset_models import (
    CodePair,
    CodeSample,
    DatasetBundle,
    DatasetSplit,
    FixType,
    ProvenanceInfo,
)

__all__ = ["DatasetNormalizer"]


class DatasetNormalizer:
    """Stateless normaliser: converts raw CodeSample fields to canonical forms.

    All public methods are pure functions — they return new objects and never
    mutate their inputs.  This guarantees that repeated normalisation passes
    are idempotent.

    Usage example::

        normalizer = DatasetNormalizer()
        normalised_bundle = normalizer.normalize_bundle(raw_bundle)
        export_rows = [normalizer.to_export_dict(s) for s in normalised_bundle.samples]
    """

    # ------------------------------------------------------------------
    # CWE normalisation
    # ------------------------------------------------------------------

    # Accepts: optional "CWE" prefix (case-insensitive), optional separator
    # (hyphen, underscore, space), then one or more digits.
    _CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d+)", re.IGNORECASE)

    def normalize_cwe(self, cwe: str) -> str:
        """Return canonical CWE string "CWE-<N>" from any recognised input.

        Any input that cannot be parsed as a CWE number returns "CWE-UNKNOWN".
        This sentinel is preserved throughout the pipeline and surfaces in
        validation reports as an indicator of incomplete metadata.

        Examples:
            >>> n = DatasetNormalizer()
            >>> n.normalize_cwe("89")
            'CWE-89'
            >>> n.normalize_cwe("CWE89")
            'CWE-89'
            >>> n.normalize_cwe("cwe-120")
            'CWE-120'
            >>> n.normalize_cwe("")
            'CWE-UNKNOWN'
        """
        if not cwe:
            return "CWE-UNKNOWN"
        stripped = cwe.strip()
        if stripped.lower() in ("", "none", "unknown", "n/a", "cwe-unknown"):
            return "CWE-UNKNOWN"
        match = self._CWE_RE.fullmatch(stripped) or self._CWE_RE.match(stripped)
        if match:
            return f"CWE-{match.group(1)}"
        return "CWE-UNKNOWN"

    # ------------------------------------------------------------------
    # Language normalisation
    # ------------------------------------------------------------------

    _LANGUAGE_MAP: Dict[str, str] = {
        "c": "c",
        "c++": "cpp",
        "cpp": "cpp",
        "c/c++": "c/cpp",
        "c/cpp": "c/cpp",
        "java": "java",
        "python": "python",
        "py": "python",
        "python3": "python",
        "javascript": "javascript",
        "js": "javascript",
        "typescript": "typescript",
        "ts": "typescript",
        "go": "go",
        "golang": "go",
        "rust": "rust",
        "rs": "rust",
        "php": "php",
        "ruby": "ruby",
        "rb": "ruby",
        "csharp": "csharp",
        "c#": "csharp",
        "swift": "swift",
        "kotlin": "kotlin",
    }

    def normalize_language(self, language: str) -> str:
        """Return lowercase canonical language string.

        Unknown languages are returned lowercased but otherwise unchanged,
        so that novel languages in future datasets are not silently discarded.

        Examples:
            >>> n = DatasetNormalizer()
            >>> n.normalize_language("C++")
            'cpp'
            >>> n.normalize_language("Python3")
            'python'
            >>> n.normalize_language("COBOL")
            'cobol'
        """
        if not language:
            return "unknown"
        return self._LANGUAGE_MAP.get(language.strip().lower(), language.strip().lower())

    # ------------------------------------------------------------------
    # Severity normalisation
    # ------------------------------------------------------------------

    _SEVERITY_LABELS: Dict[str, str] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "none": "info",
        "unknown": "unknown",
    }

    # CWE → default severity (used when source dataset provides no severity)
    _CWE_SEVERITY_MAP: Dict[str, str] = {
        "CWE-89": "critical",   # SQL Injection
        "CWE-78": "critical",   # OS Command Injection
        "CWE-798": "critical",  # Hardcoded Credentials
        "CWE-287": "high",      # Improper Authentication
        "CWE-79": "high",       # XSS
        "CWE-120": "high",      # Buffer Copy without Size Check
        "CWE-121": "high",      # Stack-based Buffer Overflow
        "CWE-122": "high",      # Heap-based Buffer Overflow
        "CWE-125": "high",      # Out-of-bounds Read
        "CWE-787": "high",      # Out-of-bounds Write
        "CWE-416": "high",      # Use After Free
        "CWE-415": "high",      # Double Free
        "CWE-362": "high",      # Race Condition
        "CWE-843": "high",      # Type Confusion
        "CWE-190": "medium",    # Integer Overflow
        "CWE-191": "medium",    # Integer Underflow
        "CWE-476": "medium",    # NULL Pointer Dereference
        "CWE-401": "medium",    # Memory Leak
        "CWE-20": "medium",     # Improper Input Validation
        "CWE-327": "medium",    # Use of Broken Algorithm
        "CWE-209": "low",       # Information Exposure via Error Message
        "CWE-404": "low",       # Improper Resource Shutdown
    }

    def normalize_severity(self, severity: str, *, cwe: str = "") -> str:
        """Normalise severity to one of: critical / high / medium / low / info / unknown.

        If severity is empty or unrecognised, the method falls back to a
        CWE-based lookup so that Juliet and DiverseVul samples (which do not
        carry explicit severity values) still receive a meaningful severity.

        CVSS v3.x numeric scores are mapped to label bands:
            9.0 – 10.0  → critical
            7.0 –  8.9  → high
            4.0 –  6.9  → medium
            0.1 –  3.9  → low
            0.0         → info

        Examples:
            >>> n = DatasetNormalizer()
            >>> n.normalize_severity("HIGH")
            'high'
            >>> n.normalize_severity("9.8")
            'critical'
            >>> n.normalize_severity("", cwe="CWE-89")
            'critical'
            >>> n.normalize_severity("unknown")
            'unknown'
        """
        if not severity:
            return self._CWE_SEVERITY_MAP.get(cwe, "unknown")

        stripped = severity.strip().lower()

        # Check label map first
        label_result = self._SEVERITY_LABELS.get(stripped)
        if label_result is not None:
            return label_result

        # Attempt CVSS numeric parsing
        try:
            score = float(stripped)
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0.0:
                return "low"
            return "info"
        except ValueError:
            pass

        # Unrecognised — fall back to CWE inference
        cwe_result = self._CWE_SEVERITY_MAP.get(cwe)
        return cwe_result if cwe_result is not None else "unknown"

    # ------------------------------------------------------------------
    # Difficulty inference
    # ------------------------------------------------------------------

    # CWE → heuristic DifficultyLevel
    # Based on the typical reasoning complexity required for detection:
    #   EASY   — single-statement, single-function patterns (direct string concat, etc.)
    #   MEDIUM — requires limited semantic understanding (bounds, null checks, etc.)
    #   HARD   — requires data-flow tracking or multi-step reasoning
    _CWE_DIFFICULTY_MAP: Dict[str, DifficultyLevel] = {
        "CWE-89": DifficultyLevel.EASY,     # direct string interpolation
        "CWE-798": DifficultyLevel.EASY,    # hardcoded literal
        "CWE-209": DifficultyLevel.EASY,    # exception message leak
        "CWE-79": DifficultyLevel.MEDIUM,   # XSS requires output context
        "CWE-20": DifficultyLevel.MEDIUM,   # input validation patterns
        "CWE-78": DifficultyLevel.MEDIUM,   # OS command injection
        "CWE-120": DifficultyLevel.MEDIUM,  # buffer copy without check
        "CWE-121": DifficultyLevel.MEDIUM,  # stack buffer overflow
        "CWE-122": DifficultyLevel.MEDIUM,  # heap buffer overflow
        "CWE-125": DifficultyLevel.MEDIUM,  # out-of-bounds read
        "CWE-190": DifficultyLevel.MEDIUM,  # integer overflow
        "CWE-191": DifficultyLevel.MEDIUM,  # integer underflow
        "CWE-476": DifficultyLevel.MEDIUM,  # null dereference
        "CWE-401": DifficultyLevel.MEDIUM,  # memory leak
        "CWE-327": DifficultyLevel.MEDIUM,  # weak crypto
        "CWE-787": DifficultyLevel.HARD,    # out-of-bounds write (data flow)
        "CWE-416": DifficultyLevel.HARD,    # use-after-free
        "CWE-415": DifficultyLevel.HARD,    # double free
        "CWE-362": DifficultyLevel.HARD,    # race condition
        "CWE-843": DifficultyLevel.HARD,    # type confusion
        "CWE-287": DifficultyLevel.HARD,    # improper authentication (state)
        "CWE-404": DifficultyLevel.HARD,    # improper resource shutdown
    }

    def infer_difficulty_from_cwe(self, cwe: str) -> DifficultyLevel:
        """Return a heuristic DifficultyLevel based on the canonical CWE.

        Defaults to MEDIUM for any CWE not in the lookup table.
        This conservative default avoids under-estimating detection difficulty.
        """
        return self._CWE_DIFFICULTY_MAP.get(cwe, DifficultyLevel.MEDIUM)

    # ------------------------------------------------------------------
    # Sample normalisation
    # ------------------------------------------------------------------

    def normalize_sample(self, sample: CodeSample) -> CodeSample:
        """Return a new CodeSample with all fields normalised.

        Normalised fields:
            sample_id       stripped of leading/trailing whitespace
            source_dataset  lowercased and stripped
            language        via normalize_language()
            cwe             via normalize_cwe()
            severity        via normalize_severity(cwe=normalised_cwe)
            difficulty      unchanged (caller may call infer_difficulty_from_cwe
                            separately before normalisation if needed)
            code            unchanged (raw code is never modified)

        The metadata dict is shallow-copied so the original is not mutated.
        """
        normalised_cwe = self.normalize_cwe(sample.cwe)
        normalised_lang = self.normalize_language(sample.language)
        normalised_sev = self.normalize_severity(sample.severity, cwe=normalised_cwe)

        return CodeSample(
            sample_id=sample.sample_id.strip(),
            source_dataset=sample.source_dataset.strip().lower(),
            language=normalised_lang,
            code=sample.code,
            is_vulnerable=sample.is_vulnerable,
            cwe=normalised_cwe,
            severity=normalised_sev,
            difficulty=sample.difficulty,
            split=sample.split,
            provenance=sample.provenance,
            metadata=dict(sample.metadata),
        )

    def normalize_sample_with_inferred_difficulty(
        self, sample: CodeSample
    ) -> CodeSample:
        """Normalise a sample and infer difficulty from CWE when MEDIUM is the default.

        Use this variant for DiverseVul samples whose difficulty was set to
        DifficultyLevel.MEDIUM as a placeholder by the loader.  For Juliet samples,
        the variant-number-based difficulty should be preserved; call normalize_sample()
        instead.

        Inference only replaces difficulty if the sample's current difficulty is
        DifficultyLevel.MEDIUM (the loader default), not if it was set explicitly.
        """
        base = self.normalize_sample(sample)
        inferred = self.infer_difficulty_from_cwe(base.cwe)
        # Only override the placeholder MEDIUM; preserve EASY/HARD set by loader
        resolved_difficulty = (
            inferred
            if base.difficulty == DifficultyLevel.MEDIUM
            else base.difficulty
        )
        return CodeSample(
            sample_id=base.sample_id,
            source_dataset=base.source_dataset,
            language=base.language,
            code=base.code,
            is_vulnerable=base.is_vulnerable,
            cwe=base.cwe,
            severity=base.severity,
            difficulty=resolved_difficulty,
            split=base.split,
            provenance=base.provenance,
            metadata=dict(base.metadata),
        )

    # ------------------------------------------------------------------
    # Bundle normalisation
    # ------------------------------------------------------------------

    def normalize_bundle(
        self,
        bundle: DatasetBundle,
        *,
        infer_difficulty: bool = False,
    ) -> DatasetBundle:
        """Return a new DatasetBundle with all samples and pair members normalised.

        Args:
            bundle:            The raw DatasetBundle from a loader.
            infer_difficulty:  If True, calls normalize_sample_with_inferred_difficulty
                               on every sample so that DiverseVul samples receive
                               CWE-based difficulty rather than the MEDIUM placeholder.
                               Set to False (default) when Juliet variant-number
                               difficulty must be preserved exactly.

        Returns:
            A new DatasetBundle; the original is not mutated.
        """
        normalise_fn = (
            self.normalize_sample_with_inferred_difficulty
            if infer_difficulty
            else self.normalize_sample
        )

        normalised_samples = [normalise_fn(s) for s in bundle.samples]

        # Build a lookup for normalised samples so pair members stay consistent
        sample_lookup: Dict[str, CodeSample] = {
            s.sample_id: s for s in normalised_samples
        }

        normalised_pairs: List[CodePair] = []
        for pair in bundle.pairs:
            # Use already-normalised counterparts if available; else normalise inline
            vuln = sample_lookup.get(
                pair.vulnerable_sample.sample_id,
                normalise_fn(pair.vulnerable_sample),
            )
            fixed = sample_lookup.get(
                pair.fixed_sample.sample_id,
                normalise_fn(pair.fixed_sample),
            )
            normalised_pairs.append(
                CodePair(
                    pair_id=pair.pair_id,
                    vulnerable_sample=vuln,
                    fixed_sample=fixed,
                    cwe=self.normalize_cwe(pair.cwe),
                    fix_type=pair.fix_type,
                    source_dataset=pair.source_dataset.strip().lower(),
                    metadata=dict(pair.metadata),
                )
            )

        return DatasetBundle(
            name=bundle.name,
            samples=normalised_samples,
            pairs=normalised_pairs,
        )

    # ------------------------------------------------------------------
    # Export dictionary format (Step 8 schema)
    # ------------------------------------------------------------------

    def to_export_dict(self, sample: CodeSample) -> Dict[str, Any]:
        """Return the canonical benchmark export dictionary for a CodeSample.

        Matches the Step 8 schema from the dissertation framework specification.
        The fixed_version and adversarial_variants fields are intentionally
        left as placeholder values: they are populated downstream by
        PairGenerator and the adversarial generator respectively.

        Schema::

            {
                "sample_id":            str,
                "dataset":              str,
                "language":             str,
                "cwe":                  str,
                "difficulty":           str,
                "split":                str,
                "vulnerable":           bool,
                "severity":             str,
                "code":                 str,
                "fixed_version":        null,
                "adversarial_variants": [],
                "provenance":           { source_url, source_commit,
                                          acquisition_date, license },
                "metadata":             dict
            }
        """
        return {
            "sample_id": sample.sample_id,
            "dataset": sample.source_dataset,
            "language": sample.language,
            "cwe": sample.cwe,
            "difficulty": sample.difficulty.value,
            "split": sample.split.value,
            "vulnerable": sample.is_vulnerable,
            "severity": sample.severity,
            "code": sample.code,
            "fixed_version": None,           # populated by PairGenerator
            "adversarial_variants": [],      # populated by adversarial generator
            "provenance": sample.provenance.to_dict(),
            "metadata": dict(sample.metadata),
        }

    def pair_to_export_dict(self, pair: CodePair) -> Dict[str, Any]:
        """Return the canonical benchmark export dictionary for a CodePair.

        Extends to_export_dict() with:
            pair_id        Unique pair identifier.
            fixed_version  The full source code of the fixed counterpart.
            fix_type       Semantic classification of how the fix was applied.

        This is the primary export format for Experiment E (vulnerable vs fixed
        discrimination) evaluation reports.
        """
        base = self.to_export_dict(pair.vulnerable_sample)
        base["pair_id"] = pair.pair_id
        base["fixed_version"] = pair.fixed_sample.code
        base["fix_type"] = pair.fix_type.value
        base["fixed_sample_id"] = pair.fixed_sample.sample_id
        return base

    def bundle_to_export_list(
        self,
        bundle: DatasetBundle,
    ) -> List[Dict[str, Any]]:
        """Convert all samples in a bundle to export dicts.

        Samples that have an associated CodePair in the bundle are exported
        via pair_to_export_dict() so fixed_version is populated.
        Unpaired samples use to_export_dict() with fixed_version=None.
        """
        # Build lookup: vulnerable_sample_id → CodePair
        pair_lookup: Dict[str, CodePair] = {
            p.vulnerable_sample.sample_id: p for p in bundle.pairs
        }

        result: List[Dict[str, Any]] = []
        for sample in bundle.samples:
            if sample.sample_id in pair_lookup:
                result.append(self.pair_to_export_dict(pair_lookup[sample.sample_id]))
            elif not sample.is_vulnerable:
                # Fixed-side of a pair: include as standalone non-vulnerable sample
                result.append(self.to_export_dict(sample))
            else:
                result.append(self.to_export_dict(sample))

        return result
