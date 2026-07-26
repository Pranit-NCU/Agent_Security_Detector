"""STMutants loader: PLC Structured Text mutants, de-leaked and paired.

Dataset
-------
Kabir, M. H., Islam, M. R., & Lou, H. H. (2026). *STMutants: A Mutation Testing
Dataset for Structured Text Programs in Industrial Automation.*
arXiv:2606.05499. https://arxiv.org/abs/2606.05499

On-disk layout (verified against all 110 files)::

    Mutations/<PROGRAM>/<1..10>.txt        11 programs x 10 files = 110

Three properties of this corpus dictate everything below. All were invisible
from the paper's description and each would silently invalidate results.

1. **It is a mutation benchmark, not a paired dataset.** All 110 files are
   mutants; no original programs ship with it. There is therefore no
   vulnerable/patched pairing to load, and the corpus is *all-positive* —
   structurally identical to SecurityEval.

2. **Every mutant self-labels its own fault.** 252 inline markers across the
   corpus announce the injected change, e.g. ``(* mutation: >= changed to > *)``
   and ``// Mutation: changed 2.0->2.1``. Markers appear in **both** comment
   forms (Lambert_W uses only ``//``; Traffic_Controller writes "Mutated:").
   Feeding these to an LLM leaks the ground truth and makes every score
   meaningless. :func:`strip_mutation_markers` removes them and
   :func:`load_mutants` asserts that none survive.

3. **An all-positive corpus rewards a response bias.** Scored with a naive
   "is this faulty?" prompt, a model that answers "faulty" every time is right
   every time. This is not hypothetical: on the first run the smallest model
   scored a perfect 1.000 while a model five times its size scored 0.336.
   :func:`build_differential_pairs` is the fix — see below.

The differential design
-----------------------
Because no originals ship, a per-program **reference** is reconstructed from
the mutants themselves. The ten mutants of a program are one-point edits of a
shared ancestor at *different* locations, so a per-line majority vote across
them cancels the individual mutations and recovers that ancestor — and does so
in the mutants' own formatting, which an external OSCAT copy would not match.

A program is admitted only if at least ``min_single`` of its ten mutants are
clean single-point edits of the reconstruction. On this corpus 7 of 11 qualify,
yielding 60 mutation pairs and 7 identity controls. The identity controls
(reference against *itself*) are what expose a response bias: a model that
flags identical code as "deviating" is caught, and the honest score becomes

    bias-corrected = kill rate - false-alarm rate

Usage
-----
    from src.evaluation.stmutants import load_mutants, build_differential_pairs

    mutants, provenance = load_mutants()
    pairs, controls, report = build_differential_pairs()
"""

from __future__ import annotations

import collections
import difflib
import glob
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src import config

__all__ = [
    "ST_PATH_CANDIDATES",
    "N_GENERATED",
    "N_RETAINED",
    "EQUIVALENCE_CEILING",
    "strip_mutation_markers",
    "classify_mutation",
    "resolve_data_dir",
    "load_mutants",
    "reconstruct_reference",
    "build_differential_pairs",
]

# First existing path wins. The Colab Drive location is checked first so the
# same code runs unchanged in the notebook and on a laptop.
ST_PATH_CANDIDATES: Tuple[str, ...] = (
    "/content/drive/MyDrive/VERDICT/datasets/Mutations/Mutations",
    "/content/drive/MyDrive/VERDICT/datasets/Mutations",
    str(config.BENCHMARK_DIR / "Mutations"),
    str(config.DATA_DIR / "Mutations"),
)

N_GENERATED = 110  # files shipped
N_RETAINED = 108  # non-equivalent after the paper's own screening
# The paper retains 108/110 after equivalence screening but ships no per-file
# retention flag, so ~2 samples may be behaviour-preserving mutants that no
# analyser could legitimately flag. Read detection against this ceiling.
EQUIVALENCE_CEILING = round(N_RETAINED / N_GENERATED, 4)

# --- ground-truth leak removal ----------------------------------------------
_MUT_BLOCK = re.compile(r"\(\*(?:(?!\*\)).)*?mutat(?:(?!\*\)).)*?\*\)", re.I | re.S)
_MUT_LINE = re.compile(r"//[^\n]*mutat[^\n]*", re.I)

# The paper's seven mutation-operator categories:
# "value, relational, arithmetic, logical, negation, operation insertion/
#  omission, and initialization faults" (Kabir et al. 2026). Assigned from the
# marker text, so this is the dataset's own taxonomy rather than an invented one.
_NUM_CHANGE = re.compile(r"\d+(?:\.\d+)?\s*(?:->|→|to)\s*\d+(?:\.\d+)?")


def strip_mutation_markers(code: str) -> Tuple[str, List[str]]:
    """Return ``(clean_code, [marker_texts])``.

    Only comments that *mention a mutation* are removed. Genuine OSCAT
    documentation comments are preserved, so the snippet still reads like real
    production PLC code rather than stripped-bare source.
    """
    markers = _MUT_BLOCK.findall(code) + _MUT_LINE.findall(code)
    clean = _MUT_LINE.sub("", _MUT_BLOCK.sub("", code))
    clean = re.sub(r"[ \t]+\n", "\n", clean)
    clean = re.sub(r"\n{3,}", "\n\n", clean)
    return clean.strip(), [m.strip() for m in markers]


def classify_mutation(note: str) -> str:
    """Map a marker string onto one of the paper's seven operator categories."""
    lowered = (note or "").lower()
    if not lowered:
        return "unclassified"
    if any(k in lowered for k in ("invert", "revers", "swapped", "negat")):
        return "negation"
    if "init" in lowered:
        return "initialization"
    if any(
        k in lowered
        for k in (">=", "<=", "changed = to", "changed <> to", "comparison",
                  "upper bound", " > ", " < ", "equal")
    ):
        return "relational"
    if any(
        k in lowered
        for k in ("and ->", "or ->", " and ", " or ", "logical", "shl", "shr", "xor", "mask")
    ):
        return "logical"
    if any(
        k in lowered
        for k in ("subtract", "addition", "multipl", "divi", "added ", "ln(", "sqrt",
                  "increment", "gain", "factor", "scaled", "offset", "differentiate")
    ):
        return "arithmetic"
    if any(
        k in lowered
        for k in ("skip", "omit", "do not", "remove", "prematurely", "unexpected",
                  "go to", "go back", "delay", "regardless", "always", "append",
                  "explicitly set")
    ):
        return "op_insertion_omission"
    if _NUM_CHANGE.search(note) or any(
        k in lowered
        for k in ("precision", "constant", "uppercase", "lowercase", "reset to", "set to",
                  "original", "shifted", "instead of", "slight", "tiny", "round",
                  "epsilon", "value", "true", "false", "increased", "decreased", "assigned")
    ):
        return "value"
    return "unclassified"


def resolve_data_dir(root: Optional[str] = None) -> Optional[Path]:
    """Return the first existing Mutations directory, or ``None``."""
    if root:
        p = Path(root)
        return p if p.is_dir() else None
    for candidate in ST_PATH_CANDIDATES:
        if os.path.isdir(candidate):
            return Path(candidate)
    return None


def _numeric_key(path: str) -> int:
    digits = re.sub(r"\D", "", os.path.basename(path))
    return int(digits) if digits else 0


def load_mutants(
    root: Optional[str] = None, verbose: bool = True
) -> Tuple[List[Dict[str, Any]], str]:
    """Parse ``Mutations/<PROGRAM>/<n>.txt`` into VERDICT sample dicts.

    Returns a flat list of mutants (no pairing — the corpus has none) and a
    provenance string of ``"stmutants"`` or ``"missing"``.
    """
    data_dir = resolve_data_dir(root)
    if data_dir is None:
        if verbose:
            print("  [ST] Mutations corpus not found. Looked in:")
            for candidate in ST_PATH_CANDIDATES:
                print(f"        - {candidate}")
        return [], "missing"

    programs = sorted(d for d in os.listdir(data_dir) if (data_dir / d).is_dir())
    samples: List[Dict[str, Any]] = []
    n_markers = 0

    for program in programs:
        for path in sorted(glob.glob(str(data_dir / program / "*.txt")), key=_numeric_key):
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
            clean, markers = strip_mutation_markers(raw)
            n_markers += len(markers)
            note = " | ".join(markers)
            stem = Path(path).stem
            samples.append(
                {
                    "sample_id": f"st_{program}_{stem}",
                    "code": clean,
                    "language": "st",
                    "expected_is_vulnerable": True,  # every file is a mutant
                    "program": program,
                    "mutation_category": classify_mutation(note),
                    "difficulty": "hard" if "subtle" in note.lower() else "medium",
                    "domain": "plc_structured_text",
                    "mutation_note": note,  # METADATA — never placed in `code`
                }
            )

    # HARD GUARD: no ground-truth marker may reach a judge.
    leaks = [s["sample_id"] for s in samples if re.search(r"mutat", s["code"], re.I)]
    if leaks:
        raise AssertionError(
            f"GROUND-TRUTH LEAK in {len(leaks)} sample(s): {leaks[:5]}"
        )

    if verbose:
        counts = collections.Counter(s["mutation_category"] for s in samples)
        print(f"  [ST] {len(samples)} first-order mutants from {len(programs)} programs")
        print(f"  [ST] stripped {n_markers} ground-truth marker(s) — none survived")
        for category, count in counts.most_common():
            print(f"        {category:<24}{count:>4}")
    return samples, "stmutants"


# ---------------------------------------------------------------------------
# Reference reconstruction + differential pairs
# ---------------------------------------------------------------------------
def _line_diff(a_lines: List[str], b_lines: List[str]) -> int:
    matcher = difflib.SequenceMatcher(None, a_lines, b_lines)
    return sum(
        max(i2 - i1, j2 - j1)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        if tag != "equal"
    )


def reconstruct_reference(files: List[str]) -> Tuple[str, List[List[str]]]:
    """Recover a program's common ancestor by per-line majority vote."""
    docs = [
        strip_mutation_markers(
            Path(f).read_text(encoding="utf-8", errors="replace")
        )[0].splitlines()
        for f in files
    ]
    modal_len = collections.Counter(len(d) for d in docs).most_common(1)[0][0]
    aligned = [d for d in docs if len(d) == modal_len]
    reference = [
        collections.Counter(a[i] for a in aligned).most_common(1)[0][0]
        for i in range(modal_len)
    ]
    return "\n".join(reference), docs


def build_differential_pairs(
    root: Optional[str] = None,
    min_single: int = 6,
    pair_max_diff: int = 3,
    verbose: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]], Dict[str, Any]]:
    """Build ``(pairs, identity_controls, report)`` for the differential study.

    ``pairs`` are ``{program, ref, mutant, sample_id}`` dicts where the mutant
    should be flagged as deviating from the reference. ``identity_controls`` are
    ``(program, reference)`` tuples that must **not** be flagged — they are what
    make a response bias visible.
    """
    data_dir = resolve_data_dir(root)
    if data_dir is None:
        if verbose:
            print("  [ST] Mutations corpus not found — cannot build pairs.")
        return [], [], {}

    programs = sorted(
        d for d in os.listdir(data_dir) if (data_dir / d).is_dir() and d != "originals"
    )
    pairs: List[Dict[str, Any]] = []
    controls: List[Tuple[str, str]] = []
    report: Dict[str, Any] = {}

    for program in programs:
        files = sorted(glob.glob(str(data_dir / program / "*.txt")), key=_numeric_key)
        reference, docs = reconstruct_reference(files)
        ref_lines = reference.splitlines()
        diffs = [_line_diff(ref_lines, d) for d in docs]
        n_single = sum(1 for x in diffs if 1 <= x <= 2)
        qualifies = n_single >= min_single
        report[program] = {
            "n_single_point": n_single,
            "qualifies": qualifies,
            "diffs": diffs,
        }
        if not qualifies:
            continue

        controls.append((program, reference))
        for path, diff in zip(files, diffs):
            if 1 <= diff <= pair_max_diff:  # isolates the injected fault
                clean, _ = strip_mutation_markers(
                    Path(path).read_text(encoding="utf-8", errors="replace")
                )
                pairs.append(
                    {
                        "program": program,
                        "ref": reference,
                        "mutant": clean,
                        "sample_id": f"st_{program}_{Path(path).stem}",
                    }
                )

    if verbose:
        good = [p for p, r in report.items() if r["qualifies"]]
        print(f"  [ST] reference reconstruction — {len(good)}/{len(programs)} programs qualify")
        for program, entry in report.items():
            mark = "OK " if entry["qualifies"] else "SKIP"
            print(f"        {mark} {program:<20} single-point mutants: "
                  f"{entry['n_single_point']}/10")
        print(f"  [ST] {len(pairs)} mutation pairs + {len(controls)} identity controls")
        excluded = [p for p, r in report.items() if not r["qualifies"]]
        if excluded:
            print(f"  [ST] excluded (mutants inconsistently reformatted): {excluded}")

    return pairs, controls, report


if __name__ == "__main__":  # pragma: no cover
    mutants, provenance = load_mutants()
    print(f"provenance={provenance}")
    if mutants:
        build_differential_pairs()
