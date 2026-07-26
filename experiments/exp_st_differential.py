"""Experiment ST — differential mutant-vs-reference discrimination on PLC code.

What this experiment is for
---------------------------
Experiments A–F establish, on Python, that a hybrid of SAST + a single strong
LLM is the best configuration. This experiment asks whether that conclusion
transfers to industrial control code (IEC 61131-3 Structured Text). It does not.

It also answers STMutants research question D ("Benchmarking AI Models and
Hybrid Analysis Systems") in four tiers:

===========  =========================================================
Tier 1       Each model benchmarked individually
Tier 2       Multi-model ensemble + Fleiss' / Cohen's kappa + bootstrap
Tier 3       Hybrid ST-SAST OR / AND ensemble
Tier 4       Verification-confidence triage for safety-critical use
===========  =========================================================

Why "differential" rather than a straight detection score
---------------------------------------------------------
The STMutants corpus is *all-positive* — every file is a mutant. Under a naive
"is this faulty?" prompt, a model that answers "faulty" every time scores a
perfect detection rate while demonstrating no skill whatsoever. That is not a
hypothetical failure mode: it is what happened on the first run, where the
smallest model in the panel posted 1.000 and a model five times larger posted
0.336.

The fix is to show each judge two versions — a reconstructed reference (A) and a
candidate (B) — and ask whether B *deviates* from A, then to include identity
controls where A and B are byte-identical. A model that flags identical code as
"deviating" is exposed, and the honest score becomes::

    bias-corrected = kill rate - false-alarm rate

A response-biased model, flagging both mutations and controls, nets zero.

Metric note
-----------
The prompt asks about **functional correctness**, not security. STMutants
faults are logic errors (a flipped comparison, a perturbed constant), not CWEs,
so a security-framed question would produce plausible but meaningless answers.

Outputs
-------
``datasets/processed/exp_st_results.json``
``datasets/processed/exp_st_summary.md``

Usage
-----
    python -X utf8 experiments/exp_st_differential.py --mock
    python -X utf8 experiments/exp_st_differential.py --no-mock
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import PROCESSED_DIR
from src.detectors.st_detectors import run_sast_st
from src.evaluation.statistical_tests import cohens_kappa, fleiss_kappa
from src.evaluation.stmutants import build_differential_pairs
from src.llm.judge_cache import JudgeCache

OUTPUT_DIR = PROCESSED_DIR
CACHE_PATH = PROCESSED_DIR / "judge_cache_st_diff.json"


# ---------------------------------------------------------------------------
# Differential prompt (functional-correctness framing, not security)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_ST_DIFF = """You are a control-systems engineer reviewing IEC 61131-3 \
Structured Text (ST) for a PLC. You are shown two versions of the same routine: \
VERSION A (the trusted reference) and VERSION B (a candidate). Decide whether \
VERSION B DEVIATES from the behaviour of VERSION A, i.e. whether a defect was \
introduced in B (a changed comparison or boundary, a wrong constant or \
initialisation, an inverted condition, a re-ordered or skipped state transition, \
an altered operator). This is about FUNCTIONAL correctness, not security.
Respond ONLY with valid JSON matching exactly:
{"is_vulnerable": boolean, "cwe": "string or NONE", "severity": \
"CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "reasoning": "which line differs"}
If the two versions are identical or behaviourally equivalent, answer \
is_vulnerable=false."""

USER_PROMPT_ST_DIFF = """Compare these two IEC 61131-3 Structured Text routines.

===== VERSION A (reference) =====
{code_a}

===== VERSION B (candidate) =====
{code_b}

Does VERSION B deviate from the behaviour of VERSION A? Return JSON with EXACTLY:
{{"is_vulnerable": <true|false>, "cwe": "<short change label or NONE>",
  "severity": "<CRITICAL|HIGH|MEDIUM|LOW|NONE>", "confidence": <0.0-1.0>,
  "reasoning": "<which construct differs, or why equivalent>"}}
"""


def build_diff_prompt(code_a: str, code_b: str) -> str:
    """Render the two-version comparison prompt."""
    return USER_PROMPT_ST_DIFF.format(code_a=code_a.strip(), code_b=code_b.strip())


# ---------------------------------------------------------------------------
# Judges
# ---------------------------------------------------------------------------
class DiffMockJudge:
    """Offline stand-in that actually compares the two versions.

    Not a random oracle: it answers honestly by diffing A against B, which makes
    ``--mock`` runs a genuine test of the *pipeline* (pairing, scoring, triage)
    while remaining clearly labelled as not a model measurement.
    """

    def __init__(self, name: str, accuracy: float = 1.0, seed: int = 7) -> None:
        self.name = name
        self._accuracy = accuracy
        self._rng = random.Random(seed)

    def judge(self, code: str, language: str = "st_diff") -> Dict[str, Any]:
        marker_a = "===== VERSION A (reference) ====="
        marker_b = "===== VERSION B (candidate) ====="
        deviates = False
        if marker_a in code and marker_b in code:
            version_a = code.split(marker_a, 1)[1].split(marker_b, 1)[0].strip()
            version_b = code.split(marker_b, 1)[1].split("Does VERSION B", 1)[0].strip()
            deviates = version_a != version_b
        if self._rng.random() >= self._accuracy:
            deviates = not deviates
        return {
            "is_vulnerable": deviates,
            "cwe": "FUNCTIONAL_DEVIATION" if deviates else "NONE",
            "severity": "HIGH" if deviates else "NONE",
            "confidence": 0.9,
            "reasoning": "mock differential comparison",
            "raw_response": "{}",
            "judge_name": self.name,
            "latency_s": 0.0,
            "error": None,
        }


def _build_judges(force_mock: bool) -> List[Any]:
    """Live judges when keys are present, else three honest mock judges."""
    if not force_mock:
        try:
            from src.llm.judge_factory import build_real_judges

            judges = build_real_judges(force_mock=False, tag="Exp ST")
            if judges:
                return judges
        except Exception as exc:  # pragma: no cover — provider import/config issues
            print(f"[Exp ST] live judge setup failed ({exc}) — falling back to mock")

    print("[Exp ST] using 3 mock differential judges (pipeline validation only)")
    return [
        DiffMockJudge("mock-diff-a", accuracy=1.00, seed=11),
        DiffMockJudge("mock-diff-b", accuracy=0.85, seed=22),
        DiffMockJudge("mock-diff-c", accuracy=0.70, seed=33),
    ]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _rate(votes: List[int]) -> float:
    return round(sum(votes) / len(votes), 4) if votes else 0.0


def score(mutation_votes: List[int], control_votes: List[int]) -> Dict[str, float]:
    """Return kill rate, false-alarm rate and the bias-corrected score."""
    kill = _rate(mutation_votes)
    false_alarm = _rate(control_votes)
    return {
        "kill_rate": kill,
        "false_alarm_rate": false_alarm,
        "bias_corrected": round(kill - false_alarm, 4),
    }


def _verdict(cache: JudgeCache, judge: Any, code_a: str, code_b: str, pair_id: str) -> int:
    """One cached differential judgement, as a 0/1 vote."""
    combined = build_diff_prompt(code_a, code_b)
    sample = {"sample_id": pair_id, "code": combined, "language": "st_diff"}
    result = cache.get_or_compute(
        judge, sample, code=combined, transform="diff", language="st_diff"
    )
    return int(bool(result.get("is_vulnerable")))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run(force_mock: bool = False) -> dict:
    pairs, controls, recon_report = build_differential_pairs()
    if not pairs:
        raise RuntimeError(
            "No differential pairs available. Place the STMutants corpus at "
            "datasets/benchmark/Mutations/<PROGRAM>/<1..10>.txt"
        )

    judges = _build_judges(force_mock)
    names = [getattr(j, "name", str(j)) for j in judges]
    cache = JudgeCache(CACHE_PATH)

    print(
        f"\n[Exp ST] differential discrimination — {len(pairs)} mutation pairs "
        f"+ {len(controls)} identity controls, {len(judges)} judge(s): {names}"
    )

    mutation_votes: Dict[str, List[int]] = {n: [] for n in names}
    control_votes: Dict[str, List[int]] = {n: [] for n in names}

    for index, pair in enumerate(pairs, 1):
        for judge, name in zip(judges, names):
            mutation_votes[name].append(
                _verdict(cache, judge, pair["ref"], pair["mutant"],
                         pair["sample_id"] + "::vs_ref")
            )
        if index % 20 == 0:
            print(f"    ...{index}/{len(pairs)} pairs judged", flush=True)

    for program, reference in controls:
        for judge, name in zip(judges, names):
            control_votes[name].append(
                _verdict(cache, judge, reference, reference, f"st_{program}_identity")
            )

    # --- Tier 1: individual models ---------------------------------------
    print("\n  --- Tier 1: individual models ---")
    per_model = {n: score(mutation_votes[n], control_votes[n]) for n in names}
    for name in names:
        s = per_model[name]
        print(
            f"    {name:<26} kill={s['kill_rate']:.3f}  "
            f"false_alarm={s['false_alarm_rate']:.3f}  "
            f"bias_corrected={s['bias_corrected']:.3f}"
        )
    best_single = max(per_model, key=lambda n: per_model[n]["bias_corrected"])
    print(f"    -> best single: {best_single} "
          f"({per_model[best_single]['bias_corrected']:.3f})")

    suspected_bias = [n for n in names if per_model[n]["false_alarm_rate"] >= 0.5]
    if suspected_bias:
        print(
            f"    WARNING response bias exposed: {suspected_bias} flag identical "
            f"code as deviating — their kill rate is not skill"
        )

    # --- Tier 2: ensemble -------------------------------------------------
    print("\n  --- Tier 2: multi-model ensemble ---")

    def majority(rows: Dict[str, List[int]], i: int) -> int:
        votes = [rows[n][i] for n in names]
        return int(sum(votes) >= (len(votes) + 1) // 2)

    mutation_majority = [majority(mutation_votes, i) for i in range(len(pairs))]
    control_majority = [majority(control_votes, i) for i in range(len(controls))]
    ensemble = score(mutation_majority, control_majority)
    print(
        f"    majority ensemble          kill={ensemble['kill_rate']:.3f}  "
        f"false_alarm={ensemble['false_alarm_rate']:.3f}  "
        f"bias_corrected={ensemble['bias_corrected']:.3f}"
    )

    rating_matrix = [
        [len(names) - sum(mutation_votes[n][i] for n in names),
         sum(mutation_votes[n][i] for n in names)]
        for i in range(len(pairs))
    ]
    fleiss = fleiss_kappa(rating_matrix, n_categories=2)
    pairwise: Dict[str, Dict[str, Any]] = {}
    for a in range(len(names)):
        for b in range(a + 1, len(names)):
            kappa = cohens_kappa(mutation_votes[names[a]], mutation_votes[names[b]])
            pairwise[f"{names[a]} vs {names[b]}"] = {
                "kappa": round(kappa.kappa, 4),
                "interpretation": kappa.interpretation,
            }
    print(f"    Fleiss kappa = {fleiss.kappa:.4f} ({fleiss.interpretation})")
    for label, entry in pairwise.items():
        print(f"      Cohen kappa {label}: {entry['kappa']:.4f} ({entry['interpretation']})")
    ensemble_gain = round(
        ensemble["bias_corrected"] - per_model[best_single]["bias_corrected"], 4
    )
    print(f"    ensemble vs best single: bias-corrected delta = {ensemble_gain:+.4f}")

    # --- Tier 3: hybrid with ST-SAST -------------------------------------
    print("\n  --- Tier 3: hybrid ST-SAST + ensemble ---")
    sast_mutation = [int(run_sast_st(p["mutant"])["is_vulnerable"]) for p in pairs]
    sast_control = [int(run_sast_st(ref)["is_vulnerable"]) for _, ref in controls]
    or_mutation = [int(a or b) for a, b in zip(sast_mutation, mutation_majority)]
    or_control = [int(a or b) for a, b in zip(sast_control, control_majority)]
    and_mutation = [int(a and b) for a, b in zip(sast_mutation, mutation_majority)]
    and_control = [int(a and b) for a, b in zip(sast_control, control_majority)]

    sast_only = score(sast_mutation, sast_control)
    hybrid_or = score(or_mutation, or_control)
    hybrid_and = score(and_mutation, and_control)
    for label, entry in (
        ("ST-SAST alone", sast_only),
        ("HYBRID (SAST OR ens.)", hybrid_or),
        ("HYBRID (SAST AND ens.)", hybrid_and),
    ):
        print(
            f"    {label:<26} kill={entry['kill_rate']:.3f}  "
            f"false_alarm={entry['false_alarm_rate']:.3f}  "
            f"bias_corrected={entry['bias_corrected']:.3f}"
        )

    # --- Tier 4: verification confidence ---------------------------------
    print("\n  --- Tier 4: verification confidence (safety-critical triage) ---")
    n_judges = len(names)
    bands: Dict[str, int] = {}
    for i in range(len(pairs)):
        votes = sum(mutation_votes[n][i] for n in names)
        sast_hit = bool(sast_mutation[i])
        if votes == n_judges or (votes >= 1 and sast_hit):
            band = "AUTO_FLAG"  # unanimous panel, or corroborated by SAST
        elif votes == 0 and not sast_hit:
            band = "SILENT_PASS"  # nothing fired — the dangerous case
        else:
            band = "REVIEW"  # split panel -> escalate to a control engineer
        bands[band] = bands.get(band, 0) + 1
    verification = {
        band: {"n": count, "share": round(count / len(pairs), 4)}
        for band, count in sorted(bands.items())
    }
    for band, entry in verification.items():
        print(f"    {band:<14}{entry['n']:>4}/{len(pairs)} ({entry['share'] * 100:5.1f}%)")
    silent_pass = verification.get("SILENT_PASS", {"share": 0.0})["share"]
    print(f"    -> SILENT-PASS rate = {silent_pass:.1%} "
          f"(faults that would reach a live PLC undetected)")

    qualifying = [p for p, r in recon_report.items() if r["qualifies"]]
    excluded = [p for p, r in recon_report.items() if not r["qualifies"]]

    return {
        "experiment": "ST",
        "name": "Differential mutant-vs-reference discrimination (PLC Structured Text)",
        "design": "differential with identity controls",
        "research_question": "STMutants RQ-D: benchmarking AI models and hybrid analysis systems",
        "dataset_citation": "Kabir, Islam & Lou (2026), STMutants, arXiv:2606.05499",
        "mock_mode": bool(force_mock) or isinstance(judges[0], DiffMockJudge),
        "metric_note": (
            "Score = kill_rate - false_alarm_rate. Identity controls (A vs A) expose "
            "response bias; bias_corrected is the honest figure. The corpus is "
            "all-positive, so a raw detection rate would reward a yes-bias."
        ),
        "reference_note": (
            "References are reconstructed per program by per-line majority vote over "
            "its mutants; STMutants ships no originals. Only programs whose mutants "
            "are consistent single-point edits were admitted."
        ),
        "not_implemented": (
            "Symbolic-execution / runtime-monitoring validation of predicted "
            "behavioural differences (RQ-D) needs an executable ST semantics "
            "(cf. K-ST, Wang et al. 2023) — future work."
        ),
        "n_mutation_pairs": len(pairs),
        "n_identity_controls": len(controls),
        "qualifying_programs": qualifying,
        "excluded_programs": excluded,
        "judges": names,
        "suspected_response_bias": suspected_bias,
        "tier1_individual_models": per_model,
        "tier1_best_single_model": best_single,
        "tier2_ensemble": {
            "scores": ensemble,
            "bias_corrected_gain_vs_best_single": ensemble_gain,
            "fleiss_kappa": {
                "kappa": round(fleiss.kappa, 4),
                "interpretation": fleiss.interpretation,
            },
            "pairwise_cohens_kappa": pairwise,
        },
        "tier3_hybrid": {
            "sast_only": sast_only,
            "hybrid_OR": hybrid_or,
            "hybrid_AND": hybrid_and,
        },
        "tier4_verification_confidence": {
            "bands": verification,
            "silent_pass_rate": silent_pass,
            "band_definition": {
                "AUTO_FLAG": "unanimous panel, or >=1 model corroborated by ST-SAST",
                "REVIEW": "split panel — escalate to a control engineer",
                "SILENT_PASS": "no model and no SAST rule fired — undetected fault",
            },
        },
    }


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_st_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\n[Exp ST] JSON  -> {json_path}")

    t1 = result["tier1_individual_models"]
    t2 = result["tier2_ensemble"]
    t3 = result["tier3_hybrid"]
    t4 = result["tier4_verification_confidence"]

    lines = [
        "# Experiment ST — Differential Discrimination on PLC Structured Text",
        "",
        f"**Mutation pairs:** {result['n_mutation_pairs']}  |  "
        f"**Identity controls:** {result['n_identity_controls']}  |  "
        f"**Programs:** {len(result['qualifying_programs'])}",
        "",
        "`bias_corrected = kill_rate - false_alarm_rate` "
        "(identity controls penalise a response bias).",
        "",
        "| System | Kill rate | False-alarm rate | Bias-corrected |",
        "|---|---:|---:|---:|",
    ]
    for name, entry in t1.items():
        lines.append(
            f"| {name} | {entry['kill_rate']:.3f} | "
            f"{entry['false_alarm_rate']:.3f} | {entry['bias_corrected']:.3f} |"
        )
    ens = t2["scores"]
    lines.append(
        f"| Ensemble (majority) | {ens['kill_rate']:.3f} | "
        f"{ens['false_alarm_rate']:.3f} | {ens['bias_corrected']:.3f} |"
    )
    for label, key in (("ST-SAST alone", "sast_only"),
                       ("Hybrid (SAST OR ens.)", "hybrid_OR"),
                       ("Hybrid (SAST AND ens.)", "hybrid_AND")):
        entry = t3[key]
        lines.append(
            f"| {label} | {entry['kill_rate']:.3f} | "
            f"{entry['false_alarm_rate']:.3f} | {entry['bias_corrected']:.3f} |"
        )

    lines += [
        "",
        f"**Best single model:** {result['tier1_best_single_model']}  |  "
        f"**Fleiss κ:** {t2['fleiss_kappa']['kappa']:+.4f} "
        f"({t2['fleiss_kappa']['interpretation']})",
        "",
        "## Verification confidence",
        "",
        "| Band | n | Share |",
        "|---|---:|---:|",
    ]
    for band, entry in t4["bands"].items():
        lines.append(f"| {band} | {entry['n']} | {entry['share'] * 100:.1f}% |")
    lines += [
        "",
        f"**Silent-pass rate:** {t4['silent_pass_rate']:.1%}",
        "",
        f"**Excluded programs:** {', '.join(result['excluded_programs']) or 'none'}",
        "",
        f"_{result['metric_note']}_",
        "",
        f"_{result['reference_note']}_",
    ]

    md_path = OUTPUT_DIR / "exp_st_summary.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[Exp ST] MD    -> {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Experiment ST (differential PLC)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--mock", dest="mock", action="store_true", default=None)
    group.add_argument("--no-mock", dest="mock", action="store_false")
    args = parser.parse_args()

    outcome = run(force_mock=args.mock is True)
    write_outputs(outcome)
