"""Experiment E — Paired Discrimination (vulnerable vs. patched).

Filters the dataset to samples that have a paired counterpart
(vulnerable + patched version of the same function) and measures how
reliably each strategy correctly discriminates the two.

A *paired correct* outcome means the strategy flags the vulnerable member
AND does NOT flag the patched member of a pair.

Metrics
-------
  - Pair discrimination accuracy (% of pairs correctly discriminated)
  - Cohen's kappa between detector decision and ground truth
  - Paired bootstrap p-value for consensus vs. SAST-only

Outputs
-------
datasets/processed/exp_e_results.json
datasets/processed/exp_e_summary.md

Usage
-----
    python experiments/exp_e_paired.py
    python experiments/exp_e_paired.py --mock
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detectors import SQLInjectionDetector, SecretsDetector, AuthDetector, VulnerabilitySeverity
from src.llm.base_judge import BaseLLMJudge, JudgeConfig, JudgeResult
from src.llm.consensus_engine import ConsensusConfig, ConsensusEngine
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix
from src.evaluation.statistical_tests import cohens_kappa, paired_bootstrap
from src.config import SEED_PATH, PROCESSED_DIR
from src.llm.judge_factory import build_real_judges

# Exp E uses the PAIRED seed dataset (vuln/patch/clean). Paths resolve to the
# local repo by default, or to Google Drive when VERDICT_* env vars are set.
DATASET_PATH = SEED_PATH
OUTPUT_DIR   = PROCESSED_DIR
EXP_A_PATH   = OUTPUT_DIR / "exp_a_results.json"

SAST_DETECTORS = [SQLInjectionDetector(), SecretsDetector(), AuthDetector()]


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------

def load_paired_samples(path: Path) -> list[tuple[dict, dict]]:
    """Return list of (vulnerable_sample, patched_sample) pairs."""
    with open(path, encoding="utf-8") as fh:
        all_samples = json.load(fh)

    sample_map = {s["sample_id"]: s for s in all_samples}
    seen: set[str] = set()
    pairs: list[tuple[dict, dict]] = []

    for s in all_samples:
        if s["paired_sample_id"] is None:
            continue
        if s["sample_id"] in seen:
            continue
        partner_id = s["paired_sample_id"]
        partner = sample_map.get(partner_id)
        if partner is None:
            continue

        # Ensure (vuln, patch) ordering
        if s["expected_is_vulnerable"] and not partner["expected_is_vulnerable"]:
            vuln, patch = s, partner
        elif partner["expected_is_vulnerable"] and not s["expected_is_vulnerable"]:
            vuln, patch = partner, s
        else:
            continue

        pairs.append((vuln, patch))
        seen.add(s["sample_id"])
        seen.add(partner_id)

    return pairs


# ---------------------------------------------------------------------------
# SAST predictor
# ---------------------------------------------------------------------------

def sast_predict(code: str) -> bool:
    for det in SAST_DETECTORS:
        for v in det.detect(code):
            if v.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
                return True
    return False


def discrimination_accuracy(vuln_preds: List[bool], patch_preds: List[bool]) -> float:
    """Fraction of pairs a strategy correctly discriminates.

    A pair is *correctly discriminated* when the strategy flags the vulnerable
    member (``vuln_pred is True``) AND does not flag the patched member
    (``patch_pred is False``). Both lists are parallel, one entry per pair.

    (Restored: this helper was referenced by ``run()`` but its definition had
    gone missing, which raised ``NameError`` before the experiment could finish.)
    """
    if not vuln_preds:
        return 0.0
    correct = sum(1 for v, p in zip(vuln_preds, patch_preds) if v and not p)
    return correct / len(vuln_preds)


# ---------------------------------------------------------------------------
# Mock judge
# ---------------------------------------------------------------------------

class PairedMockJudge(BaseLLMJudge):
    def __init__(self, model_name: str, accuracy: float, seed: int) -> None:
        super().__init__(JudgeConfig(model_name=model_name))
        self._accuracy = accuracy
        self._rng = random.Random(seed)

    @property
    def provider_name(self) -> str:
        return "mock-paired"

    def _invoke_model(self, prompt: str) -> str:
        return ""

    def analyze_code(self, code_snippet, sast_findings, vulnerability_context="") -> JudgeResult:  # type: ignore[override]
        gt = getattr(self, "_ground_truth", False)
        verdict = gt if self._rng.random() < self._accuracy else not gt
        return JudgeResult(
            model_name=self.config.model_name,
            is_vulnerable=verdict,
            vulnerability_type="mock",
            cwe="CWE-000",
            severity="HIGH" if verdict else "INFO",
            confidence=self._accuracy,
            reasoning="Mock paired",
            exploitability="mock",
            remediation="N/A",
            raw_response="{}",
            latency_ms=10.0,
        )


def _build_judges(force_mock: bool) -> List[BaseLLMJudge]:
    """Live-judge chain centralised in ``src.llm.judge_factory``.

    Falls back to three noisy paired-mock judges when no live API key is present.

    Note: this replaces an earlier version that fell through without a return
    statement in mock mode (returning ``None`` and crashing ``run()``).
    """
    judges = build_real_judges(force_mock, tag="Exp E")

    if not judges:
        print("[Exp E] No live API keys found — using 3 mock paired judges")
        judges = [
            PairedMockJudge("mock-paired-a", accuracy=0.88, seed=101),
            PairedMockJudge("mock-paired-b", accuracy=0.80, seed=202),
            PairedMockJudge("mock-paired-c", accuracy=0.74, seed=303),
        ]

    return judges


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(force_mock: bool = False) -> dict:
    pairs = load_paired_samples(DATASET_PATH)
    if not pairs:
        raise RuntimeError("No paired samples found in dataset")

    judges = _build_judges(force_mock)
    engine = ConsensusEngine(ConsensusConfig(vulnerability_threshold=0.5))

    # Flat expected/predicted lists (all samples, vuln then patch)
    all_expected:  list[bool] = []
    sast_v_preds:  list[bool] = []
    sast_p_preds:  list[bool] = []
    per_model_v:   dict[str, list[bool]] = {j.config.model_name: [] for j in judges}
    per_model_p:   dict[str, list[bool]] = {j.config.model_name: [] for j in judges}
    consensus_v:   list[bool] = []
    consensus_p:   list[bool] = []

    pair_details: list[dict] = []

    for vuln, patch in pairs:
        # SAST
        sv = sast_predict(vuln["code"])
        sp = sast_predict(patch["code"])
        sast_v_preds.append(sv)
        sast_p_preds.append(sp)
        all_expected.extend([True, False])  # vuln=True, patch=False

        # LLM judges
        v_results: list[JudgeResult] = []
        p_results: list[JudgeResult] = []
        for judge in judges:
            if isinstance(judge, PairedMockJudge):
                judge._ground_truth = True  # type: ignore[attr-defined]
            try:
                jv: JudgeResult = judge.analyze_code(vuln["code"], [])
            except Exception:
                jv = _null_result(judge.config.model_name)
            per_model_v[judge.config.model_name].append(jv.is_vulnerable)
            v_results.append(jv)

            if isinstance(judge, PairedMockJudge):
                judge._ground_truth = False  # type: ignore[attr-defined]
            try:
                jp: JudgeResult = judge.analyze_code(patch["code"], [])
            except Exception:
                jp = _null_result(judge.config.model_name)
            per_model_p[judge.config.model_name].append(jp.is_vulnerable)
            p_results.append(jp)

        cv = engine.aggregate(v_results).is_vulnerable
        cp = engine.aggregate(p_results).is_vulnerable
        consensus_v.append(cv)
        consensus_p.append(cp)

        pair_details.append({
            "pair_id": vuln["sample_id"] + "/" + patch["sample_id"],
            "cwe": vuln["cwe"],
            "domain": vuln.get("domain", "general_python"),
            "difficulty": vuln["difficulty"],
            "sast_discriminated": sv and not sp,
            "consensus_discriminated": cv and not cp,
            "per_model_discriminated": {
                mn: per_model_v[mn][-1] and not per_model_p[mn][-1]
                for mn in per_model_v
            },
        })

    n_pairs = len(pairs)

    # Discrimination accuracy per strategy
    sast_disc_acc   = discrimination_accuracy(sast_v_preds, sast_p_preds)
    consensus_disc  = discrimination_accuracy(consensus_v, consensus_p)

    per_model_disc: dict = {}
    for mn in per_model_v:
        per_model_disc[mn] = discrimination_accuracy(per_model_v[mn], per_model_p[mn])

    # Flat metrics: treat each sample independently for P/R/F1
    sast_flat_preds = sast_v_preds + sast_p_preds
    consensus_flat  = consensus_v + consensus_p
    flat_expected   = [True] * n_pairs + [False] * n_pairs

    cm_sast = ConfusionMatrix.from_predictions(expected=flat_expected, predicted=sast_flat_preds)
    m_sast  = BinaryClassificationMetrics.from_confusion_matrix(cm_sast)
    cm_con  = ConfusionMatrix.from_predictions(expected=flat_expected, predicted=consensus_flat)
    m_con   = BinaryClassificationMetrics.from_confusion_matrix(cm_con)

    k_sast = cohens_kappa(flat_expected, sast_flat_preds)
    k_con  = cohens_kappa(flat_expected, consensus_flat)

    # Bootstrap significance: consensus vs SAST-only on flat samples
    bs = paired_bootstrap(flat_expected, sast_flat_preds, consensus_flat, metric="f1")

    return {
        "experiment": "E",
        "name": "Paired Discrimination",
        "n_pairs": n_pairs,
        "n_flat_samples": 2 * n_pairs,
        "discrimination_accuracy": {
            "sast_only": round(sast_disc_acc, 4),
            "consensus": round(consensus_disc, 4),
            **{mn: round(v, 4) for mn, v in per_model_disc.items()},
        },
        "flat_metrics": {
            "sast_only": {**cm_sast.to_dict(), **m_sast.to_dict(),
                          "kappa": k_sast.kappa, "kappa_interp": k_sast.interpretation},
            "consensus": {**cm_con.to_dict(), **m_con.to_dict(),
                          "kappa": k_con.kappa, "kappa_interp": k_con.interpretation},
        },
        "bootstrap_consensus_vs_sast": {
            "delta_f1": round(bs.delta, 4),
            "p_value": round(bs.p_value, 4),
            "significant": bs.significant,
        },
        "pair_details": pair_details,
    }


def _null_result(model_name: str) -> JudgeResult:
    return JudgeResult(
        model_name=model_name, is_vulnerable=False,
        vulnerability_type="error", cwe="CWE-000",
        severity="INFO", confidence=0.0, reasoning="error",
        exploitability="N/A", remediation="N/A",
        raw_response="", latency_ms=0.0,
    )


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_e_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[Exp E] JSON  -> {json_path}")

    da  = result["discrimination_accuracy"]
    fm  = result["flat_metrics"]
    bs  = result["bootstrap_consensus_vs_sast"]

    md_lines = [
        "# Experiment E — Paired Discrimination",
        "",
        f"**Pairs:** {result['n_pairs']}  |  "
        f"**Flat samples:** {result['n_flat_samples']}",
        "",
        "## Discrimination accuracy (% of pairs correctly discriminated)",
        "",
        "| Strategy | Disc. Acc |",
        "|---|---:|",
    ]
    for strategy, acc in da.items():
        md_lines.append(f"| {strategy} | {acc:.3f} |")

    md_lines += [
        "",
        "## Flat sample metrics",
        "",
        "| Strategy | Precision | Recall | F1 | κ |",
        "|---|---:|---:|---:|---:|",
    ]
    for strat, m in fm.items():
        md_lines.append(
            f"| {strat} | {m.get('precision',0):.3f} | "
            f"{m.get('recall',0):.3f} | "
            f"{m.get('f1_score',0):.3f} | "
            f"{m.get('kappa',0):.3f} |"
        )

    md_lines += [
        "",
        f"**Bootstrap (consensus vs. SAST-only):** "
        f"ΔF1={bs['delta_f1']}  p={bs['p_value']}  significant={bs['significant']}",
    ]

    md_path = OUTPUT_DIR / "exp_e_summary.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[Exp E] MD    -> {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Experiment E")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--mock",    dest="mock", action="store_true",  default=None)
    grp.add_argument("--no-mock", dest="mock", action="store_false")
    args = parser.parse_args()

    result = run(force_mock=args.mock is True)
    write_outputs(result)

    da = result["discrimination_accuracy"]
    print(f"\n[Exp E] Pairs={result['n_pairs']}")
    print("  Discrimination accuracy:")
    for strat, acc in da.items():
        print(f"    {strat:<30} {acc:.3f}")
