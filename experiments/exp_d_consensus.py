"""Experiment D — Multi-LLM Consensus.

Runs ConsensusEngine over all configured judges, computes:
  - Majority-vote metrics (precision / recall / F1)
  - Weighted-confidence vote metrics
  - Fleiss' kappa (inter-rater agreement across all judges)
  - Pairwise Cohen's kappa between each judge pair
  - Paired bootstrap vs. best single-LLM (Exp B)

Outputs
-------
datasets/processed/exp_d_results.json
datasets/processed/exp_d_summary.md

Usage
-----
    python experiments/exp_d_consensus.py
    python experiments/exp_d_consensus.py --mock
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from itertools import combinations
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm.base_judge import BaseLLMJudge, JudgeConfig, JudgeResult
from src.llm.consensus_engine import ConsensusConfig, ConsensusEngine
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix
from src.evaluation.statistical_tests import cohens_kappa, fleiss_kappa, paired_bootstrap

DATASET_PATH = ROOT / "datasets" / "benchmark" / "seed_dataset.json"
OUTPUT_DIR   = ROOT / "datasets" / "processed"
EXP_B_PATH   = OUTPUT_DIR / "exp_b_results.json"


# ---------------------------------------------------------------------------
# Mock judge (same pattern as Exp B/C)
# ---------------------------------------------------------------------------

class ConsensusMockJudge(BaseLLMJudge):
    def __init__(self, model_name: str, accuracy: float, seed: int) -> None:
        super().__init__(JudgeConfig(model_name=model_name))
        self._accuracy = accuracy
        self._rng = random.Random(seed)

    @property
    def provider_name(self) -> str:
        return "mock-consensus"

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
            reasoning="Mock",
            exploitability="mock",
            remediation="N/A",
            raw_response="{}",
            latency_ms=10.0,
        )


def _build_judges(force_mock: bool) -> List[BaseLLMJudge]:
    judges: List[BaseLLMJudge] = []
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    if not force_mock and gemini_key:
        try:
            from src.llm.gemini_judge import GeminiJudge
            judges.append(GeminiJudge(JudgeConfig(model_name="gemini-1.5-flash")))
            print("[Exp D] Using live GeminiJudge")
        except Exception as exc:
            print(f"[Exp D] GeminiJudge unavailable ({exc})")
    if not judges:
        print("[Exp D] Using mock judges for consensus")
        judges = [
            ConsensusMockJudge("model-alpha",  accuracy=0.88, seed=111),
            ConsensusMockJudge("model-beta",   accuracy=0.82, seed=222),
            ConsensusMockJudge("model-gamma",  accuracy=0.76, seed=333),
        ]
    return judges


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(force_mock: bool = False) -> dict:
    with open(DATASET_PATH, encoding="utf-8") as fh:
        samples = json.load(fh)

    judges = _build_judges(force_mock)
    engine = ConsensusEngine(ConsensusConfig(vulnerability_threshold=0.5))

    # Collect per-model and consensus predictions
    per_model_preds: dict[str, list[bool]]   = {j.config.model_name: [] for j in judges}
    per_model_confs: dict[str, list[float]]  = {j.config.model_name: [] for j in judges}
    majority_preds:   list[bool] = []
    weighted_preds:   list[bool] = []

    for sample in samples:
        code = sample["code"]
        gt   = sample["expected_is_vulnerable"]

        judge_results: list[JudgeResult] = []
        for judge in judges:
            if isinstance(judge, ConsensusMockJudge):
                judge._ground_truth = gt  # type: ignore[attr-defined]
            try:
                jr: JudgeResult = judge.analyze_code(code, [])
            except Exception as exc:
                jr = JudgeResult(
                    model_name=judge.config.model_name,
                    is_vulnerable=False, vulnerability_type="error",
                    cwe="CWE-000", severity="INFO", confidence=0.0,
                    reasoning=str(exc), exploitability="N/A",
                    remediation="N/A", raw_response="", latency_ms=0.0,
                )
            judge_results.append(jr)
            per_model_preds[judge.config.model_name].append(jr.is_vulnerable)
            per_model_confs[judge.config.model_name].append(jr.confidence)

        consensus = engine.aggregate(judge_results)
        # Majority vote: > 50% of models say vulnerable
        n_vuln = sum(1 for jr in judge_results if jr.is_vulnerable)
        majority_preds.append(n_vuln > len(judge_results) / 2)
        weighted_preds.append(consensus.is_vulnerable)

    expected = [s["expected_is_vulnerable"] for s in samples]

    # Overall consensus metrics
    cm_maj = ConfusionMatrix.from_predictions(expected=expected, predicted=majority_preds)
    m_maj  = BinaryClassificationMetrics.from_confusion_matrix(cm_maj)
    cm_wt  = ConfusionMatrix.from_predictions(expected=expected, predicted=weighted_preds)
    m_wt   = BinaryClassificationMetrics.from_confusion_matrix(cm_wt)

    # Fleiss' kappa across all judges
    model_names = list(per_model_preds.keys())
    rating_matrix = []
    for i in range(len(samples)):
        n_vuln_i = sum(per_model_preds[mn][i] for mn in model_names)
        n_safe_i = len(model_names) - n_vuln_i
        rating_matrix.append([n_vuln_i, n_safe_i])
    fleiss = fleiss_kappa(rating_matrix, n_categories=2)

    # Pairwise Cohen's kappa
    pairwise_kappa: dict = {}
    for mn_a, mn_b in combinations(model_names, 2):
        ck = cohens_kappa(per_model_preds[mn_a], per_model_preds[mn_b])
        pairwise_kappa[f"{mn_a} vs {mn_b}"] = {
            "kappa": round(ck.kappa, 4),
            "interpretation": ck.interpretation,
        }

    # Bootstrap vs best single model in Exp B
    bootstrap_vs_best: dict = {}
    if EXP_B_PATH.exists():
        exp_b = json.loads(EXP_B_PATH.read_text())
        # Find best model by F1
        best_model = max(
            exp_b["models_evaluated"],
            key=lambda mn: exp_b["per_model_metrics"][mn]["f1_score"],
        )
        best_preds = [
            s["predictions"][best_model]
            for s in exp_b["sample_level"]
        ]
        bs = paired_bootstrap(expected, best_preds, majority_preds, metric="f1")
        bootstrap_vs_best = {
            "baseline_model": best_model,
            "delta_f1": round(bs.delta, 4),
            "p_value": round(bs.p_value, 4),
            "significant": bs.significant,
        }

    return {
        "experiment": "D",
        "name": "Multi-LLM Consensus",
        "n_samples": len(samples),
        "n_judges": len(judges),
        "models_evaluated": model_names,
        "majority_vote_metrics": {**cm_maj.to_dict(), **m_maj.to_dict()},
        "weighted_vote_metrics": {**cm_wt.to_dict(), **m_wt.to_dict()},
        "fleiss_kappa": {
            "kappa": round(fleiss.kappa, 4),
            "interpretation": fleiss.interpretation,
        },
        "pairwise_cohens_kappa": pairwise_kappa,
        "significance_vs_best_single": bootstrap_vs_best,
        "sample_level": [
            {
                "sample_id": s["sample_id"],
                "cwe": s["cwe"],
                "domain": s.get("domain", "general_python"),
                "difficulty": s["difficulty"],
                "expected": s["expected_is_vulnerable"],
                "majority_pred": majority_preds[i],
                "weighted_pred": weighted_preds[i],
                "per_model": {mn: per_model_preds[mn][i] for mn in model_names},
            }
            for i, s in enumerate(samples)
        ],
    }


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_d_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[Exp D] JSON  -> {json_path}")

    fk = result["fleiss_kappa"]
    bs = result["significance_vs_best_single"]
    mm = result["majority_vote_metrics"]
    wm = result["weighted_vote_metrics"]

    md_lines = [
        "# Experiment D — Multi-LLM Consensus",
        "",
        f"**Samples:** {result['n_samples']}  |  "
        f"**Judges:** {result['n_judges']}  |  "
        f"**Fleiss' κ:** {fk['kappa']:.3f} ({fk['interpretation']})",
        "",
        "## Consensus strategy metrics",
        "",
        "| Strategy | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---:|---:|---:|",
        f"| Majority vote | {mm.get('precision',0):.3f} | {mm.get('recall',0):.3f} | "
        f"{mm.get('f1_score',0):.3f} | {mm.get('accuracy',0):.3f} |",
        f"| Weighted confidence | {wm.get('precision',0):.3f} | {wm.get('recall',0):.3f} | "
        f"{wm.get('f1_score',0):.3f} | {wm.get('accuracy',0):.3f} |",
        "",
        "## Pairwise Cohen's κ",
        "",
        "| Pair | κ | Interpretation |",
        "|---|---:|---|",
    ]
    for pair, ck in result["pairwise_cohens_kappa"].items():
        md_lines.append(f"| {pair} | {ck['kappa']:.3f} | {ck['interpretation']} |")

    if bs:
        md_lines += [
            "",
            "## Significance vs. best single-LLM (paired bootstrap, F1)",
            "",
            f"Baseline: **{bs.get('baseline_model')}**  |  "
            f"ΔF1 = {bs.get('delta_f1')}  |  "
            f"p = {bs.get('p_value')}  |  "
            f"Significant: {bs.get('significant')}",
        ]

    md_path = OUTPUT_DIR / "exp_d_summary.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[Exp D] MD    -> {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Experiment D")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--mock",    dest="mock", action="store_true",  default=None)
    grp.add_argument("--no-mock", dest="mock", action="store_false")
    args = parser.parse_args()

    result = run(force_mock=args.mock is True)
    write_outputs(result)

    fk = result["fleiss_kappa"]
    mm = result["majority_vote_metrics"]
    print(
        f"\n[Exp D] Majority-vote: F1={mm['f1_score']:.3f}  "
        f"Fleiss' κ={fk['kappa']:.3f} ({fk['interpretation']})"
    )
