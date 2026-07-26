"""Experiment C — Hybrid SAST + LLM detector.

Passes SAST findings as structured context into each LLM judge's prompt,
implementing the hybrid fusion strategy.  Results are compared against:
  - Exp A (SAST-only) loaded from exp_a_results.json
  - Exp B (LLM-only)  loaded from exp_b_results.json

Statistical significance of the delta vs. SAST-only is tested with the
paired bootstrap procedure.

Outputs
-------
datasets/processed/exp_c_results.json
datasets/processed/exp_c_summary.md

Usage
-----
    python experiments/exp_c_hybrid.py
    python experiments/exp_c_hybrid.py --mock
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detectors import SQLInjectionDetector, SecretsDetector, AuthDetector, VulnerabilitySeverity
from src.llm.base_judge import BaseLLMJudge, JudgeConfig, JudgeResult
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix
from src.evaluation.statistical_tests import cohens_kappa, paired_bootstrap
from src.config import BENCHMARK_PATH, PROCESSED_DIR
from src.llm.judge_factory import build_real_judges

# Paths resolve to the local repo by default, or to Google Drive when the
# VERDICT_* environment variables are set (see src/config.py).
DATASET_PATH  = BENCHMARK_PATH
OUTPUT_DIR    = PROCESSED_DIR
EXP_A_PATH    = OUTPUT_DIR / "exp_a_results.json"
EXP_B_PATH    = OUTPUT_DIR / "exp_b_results.json"

SAST_DETECTORS = [SQLInjectionDetector(), SecretsDetector(), AuthDetector()]


# ---------------------------------------------------------------------------
# Mock judge (same pattern as Exp B, but uses sast_findings to boost accuracy)
# ---------------------------------------------------------------------------

class HybridMockJudge(BaseLLMJudge):
    """Mock that slightly improves accuracy when SAST findings are present."""

    def __init__(self, model_name: str, base_accuracy: float = 0.82, seed: int = 99) -> None:
        super().__init__(JudgeConfig(model_name=model_name))
        self._base = base_accuracy
        self._rng = random.Random(seed)

    @property
    def provider_name(self) -> str:
        return "mock-hybrid"

    def _invoke_model(self, prompt: str) -> str:
        return ""

    def analyze_code(self, code_snippet, sast_findings, vulnerability_context="") -> JudgeResult:  # type: ignore[override]
        ground_truth: bool = getattr(self, "_ground_truth", False)
        # If SAST already flagged it, boost accuracy
        sast_flagged = len(sast_findings) > 0
        accuracy = min(0.98, self._base + (0.06 if sast_flagged else 0.0))
        verdict = ground_truth if self._rng.random() < accuracy else not ground_truth

        return JudgeResult(
            model_name=self.config.model_name,
            is_vulnerable=verdict,
            vulnerability_type="mock",
            cwe="CWE-000",
            severity="HIGH" if verdict else "INFO",
            confidence=accuracy,
            reasoning="Mock hybrid reasoning",
            exploitability="mock",
            remediation="N/A",
            raw_response="{}",
            latency_ms=12.0,
        )


# ---------------------------------------------------------------------------
# SAST helpers
# ---------------------------------------------------------------------------

def get_sast_findings(code: str) -> list[dict]:
    findings = []
    for det in SAST_DETECTORS:
        for v in det.detect(code):
            findings.append({
                "cwe": v.cwe.value,
                "severity": v.severity.name,
                "line_number": v.line_number,
                "description": v.description,
                "confidence": v.confidence,
            })
    return findings


def sast_verdict(findings: list[dict]) -> bool:
    critical_high = {VulnerabilitySeverity.CRITICAL.name, VulnerabilitySeverity.HIGH.name}
    return any(f["severity"] in critical_high for f in findings)


# ---------------------------------------------------------------------------
# Judge factory
# ---------------------------------------------------------------------------

def _build_judges(force_mock: bool) -> List[BaseLLMJudge]:
    """Live-judge chain centralised in ``src.llm.judge_factory``.

    Exp C passes SAST findings into each judge — all real judges support this.
    Falls back to hybrid mock judges when no live API key is available.
    """
    judges = build_real_judges(force_mock, tag="Exp C")

    if not judges:
        print("[Exp C] Using mock hybrid judges")
        judges = [
            HybridMockJudge("hybrid-mock-high", base_accuracy=0.88, seed=101),
            HybridMockJudge("hybrid-mock-mid",  base_accuracy=0.78, seed=202),
        ]
    return judges


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(force_mock: bool = False) -> dict:
    with open(DATASET_PATH, encoding="utf-8") as fh:
        samples = json.load(fh)

    judges = _build_judges(force_mock)

    per_model_preds: dict[str, list[bool]] = {j.config.model_name: [] for j in judges}
    sast_preds: list[bool] = []

    for sample in samples:
        code = sample["code"]
        gt   = sample["expected_is_vulnerable"]
        findings = get_sast_findings(code)
        sast_preds.append(sast_verdict(findings))

        for judge in judges:
            if isinstance(judge, HybridMockJudge):
                judge._ground_truth = gt  # type: ignore[attr-defined]
            try:
                result: JudgeResult = judge.analyze_code(code, findings)
            except Exception as exc:
                print(f"  [warn] {judge.config.model_name} failed: {exc}")
                result = JudgeResult(
                    model_name=judge.config.model_name,
                    is_vulnerable=False, vulnerability_type="error",
                    cwe="CWE-000", severity="INFO", confidence=0.0,
                    reasoning=str(exc), exploitability="N/A",
                    remediation="N/A", raw_response="", latency_ms=0.0,
                )
            per_model_preds[judge.config.model_name].append(result.is_vulnerable)

    expected = [s["expected_is_vulnerable"] for s in samples]

    # Compute metrics
    per_model_metrics: dict = {}
    per_model_kappa: dict   = {}
    for mn, preds in per_model_preds.items():
        cm = ConfusionMatrix.from_predictions(expected=expected, predicted=preds)
        m  = BinaryClassificationMetrics.from_confusion_matrix(cm)
        kappa = cohens_kappa(expected, preds)
        per_model_metrics[mn] = {**cm.to_dict(), **m.to_dict()}
        per_model_kappa[mn] = {"kappa": kappa.kappa, "interpretation": kappa.interpretation}

    # Load Exp A SAST baseline for significance test
    sast_bootstrap: dict = {}
    if EXP_A_PATH.exists():
        exp_a = json.loads(EXP_A_PATH.read_text())
        sast_a_preds = [s["predicted"] for s in exp_a["sample_level"]]
        for mn, hybrid_preds in per_model_preds.items():
            bs = paired_bootstrap(expected, sast_a_preds, hybrid_preds, metric="f1")
            sast_bootstrap[mn] = {
                "delta_f1": round(bs.delta, 4),
                "p_value": round(bs.p_value, 4),
                "significant": bs.significant,
            }

    return {
        "experiment": "C",
        "name": "Hybrid SAST+LLM",
        "n_samples": len(samples),
        "models_evaluated": list(per_model_preds.keys()),
        "per_model_metrics": per_model_metrics,
        "per_model_kappa": per_model_kappa,
        "significance_vs_sast_only": sast_bootstrap,
        "sample_level": [
            {
                "sample_id": s["sample_id"],
                "cwe": s["cwe"],
                "domain": s.get("domain", "general_python"),
                "difficulty": s["difficulty"],
                "expected": s["expected_is_vulnerable"],
                "sast_pred": sast_preds[i],
                "hybrid_preds": {mn: per_model_preds[mn][i] for mn in per_model_preds},
            }
            for i, s in enumerate(samples)
        ],
    }


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_c_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[Exp C] JSON  -> {json_path}")

    md_lines = [
        "# Experiment C — Hybrid SAST + LLM",
        "",
        f"**Samples:** {result['n_samples']}",
        "",
        "## Per-model hybrid metrics",
        "",
        "| Model | Precision | Recall | F1 | Accuracy | κ | ΔF1 vs SAST | p-value |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model in result["models_evaluated"]:
        m  = result["per_model_metrics"][model]
        k  = result["per_model_kappa"][model]
        bs = result["significance_vs_sast_only"].get(model, {})
        md_lines.append(
            f"| {model} | {m.get('precision',0):.3f} | "
            f"{m.get('recall',0):.3f} | "
            f"{m.get('f1_score',0):.3f} | "
            f"{m.get('accuracy',0):.3f} | "
            f"{k['kappa']:.3f} | "
            f"{bs.get('delta_f1', 'N/A')} | "
            f"{bs.get('p_value', 'N/A')} |"
        )

    md_path = OUTPUT_DIR / "exp_c_summary.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[Exp C] MD    -> {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Experiment C")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--mock",    dest="mock", action="store_true",  default=None)
    grp.add_argument("--no-mock", dest="mock", action="store_false")
    args = parser.parse_args()

    result = run(force_mock=args.mock is True)
    write_outputs(result)

    print("\n[Exp C] Results:")
    for model in result["models_evaluated"]:
        m  = result["per_model_metrics"][model]
        bs = result["significance_vs_sast_only"].get(model, {})
        print(
            f"  {model:<30}  F1={m['f1_score']:.3f}  "
            f"ΔF1={bs.get('delta_f1','N/A')}  p={bs.get('p_value','N/A')}"
        )
