"""Experiment A — SAST-only baseline.

Runs all three SAST detectors (SQLInjectionDetector, SecretsDetector,
AuthDetector) against the labelled seed dataset.  For each sample the
combined detector produces a binary verdict (vulnerable / not vulnerable)
which is compared against the ground-truth label.

Outputs
-------
datasets/processed/exp_a_results.json   machine-readable metrics
datasets/processed/exp_a_summary.md     dissertation-ready markdown table

Usage
-----
    python -m experiments.exp_a_sast_baseline
    python experiments/exp_a_sast_baseline.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make sure project root is on sys.path when run directly.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detectors import (
    SQLInjectionDetector,
    SecretsDetector,
    AuthDetector,
    VulnerabilitySeverity,
)
from src.evaluation.metrics import ConfusionMatrix, BinaryClassificationMetrics
from src.evaluation.statistical_tests import cohens_kappa
from src.config import BENCHMARK_PATH, PROCESSED_DIR

# Paths resolve to the local repo by default, or to Google Drive when the
# VERDICT_* environment variables are set (see src/config.py).
DATASET_PATH = BENCHMARK_PATH
OUTPUT_DIR   = PROCESSED_DIR


# ---------------------------------------------------------------------------
# Load dataset
# ---------------------------------------------------------------------------

def load_samples(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# SAST prediction
# ---------------------------------------------------------------------------

def sast_predict(code: str, detectors) -> bool:
    """Return True if any SAST detector finds a CRITICAL or HIGH finding."""
    for det in detectors:
        vulns = det.detect(code)
        for v in vulns:
            if v.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
                return True
    return False


# ---------------------------------------------------------------------------
# Per-CWE breakdown
# ---------------------------------------------------------------------------

def metrics_for_subset(samples: list[dict], predictions: list[bool]) -> dict:
    expected  = [s["expected_is_vulnerable"] for s in samples]
    cm = ConfusionMatrix.from_predictions(expected=expected, predicted=predictions)
    m  = BinaryClassificationMetrics.from_confusion_matrix(cm)
    return {**cm.to_dict(), **m.to_dict()}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run() -> dict:
    samples = load_samples(DATASET_PATH)

    detectors = [SQLInjectionDetector(), SecretsDetector(), AuthDetector()]

    predictions: list[bool] = []
    for sample in samples:
        predictions.append(sast_predict(sample["code"], detectors))

    expected = [s["expected_is_vulnerable"] for s in samples]

    # Overall metrics
    cm      = ConfusionMatrix.from_predictions(expected=expected, predicted=predictions)
    metrics = BinaryClassificationMetrics.from_confusion_matrix(cm)

    # Per-CWE breakdown
    cwe_groups: dict[str, list] = {}
    for sample, pred in zip(samples, predictions):
        cwe = sample["cwe"]
        cwe_groups.setdefault(cwe, {"samples": [], "preds": []})
        cwe_groups[cwe]["samples"].append(sample)
        cwe_groups[cwe]["preds"].append(pred)

    per_cwe: dict = {}
    for cwe, data in cwe_groups.items():
        per_cwe[cwe] = metrics_for_subset(data["samples"], data["preds"])

    # Per-difficulty breakdown
    diff_groups: dict[str, list] = {}
    for sample, pred in zip(samples, predictions):
        d = sample["difficulty"]
        diff_groups.setdefault(d, {"samples": [], "preds": []})
        diff_groups[d]["samples"].append(sample)
        diff_groups[d]["preds"].append(pred)

    per_difficulty: dict = {}
    for diff, data in diff_groups.items():
        per_difficulty[diff] = metrics_for_subset(data["samples"], data["preds"])

    # Cohen's kappa between SAST decision and ground truth (treated as two raters)
    kappa = cohens_kappa(expected, predictions)

    result = {
        "experiment": "A",
        "name": "SAST-only baseline",
        "n_samples": len(samples),
        "confusion_matrix": cm.to_dict(),
        "overall_metrics": metrics.to_dict(),
        "cohens_kappa": kappa.kappa,
        "kappa_interpretation": kappa.interpretation,
        "per_cwe": per_cwe,
        "per_difficulty": per_difficulty,
        "sample_level": [
            {
                "sample_id": s["sample_id"],
                "cwe": s["cwe"],
                "domain": s.get("domain", "general_python"),
                "difficulty": s["difficulty"],
                "expected": s["expected_is_vulnerable"],
                "predicted": pred,
                "correct": s["expected_is_vulnerable"] == pred,
            }
            for s, pred in zip(samples, predictions)
        ],
    }

    return result


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_a_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[Exp A] JSON  -> {json_path}")

    md_lines = [
        "# Experiment A — SAST-only Baseline",
        "",
        f"**Samples:** {result['n_samples']}  |  "
        f"**Cohen's κ:** {result['cohens_kappa']:.3f} "
        f"({result['kappa_interpretation']})",
        "",
        "## Overall metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for k, v in result["overall_metrics"].items():
        md_lines.append(f"| {k} | {v:.3f} |")

    md_lines += ["", "## Per-CWE breakdown", "",
                 "| CWE | Precision | Recall | F1 | Accuracy |",
                 "|---|---:|---:|---:|---:|"]
    for cwe, m in result["per_cwe"].items():
        md_lines.append(
            f"| {cwe} | {m.get('precision',0):.3f} | "
            f"{m.get('recall',0):.3f} | "
            f"{m.get('f1_score',0):.3f} | "
            f"{m.get('accuracy',0):.3f} |"
        )

    md_lines += ["", "## Per-difficulty breakdown", "",
                 "| Difficulty | Precision | Recall | F1 | Accuracy |",
                 "|---|---:|---:|---:|---:|"]
    for diff, m in result["per_difficulty"].items():
        md_lines.append(
            f"| {diff} | {m.get('precision',0):.3f} | "
            f"{m.get('recall',0):.3f} | "
            f"{m.get('f1_score',0):.3f} | "
            f"{m.get('accuracy',0):.3f} |"
        )

    md_path = OUTPUT_DIR / "exp_a_summary.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[Exp A] MD    -> {md_path}")


if __name__ == "__main__":
    result = run()
    write_outputs(result)

    om = result["overall_metrics"]
    print(
        f"\n[Exp A] n={result['n_samples']}  "
        f"P={om['precision']:.3f}  R={om['recall']:.3f}  "
        f"F1={om['f1_score']:.3f}  κ={result['cohens_kappa']:.3f}"
    )
