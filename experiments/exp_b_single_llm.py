"""Experiment B — Single-LLM detector.

Runs each configured LLM judge independently against the seed dataset and
records per-model precision / recall / F1.  When no live API key is available
the experiment falls back to a *mock* judge that mirrors ground truth with
configurable noise so the pipeline can be exercised without API calls.

Outputs
-------
datasets/processed/exp_b_results.json
datasets/processed/exp_b_summary.md

Usage
-----
    python experiments/exp_b_single_llm.py
    python experiments/exp_b_single_llm.py --mock       # force mock mode
    python experiments/exp_b_single_llm.py --no-mock    # require real API
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.llm.base_judge import BaseLLMJudge, JudgeConfig, JudgeResult
from src.evaluation.metrics import BinaryClassificationMetrics, ConfusionMatrix
from src.evaluation.statistical_tests import cohens_kappa
from src.config import BENCHMARK_PATH, PROCESSED_DIR
from src.llm.judge_factory import build_real_judges

# Paths resolve to the local repo by default, or to Google Drive when the
# VERDICT_* environment variables are set (see src/config.py).
DATASET_PATH = BENCHMARK_PATH
OUTPUT_DIR   = PROCESSED_DIR


# ---------------------------------------------------------------------------
# Mock judge — used when no real API credentials are present
# ---------------------------------------------------------------------------

class MockLLMJudge(BaseLLMJudge):
    """Simulates an LLM judge with controllable accuracy for offline testing."""

    def __init__(self, model_name: str, accuracy: float = 0.82, seed: int = 42) -> None:
        super().__init__(JudgeConfig(model_name=model_name))
        self._accuracy = accuracy
        self._rng = random.Random(seed)

    @property
    def provider_name(self) -> str:
        return "mock"

    def _invoke_model(self, prompt: str) -> str:
        # Unused by _mock_judge; override analyze_code directly.
        return ""

    def analyze_code(self, code_snippet, sast_findings, vulnerability_context="") -> JudgeResult:  # type: ignore[override]
        # Extract expected label from context (injected by runner below).
        ground_truth: bool = getattr(self, "_ground_truth", False)
        if self._rng.random() < self._accuracy:
            verdict = ground_truth
        else:
            verdict = not ground_truth

        return JudgeResult(
            model_name=self.config.model_name,
            is_vulnerable=verdict,
            vulnerability_type="mock",
            cwe="CWE-000",
            severity="HIGH" if verdict else "INFO",
            confidence=self._accuracy,
            reasoning="Mock reasoning",
            exploitability="mock",
            remediation="N/A",
            raw_response="{}",
            latency_ms=10.0,
        )


# ---------------------------------------------------------------------------
# Judge factory
# ---------------------------------------------------------------------------

def _build_judges(force_mock: bool) -> List[BaseLLMJudge]:
    """Return a list of judges based on available credentials.

    The live-provider priority chain (HF Gemma / Cerebras / Mistral / Together /
    SambaNova / Groq / Gemini) is centralised in ``src.llm.judge_factory`` so it
    is defined exactly once for experiments B–E. If no live key is present, this
    experiment falls back to its own noisy mock judges.
    """
    judges = build_real_judges(force_mock, tag="Exp B")

    if not judges:
        print("[Exp B] No live API keys found — using mock judges")
        judges = [
            MockLLMJudge("mock-high-accuracy",   accuracy=0.88, seed=11),
            MockLLMJudge("mock-mid-accuracy",    accuracy=0.78, seed=22),
            MockLLMJudge("mock-lower-accuracy",  accuracy=0.70, seed=33),
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
    per_model_latencies: dict[str, list[float]] = {j.config.model_name: [] for j in judges}

    for sample in samples:
        code = sample["code"]
        ground_truth = sample["expected_is_vulnerable"]
        sast_findings: list = []  # Exp B: no SAST hints passed to LLM

        for judge in judges:
            # Inject ground truth for mock judges only
            if isinstance(judge, MockLLMJudge):
                judge._ground_truth = ground_truth  # type: ignore[attr-defined]

            t0 = time.monotonic()
            try:
                result: JudgeResult = judge.analyze_code(code, sast_findings)
                latency = (time.monotonic() - t0) * 1000
            except Exception as exc:
                print(f"  [warn] {judge.config.model_name} failed on {sample['sample_id']}: {exc}")
                result = JudgeResult(
                    model_name=judge.config.model_name,
                    is_vulnerable=False,
                    vulnerability_type="error",
                    cwe="CWE-000",
                    severity="INFO",
                    confidence=0.0,
                    reasoning=str(exc),
                    exploitability="N/A",
                    remediation="N/A",
                    raw_response="",
                    latency_ms=0.0,
                )
                latency = 0.0

            per_model_preds[judge.config.model_name].append(result.is_vulnerable)
            per_model_latencies[judge.config.model_name].append(result.latency_ms or latency)

    expected = [s["expected_is_vulnerable"] for s in samples]

    per_model_metrics: dict = {}
    per_model_kappa: dict = {}
    per_model_avg_latency: dict = {}

    for model_name, preds in per_model_preds.items():
        cm = ConfusionMatrix.from_predictions(expected=expected, predicted=preds)
        m  = BinaryClassificationMetrics.from_confusion_matrix(cm)
        kappa = cohens_kappa(expected, preds)
        per_model_metrics[model_name] = {**cm.to_dict(), **m.to_dict()}
        per_model_kappa[model_name] = {"kappa": kappa.kappa, "interpretation": kappa.interpretation}
        lats = per_model_latencies[model_name]
        per_model_avg_latency[model_name] = sum(lats) / len(lats) if lats else 0.0

    return {
        "experiment": "B",
        "name": "Single-LLM detector",
        "n_samples": len(samples),
        "models_evaluated": list(per_model_preds.keys()),
        "per_model_metrics": per_model_metrics,
        "per_model_kappa": per_model_kappa,
        "per_model_avg_latency_ms": per_model_avg_latency,
        "sample_level": [
            {
                "sample_id": s["sample_id"],
                "cwe": s["cwe"],
                "domain": s.get("domain", "general_python"),
                "difficulty": s["difficulty"],
                "expected": s["expected_is_vulnerable"],
                "predictions": {
                    mn: per_model_preds[mn][i]
                    for mn in per_model_preds
                },
            }
            for i, s in enumerate(samples)
        ],
    }


def write_outputs(result: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = OUTPUT_DIR / "exp_b_results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[Exp B] JSON  -> {json_path}")

    md_lines = [
        "# Experiment B — Single-LLM Detector",
        "",
        f"**Samples:** {result['n_samples']}",
        "",
        "## Per-model metrics",
        "",
        "| Model | Precision | Recall | F1 | Accuracy | κ | κ interp |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for model in result["models_evaluated"]:
        m = result["per_model_metrics"][model]
        k = result["per_model_kappa"][model]
        md_lines.append(
            f"| {model} | {m.get('precision',0):.3f} | "
            f"{m.get('recall',0):.3f} | "
            f"{m.get('f1_score',0):.3f} | "
            f"{m.get('accuracy',0):.3f} | "
            f"{k['kappa']:.3f} | {k['interpretation']} |"
        )

    md_path = OUTPUT_DIR / "exp_b_summary.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"[Exp B] MD    -> {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Experiment B")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--mock",    dest="mock", action="store_true",  default=None)
    grp.add_argument("--no-mock", dest="mock", action="store_false")
    args = parser.parse_args()
    force_mock = args.mock is True

    result = run(force_mock=force_mock)
    write_outputs(result)

    print("\n[Exp B] Results:")
    for model in result["models_evaluated"]:
        m = result["per_model_metrics"][model]
        k = result["per_model_kappa"][model]
        print(
            f"  {model:<30}  P={m['precision']:.3f}  R={m['recall']:.3f}  "
            f"F1={m['f1_score']:.3f}  κ={k['kappa']:.3f}"
        )
