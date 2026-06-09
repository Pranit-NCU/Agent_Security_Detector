"""Run all VERDICT experiments (A–F) in sequence.

Usage
-----
    python experiments/run_all.py           # auto-detect API keys
    python experiments/run_all.py --mock    # force offline/mock mode
    python experiments/run_all.py --exp A B D  # run only selected experiments
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import experiments.exp_a_sast_baseline as exp_a
import experiments.exp_b_single_llm    as exp_b
import experiments.exp_c_hybrid        as exp_c
import experiments.exp_d_consensus     as exp_d
import experiments.exp_e_paired        as exp_e
import experiments.exp_f_adversarial   as exp_f

OUTPUT_DIR = ROOT / "datasets" / "processed"

EXPERIMENT_MAP = {
    "A": (exp_a.run, exp_a.write_outputs),
    "B": (exp_b.run, exp_b.write_outputs),
    "C": (exp_c.run, exp_c.write_outputs),
    "D": (exp_d.run, exp_d.write_outputs),
    "E": (exp_e.run, exp_e.write_outputs),
    "F": (exp_f.run, exp_f.write_outputs),
}


def run_all(experiments: list[str], force_mock: bool) -> dict:
    summary: dict = {}

    for exp_id in experiments:
        runner, writer = EXPERIMENT_MAP[exp_id]
        print(f"\n{'='*60}")
        print(f"  Experiment {exp_id}")
        print(f"{'='*60}")
        t0 = time.monotonic()

        kwargs = {}
        if exp_id != "A":          # Exp A has no mock parameter
            kwargs["force_mock"] = force_mock

        try:
            result = runner(**kwargs)
            writer(result)
            elapsed = time.monotonic() - t0
            summary[exp_id] = {"status": "ok", "elapsed_s": round(elapsed, 2)}
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"[ERROR] Experiment {exp_id} failed: {exc}")
            summary[exp_id] = {"status": "error", "error": str(exc), "elapsed_s": round(elapsed, 2)}

    return summary


def print_summary(summary: dict) -> None:
    print(f"\n{'='*60}")
    print("  VERDICT Run Summary")
    print(f"{'='*60}")
    for exp_id, info in summary.items():
        status = "✓" if info["status"] == "ok" else "✗"
        print(f"  {status} Exp {exp_id}  ({info['elapsed_s']:.1f}s)")
        if info["status"] == "error":
            print(f"       └─ {info['error']}")
    print(f"{'='*60}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run all VERDICT experiments")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--mock",    dest="mock", action="store_true",  default=None)
    grp.add_argument("--no-mock", dest="mock", action="store_false")
    parser.add_argument(
        "--exp", nargs="+", choices=list(EXPERIMENT_MAP.keys()),
        default=list(EXPERIMENT_MAP.keys()),
        help="Experiments to run (default: all)",
    )
    args = parser.parse_args()

    force_mock = args.mock is True
    summary = run_all(experiments=args.exp, force_mock=force_mock)
    print_summary(summary)

    # Write consolidated summary
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "run_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    all_ok = all(v["status"] == "ok" for v in summary.values())
    sys.exit(0 if all_ok else 1)
