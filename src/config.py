"""Centralised, environment-overridable paths — the single source of truth.

Why this module exists
----------------------
Every experiment used to hard-code paths like ``ROOT / "datasets" / "processed"``.
That is fine on a laptop, but in Google Colab we want outputs to land on a
*mounted Google Drive* folder so nothing is lost when the runtime disconnects.

Think of this module as a **power adapter**: the experiments always ask for
"the output socket"; this module decides whether that socket is wired to the
local repo folder or to ``/content/drive/MyDrive/VERDICT`` — depending on a few
environment variables. Same plug, different wall.

Backwards compatibility
-----------------------
If **no** environment variables are set, every path resolves to exactly the
same location it did before this module existed. Existing local runs are
unaffected.

Environment variables
----------------------
================================  ==========================================
Variable                          Overrides
================================  ==========================================
``VERDICT_DATA_DIR``              base ``datasets/`` directory
``VERDICT_OUTPUT_DIR``            processed results directory
``VERDICT_BENCHMARK_FILE``       primary benchmark JSON (Exp A–D, F)
``VERDICT_SEED_FILE``            paired seed JSON (Exp E)
``VERDICT_ADVERSARIAL_DIR``      transformed adversarial samples (Exp F)
================================  ==========================================

Usage
-----
    from src.config import BENCHMARK_PATH, SEED_PATH, PROCESSED_DIR
"""

from __future__ import annotations

import os
from pathlib import Path

# Repo root = parent directory of this file's package (src/ -> repo root).
ROOT: Path = Path(__file__).resolve().parent.parent


def _path_env(name: str, default: Path) -> Path:
    """Return an absolute Path from env var ``name`` or ``default`` if unset/empty."""
    raw = os.getenv(name, "").strip()
    return Path(raw).expanduser().resolve() if raw else default


# --- Base data directory -----------------------------------------------------
DATA_DIR: Path = _path_env("VERDICT_DATA_DIR", ROOT / "datasets")

BENCHMARK_DIR: Path = DATA_DIR / "benchmark"
PROCESSED_DIR: Path = _path_env("VERDICT_OUTPUT_DIR", DATA_DIR / "processed")
ADVERSARIAL_DIR: Path = _path_env("VERDICT_ADVERSARIAL_DIR", DATA_DIR / "adversarial")

# --- Individual dataset files ------------------------------------------------
BENCHMARK_PATH: Path = _path_env(
    "VERDICT_BENCHMARK_FILE", BENCHMARK_DIR / "securityeval_dataset.json"
)
SEED_PATH: Path = _path_env(
    "VERDICT_SEED_FILE", BENCHMARK_DIR / "seed_dataset.json"
)

# --- Figures output (used by src/evaluation/figures.py) ----------------------
FIGURES_DIR: Path = _path_env("VERDICT_FIGURES_DIR", PROCESSED_DIR / "figures")


def ensure_dirs() -> None:
    """Create the writable output directories if they do not yet exist."""
    for d in (PROCESSED_DIR, ADVERSARIAL_DIR, FIGURES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def summary() -> dict[str, str]:
    """Return a JSON-friendly snapshot of resolved paths (handy in Colab)."""
    return {
        "ROOT": str(ROOT),
        "DATA_DIR": str(DATA_DIR),
        "BENCHMARK_DIR": str(BENCHMARK_DIR),
        "PROCESSED_DIR": str(PROCESSED_DIR),
        "ADVERSARIAL_DIR": str(ADVERSARIAL_DIR),
        "BENCHMARK_PATH": str(BENCHMARK_PATH),
        "SEED_PATH": str(SEED_PATH),
        "FIGURES_DIR": str(FIGURES_DIR),
    }


if __name__ == "__main__":  # pragma: no cover — manual inspection helper
    import json

    print(json.dumps(summary(), indent=2))
