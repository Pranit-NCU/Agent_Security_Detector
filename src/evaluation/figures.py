"""Publication-quality figures generated from processed experiment results.

This is the *reporting* layer for the Colab experimentation workflow (and local
runs). It reads the machine-readable ``exp_*_results.json`` files that every
experiment already writes, and renders dissertation-ready PNG charts — so the
figure code is decoupled from the (expensive) experiment execution.

Analogy: the experiments are the *kitchen* (they cook the data); this module is
the *plating* — it never re-cooks, it only arranges what is already on the pass
into something you can put on the page.

Design notes
------------
* Matplotlib only (no seaborn/pandas) to keep the dependency surface tiny.
* Every function is defensive: a missing results file is skipped with a warning
  rather than crashing the batch.
* 300 DPI, colour-blind-friendly palette, tight layout — ready for print.
* On the all-positive SecurityEval benchmark, ROC / PR curves are *degenerate*
  (there are no negative samples), so they are only emitted for the paired
  Exp E data, which does contain patched (negative) members. This is stated
  explicitly rather than drawing a misleading diagonal.

Usage
-----
    from src.evaluation.figures import generate_all
    generate_all()                      # uses src.config paths

    # or from the command line
    python -m src.evaluation.figures
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib

matplotlib.use("Agg")  # headless / Colab-safe backend
import matplotlib.pyplot as plt

from src import config

# Colour-blind-friendly palette (Wong 2011)
_PALETTE = ["#0072B2", "#E69F00", "#009E73", "#D55E00", "#CC79A7", "#56B4E9", "#F0E442"]
_DPI = 300


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(path: Path) -> Optional[dict]:
    if not path.exists():
        print(f"[figures] skip — not found: {path.name}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[figures] skip — could not parse {path.name}: {exc}")
        return None


def _save(fig, out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / name
    fig.savefig(p, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[figures] wrote {p}")
    return p


def _style_ax(ax, title: str, ylabel: str = "", xlabel: str = "") -> None:
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=11)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.3, linewidth=0.6)


# ---------------------------------------------------------------------------
# Individual figures
# ---------------------------------------------------------------------------

def confusion_matrix_figure(cm: Dict[str, int], title: str, out_dir: Path, name: str) -> Optional[Path]:
    """Render a 2x2 confusion matrix heatmap from {tp,fp,tn,fn}."""
    if not cm:
        return None
    grid = [[cm.get("tp", 0), cm.get("fn", 0)],
            [cm.get("fp", 0), cm.get("tn", 0)]]
    fig, ax = plt.subplots(figsize=(4.6, 4.2))
    im = ax.imshow(grid, cmap="Blues")
    ax.set_xticks([0, 1], ["Pred: Vuln", "Pred: Safe"])
    ax.set_yticks([0, 1], ["Actual: Vuln", "Actual: Safe"])
    vmax = max(max(row) for row in grid) or 1
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(grid[i][j]), ha="center", va="center",
                    fontsize=16, fontweight="bold",
                    color="white" if grid[i][j] > vmax * 0.5 else "#222")
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    return _save(fig, out_dir, name)


def grouped_metric_bars(
    labels: List[str],
    series: Dict[str, List[float]],
    title: str,
    out_dir: Path,
    name: str,
    ylabel: str = "Score",
) -> Optional[Path]:
    """Grouped bar chart: one cluster per label, one bar per series key."""
    if not labels or not series:
        return None
    n_series = len(series)
    x = range(len(labels))
    width = 0.8 / n_series
    fig, ax = plt.subplots(figsize=(max(6, 1.6 * len(labels)), 4.6))
    for idx, (sname, vals) in enumerate(series.items()):
        offsets = [i + idx * width - 0.4 + width / 2 for i in x]
        ax.bar(offsets, vals, width=width, label=sname,
               color=_PALETTE[idx % len(_PALETTE)])
    ax.set_xticks(list(x), labels, rotation=20, ha="right", fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=9, frameon=False, ncol=min(n_series, 4))
    _style_ax(ax, title, ylabel=ylabel)
    return _save(fig, out_dir, name)


def horizontal_bars(
    labels: List[str], values: List[float], title: str, out_dir: Path,
    name: str, xlabel: str = "", color_idx: int = 0, vmax: Optional[float] = None,
) -> Optional[Path]:
    if not labels:
        return None
    fig, ax = plt.subplots(figsize=(7, max(2.5, 0.5 * len(labels) + 1.2)))
    ax.barh(labels, values, color=_PALETTE[color_idx % len(_PALETTE)])
    for i, v in enumerate(values):
        ax.text(v + (vmax or max(values) or 1) * 0.01, i, f"{v:.3f}",
                va="center", fontsize=9)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=11)
    if vmax:
        ax.set_xlim(0, vmax)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.invert_yaxis()
    return _save(fig, out_dir, name)


def agreement_matrix_figure(
    pairwise: Dict[str, Dict[str, Any]], title: str, out_dir: Path, name: str
) -> Optional[Path]:
    """Symmetric Cohen's-kappa heatmap from {'A vs B': {'kappa': x}} entries."""
    if not pairwise:
        return None
    models: List[str] = []
    for pair in pairwise:
        a, _, b = pair.partition(" vs ")
        for m in (a.strip(), b.strip()):
            if m and m not in models:
                models.append(m)
    n = len(models)
    if n < 2:
        return None
    idx = {m: i for i, m in enumerate(models)}
    grid = [[1.0 if i == j else float("nan") for j in range(n)] for i in range(n)]
    for pair, val in pairwise.items():
        a, _, b = pair.partition(" vs ")
        i, j = idx[a.strip()], idx[b.strip()]
        k = float(val.get("kappa", 0.0))
        grid[i][j] = grid[j][i] = k

    fig, ax = plt.subplots(figsize=(1.4 * n + 2, 1.4 * n + 1.5))
    im = ax.imshow(grid, cmap="RdYlGn", vmin=-1, vmax=1)
    short = [m.split("/")[-1][:18] for m in models]
    ax.set_xticks(range(n), short, rotation=35, ha="right", fontsize=9)
    ax.set_yticks(range(n), short, fontsize=9)
    for i in range(n):
        for j in range(n):
            v = grid[i][j]
            if v == v:  # not NaN
                ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                        fontsize=10, color="#111")
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Cohen's κ")
    return _save(fig, out_dir, name)


# ---------------------------------------------------------------------------
# Cross-experiment headline figure
# ---------------------------------------------------------------------------

def headline_strategy_comparison(processed: Path, out_dir: Path) -> Optional[Path]:
    """F1 across strategies: SAST (A) vs best LLM (B) vs best hybrid (C) vs consensus (D)."""
    labels: List[str] = []
    f1s: List[float] = []

    a = _load(processed / "exp_a_results.json")
    if a:
        labels.append("SAST only (A)")
        f1s.append(a["overall_metrics"]["f1_score"])

    b = _load(processed / "exp_b_results.json")
    if b:
        best = max(b["per_model_metrics"].values(), key=lambda m: m.get("f1_score", 0))
        labels.append("Best single LLM (B)")
        f1s.append(best.get("f1_score", 0))

    c = _load(processed / "exp_c_results.json")
    if c:
        best = max(c["per_model_metrics"].values(), key=lambda m: m.get("f1_score", 0))
        labels.append("Best hybrid (C)")
        f1s.append(best.get("f1_score", 0))

    d = _load(processed / "exp_d_results.json")
    if d:
        labels.append("Consensus majority (D)")
        f1s.append(d["majority_vote_metrics"]["f1_score"])

    if not labels:
        return None
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    bars = ax.bar(labels, f1s, color=[_PALETTE[i % len(_PALETTE)] for i in range(len(labels))])
    for bar, v in zip(bars, f1s):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.02, f"{v:.3f}",
                ha="center", fontsize=10, fontweight="bold")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(range(len(labels)), labels, rotation=15, ha="right", fontsize=9)
    _style_ax(ax, "VERDICT — F1 by detection strategy", ylabel="F1 score")
    return _save(fig, out_dir, "fig_headline_strategy_f1.png")


# ---------------------------------------------------------------------------
# Master entry point
# ---------------------------------------------------------------------------

def generate_all(processed_dir: Optional[Path] = None, figures_dir: Optional[Path] = None) -> List[Path]:
    """Generate every figure for which the source results file exists.

    Returns the list of written PNG paths. Safe to call repeatedly.
    """
    processed = Path(processed_dir) if processed_dir else config.PROCESSED_DIR
    out = Path(figures_dir) if figures_dir else config.FIGURES_DIR
    out.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    def _add(p: Optional[Path]) -> None:
        if p:
            written.append(p)

    # Headline
    _add(headline_strategy_comparison(processed, out))

    # Exp A — SAST confusion + per-difficulty recall
    a = _load(processed / "exp_a_results.json")
    if a:
        _add(confusion_matrix_figure(a.get("confusion_matrix", {}),
                                     "Exp A — SAST-only confusion matrix",
                                     out, "fig_exp_a_confusion.png"))
        pd = a.get("per_difficulty", {})
        if pd:
            diffs = list(pd.keys())
            _add(grouped_metric_bars(
                diffs,
                {"Recall": [pd[d].get("recall", 0) for d in diffs],
                 "F1": [pd[d].get("f1_score", 0) for d in diffs]},
                "Exp A — SAST performance by difficulty", out,
                "fig_exp_a_by_difficulty.png"))

    # Exp B — per-model P/R/F1 + latency
    b = _load(processed / "exp_b_results.json")
    if b:
        models = b["models_evaluated"]
        short = [m.split("/")[-1] for m in models]
        pm = b["per_model_metrics"]
        _add(grouped_metric_bars(
            short,
            {"Precision": [pm[m].get("precision", 0) for m in models],
             "Recall": [pm[m].get("recall", 0) for m in models],
             "F1": [pm[m].get("f1_score", 0) for m in models]},
            "Exp B — single-LLM metrics by model", out, "fig_exp_b_model_metrics.png"))
        lat = b.get("per_model_avg_latency_ms", {})
        if lat:
            _add(horizontal_bars(
                [m.split("/")[-1] for m in lat], list(lat.values()),
                "Exp B — mean latency per model", out, "fig_exp_b_latency.png",
                xlabel="Latency (ms)", color_idx=3))

    # Exp C — per-model hybrid F1
    c = _load(processed / "exp_c_results.json")
    if c:
        models = c["models_evaluated"]
        pm = c["per_model_metrics"]
        _add(grouped_metric_bars(
            [m.split("/")[-1] for m in models],
            {"Precision": [pm[m].get("precision", 0) for m in models],
             "Recall": [pm[m].get("recall", 0) for m in models],
             "F1": [pm[m].get("f1_score", 0) for m in models]},
            "Exp C — hybrid SAST+LLM metrics by model", out, "fig_exp_c_model_metrics.png"))

    # Exp D — consensus strategies + inter-model agreement matrix
    d = _load(processed / "exp_d_results.json")
    if d:
        mm, wm = d["majority_vote_metrics"], d["weighted_vote_metrics"]
        _add(grouped_metric_bars(
            ["Precision", "Recall", "F1", "Accuracy"],
            {"Majority vote": [mm.get(k, 0) for k in ("precision", "recall", "f1_score", "accuracy")],
             "Weighted vote": [wm.get(k, 0) for k in ("precision", "recall", "f1_score", "accuracy")]},
            "Exp D — consensus strategy metrics", out, "fig_exp_d_consensus.png"))
        _add(agreement_matrix_figure(
            d.get("pairwise_cohens_kappa", {}),
            "Exp D — inter-model agreement (Cohen's κ)", out, "fig_exp_d_agreement.png"))

    # Exp E — paired discrimination accuracy
    e = _load(processed / "exp_e_results.json")
    if e:
        da = e.get("discrimination_accuracy", {})
        if da:
            _add(horizontal_bars(
                list(da.keys()), list(da.values()),
                "Exp E — paired discrimination accuracy", out,
                "fig_exp_e_discrimination.png", xlabel="Discrimination accuracy",
                color_idx=2, vmax=1.05))

    # Exp F — adversarial robustness per technique
    f = _load(processed / "exp_f_results.json")
    if f:
        pt = f.get("per_technique", {})
        if pt:
            techs = list(pt.keys())
            _add(grouped_metric_bars(
                [t.replace("_", " ").title() for t in techs],
                {"Baseline detection": [pt[t].get("baseline_detection_rate", 0) for t in techs],
                 "Adversarial detection": [pt[t].get("adversarial_detection_rate", 0) for t in techs],
                 "Robustness": [pt[t].get("robustness_score", 0) for t in techs]},
                "Exp F — adversarial robustness by technique", out,
                "fig_exp_f_robustness.png"))

    print(f"[figures] done — {len(written)} figure(s) in {out}")
    return written


if __name__ == "__main__":  # pragma: no cover
    generate_all()
