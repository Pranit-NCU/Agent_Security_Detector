"""Statistical significance and agreement tests for VERDICT experiments.

Implements:
  - Cohen's kappa          (pairwise inter-rater agreement)
  - Fleiss' kappa          (multi-rater agreement over N raters)
  - Paired bootstrap       (non-parametric p-value for F1/recall/precision delta)
  - Benjamini-Hochberg     (FDR correction for multiple comparisons)

All functions operate on plain Python lists so they remain dependency-free.
Results are returned as frozen dataclasses for easy JSON serialisation.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple


# ---------------------------------------------------------------------------
# Cohen's kappa
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CohenKappaResult:
    """Pairwise inter-rater agreement."""
    kappa: float
    p_o: float          # observed agreement
    p_e: float          # expected agreement by chance
    interpretation: str


def cohens_kappa(
    rater_a: Sequence[bool],
    rater_b: Sequence[bool],
) -> CohenKappaResult:
    """Compute Cohen's kappa between two binary raters.

    Args:
        rater_a: Binary labels from rater A.
        rater_b: Binary labels from rater B.

    Returns:
        CohenKappaResult with kappa, p_o, p_e, and an interpretation string.

    Raises:
        ValueError: If sequences differ in length or p_e == 1.
    """
    if len(rater_a) != len(rater_b):
        raise ValueError("rater_a and rater_b must have equal length")
    n = len(rater_a)
    if n == 0:
        raise ValueError("Sequences must not be empty")

    agree = sum(1 for a, b in zip(rater_a, rater_b) if a == b)
    p_o = agree / n

    a_pos = sum(rater_a) / n
    b_pos = sum(rater_b) / n
    p_e = a_pos * b_pos + (1 - a_pos) * (1 - b_pos)

    if p_e == 1.0:
        # All items same class by both raters — kappa undefined, treat as 1.
        return CohenKappaResult(kappa=1.0, p_o=p_o, p_e=p_e,
                                interpretation="perfect (trivial)")

    kappa = (p_o - p_e) / (1.0 - p_e)
    return CohenKappaResult(kappa=kappa, p_o=p_o, p_e=p_e,
                            interpretation=_kappa_label(kappa))


# ---------------------------------------------------------------------------
# Fleiss' kappa
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FleissKappaResult:
    """Multi-rater agreement across N raters."""
    kappa: float
    p_bar: float        # mean proportion of rater agreement
    p_e_bar: float      # expected agreement
    interpretation: str


def fleiss_kappa(rating_matrix: Sequence[Sequence[int]], n_categories: int = 2) -> FleissKappaResult:
    """Compute Fleiss' kappa for N raters and K categories.

    Args:
        rating_matrix: List of rows (one per subject); each row is a list of
            category counts summing to the number of raters. For binary tasks
            ``[n_vulnerable, n_not_vulnerable]``.
        n_categories: Number of rating categories (default 2 for binary).

    Returns:
        FleissKappaResult.

    Raises:
        ValueError: If the matrix is malformed.
    """
    n_subjects = len(rating_matrix)
    if n_subjects == 0:
        raise ValueError("rating_matrix must not be empty")

    n_raters = sum(rating_matrix[0])
    if any(sum(row) != n_raters for row in rating_matrix):
        raise ValueError("Each row must sum to the same number of raters")

    # P_i: extent of agreement for subject i
    p_i_values: List[float] = []
    for row in rating_matrix:
        numerator = sum(n_j * (n_j - 1) for n_j in row)
        denominator = n_raters * (n_raters - 1)
        p_i_values.append(numerator / denominator if denominator > 0 else 0.0)

    p_bar = sum(p_i_values) / n_subjects

    # p_j: proportion of all assignments in category j
    p_j_values: List[float] = []
    total_ratings = n_subjects * n_raters
    for j in range(n_categories):
        col_sum = sum(row[j] for row in rating_matrix if len(row) > j)
        p_j_values.append(col_sum / total_ratings)

    p_e_bar = sum(p_j ** 2 for p_j in p_j_values)

    if p_e_bar == 1.0:
        return FleissKappaResult(kappa=1.0, p_bar=p_bar, p_e_bar=p_e_bar,
                                 interpretation="perfect (trivial)")

    kappa = (p_bar - p_e_bar) / (1.0 - p_e_bar)
    return FleissKappaResult(kappa=kappa, p_bar=p_bar, p_e_bar=p_e_bar,
                             interpretation=_kappa_label(kappa))


# ---------------------------------------------------------------------------
# Paired bootstrap significance test
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PairedBootstrapResult:
    """Non-parametric significance test for metric delta between two systems."""
    delta: float            # system_b_metric - system_a_metric
    p_value: float
    significant: bool       # True if p_value < alpha
    n_bootstrap: int
    alpha: float


def paired_bootstrap(
    expected: Sequence[bool],
    system_a_preds: Sequence[bool],
    system_b_preds: Sequence[bool],
    metric: str = "f1",
    n_bootstrap: int = 10_000,
    alpha: float = 0.05,
    seed: int = 42,
) -> PairedBootstrapResult:
    """Paired bootstrap test for whether system B is significantly better than A.

    Implements the one-sided test: H0: delta(B,A) <= 0.

    Args:
        expected: Ground-truth binary labels.
        system_a_preds: Predictions from system A.
        system_b_preds: Predictions from system B.
        metric: One of "f1", "precision", "recall", "accuracy".
        n_bootstrap: Number of bootstrap resamples.
        alpha: Significance level.
        seed: Random seed for reproducibility.

    Returns:
        PairedBootstrapResult.
    """
    n = len(expected)
    if not (n == len(system_a_preds) == len(system_b_preds)):
        raise ValueError("All sequences must have equal length")

    rng = random.Random(seed)
    samples = list(zip(expected, system_a_preds, system_b_preds))

    delta_obs = _compute_metric(expected, system_b_preds, metric) - \
                _compute_metric(expected, system_a_preds, metric)

    count_ge = 0
    for _ in range(n_bootstrap):
        boot = [rng.choice(samples) for _ in range(n)]
        exp_b    = [s[0] for s in boot]
        pred_a_b = [s[1] for s in boot]
        pred_b_b = [s[2] for s in boot]
        boot_delta = (_compute_metric(exp_b, pred_b_b, metric) -
                      _compute_metric(exp_b, pred_a_b, metric))
        # Shift: under H0, delta = 0; test 2*delta_obs - boot_delta >= delta_obs
        if 2 * delta_obs - boot_delta >= delta_obs:
            count_ge += 1

    p_value = count_ge / n_bootstrap
    return PairedBootstrapResult(
        delta=delta_obs,
        p_value=p_value,
        significant=p_value < alpha,
        n_bootstrap=n_bootstrap,
        alpha=alpha,
    )


# ---------------------------------------------------------------------------
# Benjamini-Hochberg FDR correction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BHResult:
    """Single comparison result after BH correction."""
    label: str
    p_value: float
    adjusted_p_value: float
    significant: bool


def benjamini_hochberg(
    p_values: Dict[str, float],
    alpha: float = 0.05,
) -> List[BHResult]:
    """Apply Benjamini-Hochberg FDR correction.

    Args:
        p_values: Mapping of comparison label -> raw p-value.
        alpha: Desired FDR level.

    Returns:
        List of BHResult sorted by p-value ascending.
    """
    if not p_values:
        return []

    m = len(p_values)
    sorted_items: List[Tuple[str, float]] = sorted(p_values.items(), key=lambda x: x[1])

    # Determine largest k where p_(k) <= (k/m) * alpha
    threshold_index = -1
    for k, (_, p) in enumerate(sorted_items, start=1):
        if p <= (k / m) * alpha:
            threshold_index = k - 1  # 0-based

    results: List[BHResult] = []
    for idx, (label, p) in enumerate(sorted_items):
        adj_p = min(1.0, p * m / (idx + 1))
        results.append(BHResult(
            label=label,
            p_value=p,
            adjusted_p_value=round(adj_p, 6),
            significant=idx <= threshold_index,
        ))

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_metric(expected: Sequence[bool], predicted: Sequence[bool], metric: str) -> float:
    tp = sum(1 for e, p in zip(expected, predicted) if e and p)
    fp = sum(1 for e, p in zip(expected, predicted) if not e and p)
    tn = sum(1 for e, p in zip(expected, predicted) if not e and not p)
    fn = sum(1 for e, p in zip(expected, predicted) if e and not p)

    if metric == "precision":
        return tp / (tp + fp) if (tp + fp) else 0.0
    if metric == "recall":
        return tp / (tp + fn) if (tp + fn) else 0.0
    if metric == "accuracy":
        total = tp + fp + tn + fn
        return (tp + tn) / total if total else 0.0
    # default: f1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    return (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


def _kappa_label(kappa: float) -> str:
    if kappa < 0.0:
        return "poor (worse than chance)"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"
