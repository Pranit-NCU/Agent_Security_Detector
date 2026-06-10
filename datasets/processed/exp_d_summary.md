# Experiment D — Multi-LLM Consensus

**Samples:** 121  |  **Judges:** 3  |  **Fleiss' κ:** 0.097 (slight)

## Consensus strategy metrics

| Strategy | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|
| Majority vote | 1.000 | 0.901 | 0.948 | 0.901 |
| Weighted confidence | 1.000 | 0.901 | 0.948 | 0.901 |

## Pairwise Cohen's κ

| Pair | κ | Interpretation |
|---|---:|---|
| model-alpha vs model-beta | 0.076 | slight |
| model-alpha vs model-gamma | 0.231 | fair |
| model-beta vs model-gamma | -0.007 | poor (worse than chance) |

## Significance vs. best single-LLM (paired bootstrap, F1)

Baseline: **mock-high-accuracy**  |  ΔF1 = 0.0234  |  p = 0.5055  |  Significant: False
