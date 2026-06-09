# Experiment D — Multi-LLM Consensus

**Samples:** 25  |  **Judges:** 3  |  **Fleiss' κ:** 0.520 (moderate)

## Consensus strategy metrics

| Strategy | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|
| Majority vote | 0.909 | 0.833 | 0.870 | 0.880 |
| Weighted confidence | 0.909 | 0.833 | 0.870 | 0.880 |

## Pairwise Cohen's κ

| Pair | κ | Interpretation |
|---|---:|---|
| model-alpha vs model-beta | 0.615 | substantial |
| model-alpha vs model-gamma | 0.603 | substantial |
| model-beta vs model-gamma | 0.355 | fair |

## Significance vs. best single-LLM (paired bootstrap, F1)

Baseline: **mock-high-accuracy**  |  ΔF1 = 0.0  |  p = 0.649  |  Significant: False
