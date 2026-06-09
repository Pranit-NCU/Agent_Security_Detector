# Experiment A — SAST-only Baseline

**Samples:** 25  |  **Cohen's κ:** 0.679 (substantial)

## Overall metrics

| Metric | Value |
|---|---:|
| precision | 0.833 |
| recall | 0.833 |
| f1_score | 0.833 |
| accuracy | 0.840 |

## Per-CWE breakdown

| CWE | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|
| CWE-89 | 0.600 | 0.750 | 0.667 | 0.571 |
| CWE-798 | 1.000 | 0.750 | 0.857 | 0.857 |
| CWE-287 | 1.000 | 1.000 | 1.000 | 1.000 |
| NONE | 0.000 | 0.000 | 0.000 | 1.000 |

## Per-difficulty breakdown

| Difficulty | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|
| easy | 0.750 | 1.000 | 0.857 | 0.875 |
| medium | 0.667 | 0.667 | 0.667 | 0.750 |
| hard | 1.000 | 1.000 | 1.000 | 1.000 |
| adversarial | 1.000 | 0.667 | 0.800 | 0.667 |
