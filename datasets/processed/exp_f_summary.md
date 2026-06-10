# Experiment F — Adversarial Robustness

**Vulnerable samples:** 121  |  **Techniques:** 5  |  **Total cases:** 605

**Overall robustness score:** 0.851  |  **Detection degradation:** 0.149

## Per-technique robustness

| Technique | Baseline det. | Adversarial det. | Degradation | Robustness |
|---|---:|---:|---:|---:|
| misleading_comments | 0.884 | 0.727 | 0.157 | 0.843 |
| variable_obfuscation | 0.884 | 0.785 | 0.099 | 0.901 |
| dead_code_camouflage | 0.884 | 0.835 | 0.050 | 0.950 |
| logic_obfuscation | 0.884 | 0.785 | 0.099 | 0.901 |
| prompt_injection | 0.884 | 0.545 | 0.339 | 0.661 |
