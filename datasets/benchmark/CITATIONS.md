# VERDICT Benchmark Dataset Citations

This document provides full bibliographic references and usage notes for all
datasets used in or considered for the VERDICT evaluation framework.

---

## 1. SecurityEval (Primary Evaluation Dataset)

**Status:** ✅ Integrated — `datasets/benchmark/securityeval_dataset.json`

### Summary

SecurityEval is a dataset of 121 Python code snippets specifically designed to
evaluate the ability of language models and security tools to generate *secure*
code. Every sample contains an insecure Python function produced in response to a
natural-language prompt. The dataset covers 69 unique CWE categories, making it
the broadest Python-focused vulnerability benchmark currently available.

**Key properties relevant to VERDICT:**

| Property | Value |
|---|---|
| Language | Python (exclusively) |
| Samples | 121 |
| Unique CWEs | 69 |
| Ground truth | All samples are vulnerable (`expected_is_vulnerable = true`) |
| Sources | CodeQL, SonarSource, MITRE, manual author, Pearce et al. |
| License | MIT |

**Important methodological note:** Because SecurityEval contains only vulnerable
examples, standard binary classification metrics reduce to detection-rate
metrics. Precision is trivially 1.0 (no false positives possible) and Cohen's κ
is degenerate (0.0 regardless of recall). For full binary classification
analysis, use the seed dataset (`seed_dataset.json`) which contains balanced
vulnerable/patched/clean samples.

### Source repository

```
https://github.com/s2e-lab/SecurityEval
```

### Citation

```bibtex
@inproceedings{siddiq2022securityeval,
  title     = {{SecurityEval} Dataset: Mining Vulnerability Examples to Evaluate
               Machine Learning-Based Code Generation Techniques},
  author    = {Siddiq, Mohammed Latif and Santos, Joanna C. S.},
  booktitle = {Proceedings of the 1st International Workshop on Mining Software
               Repositories Applications for Privacy and Security (MSR4P\&S)},
  year      = {2022},
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  pages     = {29--33},
  doi       = {10.1145/3549035.3561184},
  url       = {https://doi.org/10.1145/3549035.3561184},
}
```

**Narrative reference (APA 7th):**

> Siddiq, M. L., & Santos, J. C. S. (2022). SecurityEval dataset: Mining
> vulnerability examples to evaluate machine learning-based code generation
> techniques. *Proceedings of the 1st International Workshop on Mining Software
> Repositories Applications for Privacy and Security (MSR4P&S)*, 29–33.
> https://doi.org/10.1145/3549035.3561184

---

## 2. VERDICT Seed Dataset (Paired Evaluation)

**Status:** ✅ Integrated — `datasets/benchmark/seed_dataset.json`

### Summary

A hand-curated dataset of 25 labelled Python samples designed specifically for
VERDICT. It contains matched vulnerable/patched pairs and a small set of clean
samples, supporting binary classification metrics, Cohen's κ, and paired
discrimination experiments (Experiment E).

**Key properties:**

| Property | Value |
|---|---|
| Language | Python |
| Samples | 25 (12 vulnerable, 9 patched, 4 clean) |
| CWEs covered | CWE-89 (SQL injection), CWE-798 (hardcoded secrets), CWE-287 (missing auth) |
| Difficulty levels | easy, medium, hard (3 pairs per CWE per difficulty) |
| Domains | general_python, industrial_python (SCADA/PLC examples) |
| Paired samples | 9 vulnerable/patched pairs |
| Adversarial samples | 3 (misleading comment, JWT injection, fake middleware) |
| License | CC BY 4.0 (see `datasets/benchmark/LICENSE`) |

### Citation

This dataset was created as part of the VERDICT MSc dissertation (Pranit
Chatzimitheas, 2026). If you use or extend it, please cite:

```bibtex
@misc{chatzimitheas2026verdict,
  title   = {{VERDICT}: Vulnerability Evaluation by Reasoning, Consensus,
             Integration, and Detection Tiers},
  author  = {Chatzimitheas, Pranit},
  year    = {2026},
  note    = {MSc dissertation, School of Computing, University of Leeds},
}
```

---

## 3. VUDENC (Related Work — Not Directly Integrated)

**Status:** ℹ️ Referenced only — architecturally incompatible with VERDICT

### Summary

VUDENC (Vulnerability Detection with Deep Learning on a Natural Codebase) is a
Python vulnerability dataset extracted from 1,009 security-fixing GitHub
commits. It covers seven vulnerability types: SQL injection, XSS, XSRF, command
injection, remote code execution, path disclosure, and open redirect.

**Why VUDENC was not integrated into VERDICT:**

VUDENC's data representation stores code as sequences of *word2vec-embedded
tokens* with *statement-level binary labels*. Each sample is a sliding window of
code tokens from a larger source file, not a self-contained Python function. This
token-level format is fundamentally incompatible with VERDICT's function-level
snippet evaluation, which requires complete, executable Python code snippets.
Reconstructing full functions from VUDENC's token sequences would require the
original source files (distributed separately at ~11.9 GB on Zenodo) and
substantial post-processing.

VUDENC remains valuable as a benchmark for LSTM/RNN-based token classifiers, and
its real-world commit provenance is a methodological strength for that paradigm.

**Key properties:**

| Property | Value |
|---|---|
| Language | Python |
| Vulnerability types | 7 (SQL injection, XSS, XSRF, command injection, RCE, path disclosure, open redirect) |
| Commit sources | 1,009 security-fixing GitHub commits |
| Format | Token sequences with per-token binary labels |
| Zenodo record | https://doi.org/10.5281/zenodo.3559841 |

### Citation

```bibtex
@article{wartschinski2022vudenc,
  title   = {{VUDENC}: Vulnerability Detection with Deep Learning on a Natural
             Codebase for {Python}},
  author  = {Wartschinski, Laura and Noller, Yannic and Vogel, Thomas and
             Kehrer, Timo and Grunske, Lars},
  journal = {Information and Software Technology},
  volume  = {144},
  pages   = {106809},
  year    = {2022},
  issn    = {0950-5849},
  doi     = {10.1016/j.infsof.2021.106809},
  url     = {https://doi.org/10.1016/j.infsof.2021.106809},
}
```

**Narrative reference (APA 7th):**

> Wartschinski, L., Noller, Y., Vogel, T., Kehrer, T., & Grunske, L. (2022).
> VUDENC: Vulnerability detection with deep learning on a natural codebase for
> Python. *Information and Software Technology*, *144*, 106809.
> https://doi.org/10.1016/j.infsof.2021.106809

**Zenodo dataset record:**

> Wartschinski, L. (2019). *VUDENC — datasets for vulnerabilities* (Version 1)
> [Data set]. Zenodo. https://doi.org/10.5281/zenodo.3559841

---

## 4. DiverseVul (Considered — C/C++ Only)

**Status:** ❌ Out of scope — C/C++ only, no Python

### Summary

DiverseVul is a large-scale vulnerability dataset containing 18,945 vulnerable
and 330,492 non-vulnerable C/C++ functions collected from 7,514 projects. It
covers 150 CWE types and is designed for training graph neural networks and
transformer models on compiled language vulnerability patterns.

DiverseVul was reviewed as a candidate dataset but excluded because VERDICT
evaluates Python code exclusively and the syntactic/semantic differences between
Python and C/C++ make cross-language evaluation invalid for our research
questions.

### Citation

```bibtex
@inproceedings{chen2023diversevul,
  title     = {{DiverseVul}: A New Vulnerable Source Code Dataset for Deep
               Learning Based Vulnerability Detection},
  author    = {Chen, Yizheng and Ding, Zhoujie and Chen, Lingxiao and Wagner,
               David},
  booktitle = {Proceedings of the 26th International Symposium on Research in
               Attacks, Intrusions and Defenses (RAID)},
  year      = {2023},
  doi       = {10.1145/3607199.3607242},
}
```

---

## 5. CWE Reference

All CWE identifiers in VERDICT datasets are drawn from the MITRE CWE database:

> MITRE Corporation. (2024). *Common Weakness Enumeration (CWE)*. Version 4.14.
> https://cwe.mitre.org/

---

*Last updated: June 2026*
*Maintainer: Pranit Chatzimitheas (pranitchatz@gmail.com)*
