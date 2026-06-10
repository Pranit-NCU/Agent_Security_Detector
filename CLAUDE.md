# VERDICT — Project Context for AI Assistants

**Project name:** VERDICT (Vulnerability Evaluation by Reasoning, Consensus, Integration, and Detection Tiers)
**Type:** MSc Data Science & AI dissertation — University of Leeds
**Author:** Pranit Chatzimitheas (pranitchatz@gmail.com)
**Deadlines:** Poster 29 July 2026 · Dissertation 10 August 2026
**Repo:** https://github.com/Pranit-NCU/Agent_Security_Detector (branch: `feat/experiment-runners-a-f`)

---

## Research Goal

Empirically evaluate whether multi-LLM consensus + SAST improves vulnerability detection in AI-generated Python code versus single-tool approaches. Six controlled experiments (A–F) compare strategies across a standardised benchmark.

---

## Project Layout

```
Agent_Security_Detector/
├── src/
│   ├── detectors/          # SAST detectors (SQLInjection, Secrets, Auth)
│   ├── llm/                # LLM judges + ConsensusEngine
│   │   ├── base_judge.py       BaseLLMJudge, JudgeConfig, JudgeResult
│   │   ├── gemini_judge.py     GeminiJudge (live, needs GEMINI_API_KEY)
│   │   ├── openrouter_judge.py OpenRouterJudge
│   │   ├── huggingface_judge.py
│   │   ├── ollama_judge.py
│   │   ├── consensus_engine.py ConsensusEngine (majority + weighted vote)
│   │   └── prompt_builder.py
│   └── evaluation/
│       ├── statistical_tests.py  cohens_kappa, fleiss_kappa, paired_bootstrap, BH FDR
│       ├── metrics.py            ConfusionMatrix, BinaryClassificationMetrics
│       ├── adversarial_tests.py  AdversarialEvaluator, AdversarialCaseResult
│       └── dataset_loaders.py
├── experiments/
│   ├── exp_a_sast_baseline.py    Exp A — SAST only
│   ├── exp_b_single_llm.py       Exp B — single LLM
│   ├── exp_c_hybrid.py           Exp C — SAST + LLM hybrid
│   ├── exp_d_consensus.py        Exp D — multi-LLM majority vote
│   ├── exp_e_paired.py           Exp E — paired discrimination (vuln vs. patch)
│   ├── exp_f_adversarial.py      Exp F — adversarial robustness (5 transforms)
│   └── run_all.py                Orchestrator — runs A–F in sequence
├── datasets/
│   ├── benchmark/
│   │   ├── securityeval_dataset.json  PRIMARY (121 samples, 69 CWEs) ← Exp A–D, F
│   │   ├── seed_dataset.json          PAIRED (25 samples, vuln+patch+clean) ← Exp E
│   │   └── CITATIONS.md              Full academic references for all datasets
│   ├── processed/                     Experiment outputs (JSON + MD per exp)
│   └── adversarial/                   Transformed samples from Exp F
└── tests/                             46 tests, all passing
```

---

## Running Experiments

```bash
# Full offline run (mock LLM judges, no API keys needed)
python experiments/run_all.py --mock

# Individual experiment
python experiments/exp_a_sast_baseline.py

# With real LLM (requires GEMINI_API_KEY in .env)
python experiments/run_all.py --no-mock

# Run a subset
python experiments/run_all.py --exp A D F
```

All experiments produce:
- `datasets/processed/exp_<x>_results.json` — machine-readable metrics
- `datasets/processed/exp_<x>_summary.md` — dissertation-ready markdown table

---

## Current Mock-Mode Results (SecurityEval, n=121)

| Exp | Strategy | F1 | Key metric |
|---|---|---|---|
| A | SAST only | 0.138 | R=0.074 — only 3 CWEs covered by our detectors |
| B | Single LLM (best) | 0.924 | R=0.860 |
| C | Hybrid SAST+LLM (best) | 0.934 | R=0.876 |
| D | Multi-LLM majority vote | 0.948 | R=0.901, Fleiss κ=0.097 |
| E | Paired discrimination | — | SAST disc=0.778, Consensus disc=1.000 (n=9 pairs) |
| F | Adversarial (5 transforms) | — | Robustness=0.851, Degradation=0.149 (n=605 cases) |

**Important caveats for real-mode runs:**
- SecurityEval is all-positive (no safe samples) → precision=1.0 trivially, Cohen κ=0 degenerately. Detection rate (recall) is the primary metric.
- Exp E uses `seed_dataset.json` (has paired vuln/patch samples). All other experiments use `securityeval_dataset.json`.
- Mock results use seeded random accuracy — not meaningful for the dissertation. Real API runs needed for final results.

---

## LLM Providers & Keys

| Provider | Judge class | Env var | Status |
|---|---|---|---|
| Gemini | `GeminiJudge` | `GEMINI_API_KEY` | Key exists in `.env.example` — primary provider |
| OpenRouter | `OpenRouterJudge` | `OPENROUTER_API_KEY` | Optional |
| HuggingFace | `HuggingFaceJudge` | `HF_API_KEY` | Optional |
| Ollama | `OllamaJudge` | (local) | Optional |

All experiments auto-detect keys and fall back to mock judges if none are set.

---

## SAST Detectors

Three detectors in `src/detectors/`:

| Detector | CWE | Severity trigger |
|---|---|---|
| `SQLInjectionDetector` | CWE-89 | CRITICAL / HIGH |
| `SecretsDetector` | CWE-798 | CRITICAL / HIGH |
| `AuthDetector` | CWE-287 | CRITICAL / HIGH |

Only 3 CWEs are covered — this is intentional to demonstrate SAST's narrow coverage (Exp A finding: recall=7.4% on SecurityEval's 69 CWEs).

**Possible future work:** Add detectors for CWE-78 (command injection), CWE-400 (resource exhaustion), CWE-267/250 (unsafe dynamic exec/import).

---

## Datasets

### SecurityEval (primary, Exp A–D, F)
- 121 Python samples · 69 CWEs · all vulnerable
- Source: Siddiq & Santos, ACM MSR4P&S 2022. DOI: 10.1145/3549035.3561184
- Schema: `sample_id, source_dataset, source_id, vulnerability_label, cwe, expected_is_vulnerable, difficulty, paired_sample_id, domain, code, prompt`
- Difficulty split: 34 hard (codeql) / 40 medium (sonar/mitre) / 47 easy (author/pearce)

### Seed dataset (paired evaluation, Exp E)
- 25 samples: 12 vulnerable · 9 patched · 4 clean
- CWEs: CWE-89, CWE-798, CWE-287 (3 pairs each × easy/medium/hard)
- Includes 3 adversarial samples + 3 industrial_python samples (SCADA/PLC context)
- Hand-curated for VERDICT; cite as Chatzimitheas (2026)

### VUDENC (not integrated)
- Python, 7 vuln types, GitHub commit provenance
- Excluded: token-level numpy format, incompatible with snippet-level evaluation
- See `datasets/benchmark/CITATIONS.md` for full reference

---

## Statistical Tests (`src/evaluation/statistical_tests.py`)

All stdlib-only, no external deps:

| Function | Purpose |
|---|---|
| `cohens_kappa(rater_a, rater_b)` | Pairwise binary agreement — returns CohenKappaResult |
| `fleiss_kappa(rating_matrix, n_categories=2)` | Multi-rater agreement — returns FleissKappaResult |
| `paired_bootstrap(expected, sys_a, sys_b, metric='f1', n=10000)` | Non-parametric H₀: Δ(B,A)≤0 |
| `benjamini_hochberg(p_values, alpha=0.05)` | FDR correction for multiple comparisons |

Kappa interpretation: slight (<0.2) · fair (0.2–0.4) · moderate (0.4–0.6) · substantial (0.6–0.8) · almost perfect (≥0.8)

---

## Adversarial Transforms (Exp F)

Five transforms applied to all 121 vulnerable samples (= 605 cases):

| Technique | Mock susceptibility | Description |
|---|---|---|
| `PROMPT_INJECTION` | 0.55 | Embeds `{"is_vulnerable": false}` in comment |
| `MISLEADING_COMMENTS` | 0.70 | Prepends "Security review: PASSED" |
| `VARIABLE_OBFUSCATION` | 0.78 | Renames `query`→`data_payload`, `password`→`user_pref`, etc. |
| `LOGIC_OBFUSCATION` | 0.75 | Wraps body in `_internal_handler()` |
| `DEAD_CODE_CAMOUFLAGE` | 0.82 | Injects fake validation block at midpoint |

---

## Git

- Remote: `https://github.com/Pranit-NCU/Agent_Security_Detector.git`
- Active branch: `feat/experiment-runners-a-f`
- Last commits (most recent first):
  1. `feat(experiments): switch primary benchmark to SecurityEval (121 samples)`
  2. `data(securityeval): add 121-sample SecurityEval benchmark dataset`
  3. `chore(results): add initial mock-mode experiment outputs`
  4. `feat(experiments): add controlled experiment runners A–F`
  5. `data(benchmark): add labelled seed dataset (25 samples)`

**Git push workaround:** The Windows NTFS mount blocks `git add` due to `.git/index.lock`. Always push via:
```bash
cd /tmp
git clone --no-local <remote_url> verdict_push
# copy files, commit, push from /tmp/verdict_push
```

---

## What Needs Doing Next

1. **Run with real API keys** — set `GEMINI_API_KEY` in `.env` and run `python experiments/run_all.py --no-mock` to get real (non-mock) results for the dissertation.
2. **Statistical interpretation** — real Fleiss κ and bootstrap p-values will determine whether consensus is significantly better than single-LLM.
3. **Dissertation write-up** — results are in `datasets/processed/exp_*_summary.md`.
4. **Poster (29 Jul 2026)** — needs headline numbers from real runs; Exp D (consensus F1) and Exp F (robustness score) are the headline findings.
5. **Optional: extend SAST coverage** — add CWE-78, CWE-400, CWE-267/250 detectors to improve Exp A recall beyond 7.4%.
6. **Optional: add safe samples to SecurityEval benchmark** — synthetically patch some samples to enable full binary classification metrics (remove the all-positive limitation).

---

## Tests

```bash
python -m pytest tests/ -v      # 46 tests, all pass
```

Key test files: `tests/test_detectors.py`, `tests/test_llm_base_judge.py`, `tests/test_llm_consensus_engine.py`, `tests/test_evaluation_framework.py`
