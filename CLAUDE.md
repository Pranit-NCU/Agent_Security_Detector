# VERDICT — Project Context for AI Assistants

**Project name:** VERDICT (Vulnerability Evaluation by Reasoning, Consensus, Integration, and Detection Tiers)
**Type:** MSc Data Science & AI dissertation — University of Leeds
**Author:** Pranit Chatzimitheas (pranitchatz@gmail.com)
**Deadlines:** Poster 29 July 2026 · Dissertation 10 August 2026
**Repo:** https://github.com/Pranit-NCU/Agent_Security_Detector (branch: `feat/experiment-runners-a-f`)

---

## Research Goal

Empirically evaluate whether multi-LLM consensus + SAST improves vulnerability detection in AI-generated Python code versus single-tool approaches. Six controlled experiments (A–F) compare strategies across a standardised benchmark.

**Not Python-only by design.** Python is the validation language for Experiments A–F because mature SAST tooling and benchmarks (SecurityEval, VUDENC) exist for it. Once the consensus+SAST approach is validated here, the same detection methodology (SAST pattern rules + multi-LLM judge consensus + statistical agreement analysis) is intended to be carried over to **PLC code** (ladder logic / structured text / IEC 61131-3), motivated by the SCADA/PLC-context samples already seeded in `seed_dataset.json`. Python is the proving ground, not the boundary of the research.

---

## Dual-Environment Architecture (Local + Google Colab)

The repo is the **single source of truth**. It runs unchanged in two environments:

* **Local development** — SAST detectors, dataset/benchmark framework, statistics, reporting, CLI, and Streamlit all run on a laptop exactly as before.
* **Google Colab experimentation** — the *computational experimentation layer only* (the A–F runners + figures) runs in the cloud against free-tier LLM providers, writing every artifact to Google Drive so nothing is lost on disconnect.

No experiment code is duplicated between environments. Colab differs from local **only through environment variables**, resolved centrally in `src/config.py`.

### New modules (added for the dual-environment split)

| File | Role |
|---|---|
| `src/config.py` | Single source of truth for paths. Env-overridable (`VERDICT_OUTPUT_DIR`, `VERDICT_FIGURES_DIR`, `VERDICT_ADVERSARIAL_DIR`, `VERDICT_BENCHMARK_FILE`, `VERDICT_SEED_FILE`, `VERDICT_DATA_DIR`). **Unset → identical to old behaviour** (backwards compatible). |
| `src/llm/judge_factory.py` | `build_real_judges(force_mock, tag)` — the live-provider priority chain defined **once**. Previously copy-pasted into exp B/C/D/E. Adding a provider is now a one-line change. |
| `src/llm/together_judge.py` | New free-tier judge (Together AI, `Llama-3.3-70B-Instruct-Turbo-Free`, Meta family). Opt-in via `TOGETHER_API_KEY`. |
| `src/evaluation/figures.py` | Publication-quality PNGs (300 DPI, colour-blind palette) built from the `exp_*_results.json` files: headline F1, per-model bars, latency, Cohen's-κ agreement matrix, paired discrimination, adversarial robustness. `generate_all()` renders everything available. |
| `requirements.txt` | Minimal deps (core is stdlib-only; `matplotlib` for figures, `click`/`streamlit` for the local interface). |
| `notebooks/VERDICT_Colab.ipynb` | 24-cell end-to-end Colab pipeline (clone → mount Drive → install → validate → run A–F → figures → export). Free providers only. |
| `notebooks/VERDICT_Colab_Cells.md` | Cell-by-cell guide (purpose / copy-paste code / expected output / troubleshooting). |

### Experiment wiring changes (backwards compatible)

Each `experiments/exp_*.py` now reads paths from `src.config` and (for B–E) delegates provider selection to `judge_factory.build_real_judges(...)`, keeping its own mock fallback. Exp F gained a Together branch in its single-judge selector.

### Bug fixes made during the refactor

* **`exp_d` and `exp_e` `_build_judges` returned `None` in mock mode** (no `return`, no mock fallback) — would crash `run()`. Both now fall back to three noisy mock judges and return them.
* **`exp_e` called `discrimination_accuracy(...)` which was undefined anywhere** (`NameError` before the experiment could finish). The helper has been restored in `exp_e_paired.py`.

### Drive folder layout (created by the notebook)

```
MyDrive/VERDICT/{datasets, results, reports, charts, logs, raw_outputs}
```

Providers used in Colab (all free-tier, no credit card): **OpenRouter (Cohere North Mini Code + Poolside Laguna XS 2.1) + Mistral (Nemo) + Groq (Llama 3.1 8B)** as the active 4-judge design. Keys are entered once via `getpass`/Colab Secrets and reused for the session.

---

## Project Layout

```
Agent_Security_Detector/
├── src/
│   ├── detectors/          # SAST detectors (SQLInjection, Secrets, Auth)
│   ├── llm/                # LLM judges + ConsensusEngine
│   │   ├── base_judge.py           BaseLLMJudge, JudgeConfig, JudgeResult
│   │   ├── openrouter_judge.py     OpenRouterJudge — Cohere North Mini Code + Poolside Laguna XS 2.1 ← ACTIVE (primary)
│   │   ├── mistral_judge.py        MistralJudge — open-mistral-nemo ← ACTIVE (primary)
│   │   ├── groq_judge.py           GroqJudge — llama-3.1-8b-instant ← ACTIVE (4th judge, Meta family)
│   │   ├── huggingface_judge.py    HuggingFaceJudge — gemma-3-27b-it ← optional fallback (quota often exhausted)
│   │   ├── cerebras_judge.py       CerebasJudge — gpt-oss-120b ← optional fallback (requires payment on file)
│   │   ├── sambanova_judge.py      SambaNovaJudge — Meta-Llama-3.3-70B ← optional fallback
│   │   ├── together_judge.py       TogetherJudge — Llama-3.3-70B-Turbo-Free ← optional, opt-in
│   │   ├── gemini_judge.py         GeminiJudge — emergency fallback, needs GEMINI_API_KEY
│   │   ├── ollama_judge.py         OllamaJudge (local, optional)
│   │   ├── judge_factory.py        build_real_judges() — single source of truth for provider priority
│   │   ├── consensus_engine.py     ConsensusEngine (majority + weighted vote)
│   │   └── prompt_builder.py
│   ├── evaluation/
│   │   ├── statistical_tests.py  cohens_kappa, fleiss_kappa, paired_bootstrap, BH FDR
│   │   ├── metrics.py            ConfusionMatrix, BinaryClassificationMetrics
│   │   ├── adversarial_tests.py  AdversarialEvaluator, AdversarialCaseResult
│   │   └── dataset_loaders.py
│   └── utils/
│       ├── __init__.py
│       └── dns_patch.py      stdlib-only DNS-over-HTTPS fallback (see note below)
├── experiments/
│   ├── exp_a_sast_baseline.py    Exp A — SAST only
│   ├── exp_b_single_llm.py       Exp B — single LLM
│   ├── exp_c_hybrid.py           Exp C — SAST + LLM hybrid
│   ├── exp_d_consensus.py        Exp D — multi-LLM majority vote
│   ├── exp_e_paired.py           Exp E — paired discrimination (vuln vs. patch)
│   ├── exp_f_adversarial.py      Exp F — adversarial robustness (5 transforms)
│   ├── validate_hf.py            Token + model reachability check (run before --no-mock)
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

**Windows note:** always use `python -X utf8` to avoid emoji/Unicode encoding errors on cp1252 terminals.

```bash
# Validate all providers before a real run (currently probes the old HF/Cerebras/
# SambaNova/Mistral/Groq set -- see task_98aa1346 for the pending OpenRouter update)
python -X utf8 experiments/validate_hf.py

# Full offline run (mock LLM judges, no API keys needed)
python -X utf8 experiments/run_all.py --mock

# Full real run (~4–6 hrs for 121 samples × 6 experiments with 4 live judges)
python -X utf8 experiments/run_all.py --no-mock

# Run a subset of experiments
python -X utf8 experiments/run_all.py --exp A D F

# Individual experiment
python experiments/exp_a_sast_baseline.py
```

All experiments produce:
- `datasets/processed/exp_<x>_results.json` — machine-readable metrics
- `datasets/processed/exp_<x>_summary.md` — dissertation-ready markdown table

**Real-mode detection:** elapsed times in `run_summary.json` should be **minutes**, not fractions of a second. Any experiment completing 121 samples in < 2s is running in mock mode despite `--no-mock` (check `.env` loading).

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

Four providers form the **active 4-judge design** (one per model family for Fleiss κ diversity). This is the genuinely payment-free design — **no provider below requires a credit card or payment method on file.**

| Provider | Judge class | Env var | Model | Architecture | Free-tier limit |
|---|---|---|---|---|---|
| OpenRouter | `OpenRouterJudge` | `OPENROUTER_API_KEY` | `cohere/north-mini-code:free` | Cohere (30B MoE, 3B active) | 20 req/min, 50 req/day (account-wide, shared with Poolside below) |
| OpenRouter | `OpenRouterJudge` | `OPENROUTER_API_KEY` | `poolside/laguna-xs-2.1:free` | Poolside (33B MoE, 3B active) | 20 req/min, 50 req/day (account-wide, shared with Cohere above) |
| Mistral AI | `MistralJudge` | `MISTRAL_API_KEY` | `open-mistral-nemo` | Mistral Nemo | ~1 RPS, 500K TPM |
| Groq | `GroqJudge` | `GROQ_API_KEY` | `llama-3.1-8b-instant` | Meta Llama 3.1 | 30 req/min, 14,400 req/day, 6,000 TPM (verified: [console.groq.com/docs/rate-limits](https://console.groq.com/docs/rate-limits)) |

**OpenRouter's 20 req/min and 50 req/day limits are ACCOUNT-WIDE, shared across both Cohere and Poolside combined** — not per-model. (An earlier version of this doc said 200 req/day per model; that figure came from a secondary aggregator and was wrong. Verified against [OpenRouter's own rate-limit docs](https://openrouter.ai/docs/api/reference/limits): unpaid accounts get 50 req/day total across all `:free` models; the 1000/day tier requires $10 in lifetime purchases, which breaks the no-card constraint.) See **ADR-001** (below) for the mitigation: a Drive-persisted judge-result cache shared across B/C/D/F, plus stratified subsampling for Exp F.

**Groq is the 4th judge (added for extra daily throughput, ADR-001 Option D).** At 14,400 req/day it is not a practical bottleneck — the full A–F pipeline's Groq-side calls (well under 2,000) finish quickly. OpenRouter's 50 req/day account-wide cap remains the binding constraint for the panel overall: Exp C/D/F still need all 4 judges' votes per sample, so the pipeline's total wall-clock time is still governed by Cohere/Poolside. What Groq buys you is (a) Exp B's per-judge Groq/Mistral rows complete almost immediately rather than waiting on OpenRouter's multi-day drip, and (b) a working 2-judge fallback (Mistral + Groq) if OpenRouter is ever fully unavailable. Adding a 4th judge also changes Fleiss κ from a 3-rater to a 4-rater computation — note this if comparing against any earlier 3-judge mock-mode results.

**OpenRouter replaces HuggingFace + Cerebras** as the primary two judges. Cerebras requires a payment method on file despite marketing itself as free-tier (confirmed via research after an earlier assumption proved wrong — see `git log` for the correction), and HuggingFace's free Router quota is frequently exhausted mid-run (HTTP 402). Both are kept as optional fallbacks (see below) but are no longer part of the default panel.

HuggingFace (`HF_API_KEY`), Cerebras (`CEREBRAS_API_KEY`), Together AI (`TOGETHER_API_KEY`), SambaNova (`SAMBANOVA_API_KEY`) and Gemini (`GEMINI_API_KEY`) remain wired into `judge_factory.py` as **optional extra judges** — set any of their keys to add them to the panel, but none are required.

**Priority chain in each experiment** (`src/llm/judge_factory.py::build_real_judges`):
```
OpenRouter (Cohere + Poolside) → Mistral (Nemo) → Groq (Llama 3.1 8B)
    → HF (Gemma, optional) → Cerebras (optional, needs payment)
    → Together (opt-in) → SambaNova (if no Cerebras key)
    → Gemini (emergency) → mock
```

### .env (payment-free 4-judge design)

```
OPENROUTER_API_KEY=...          # openrouter.ai/keys (FREE, no credit card) → Cohere + Poolside
MISTRAL_API_KEY=...             # console.mistral.ai → API Keys → Create (FREE Experiment plan)
GROQ_API_KEY=...                # console.groq.com (FREE, no credit card) → llama-3.1-8b-instant
```

Everything else in `.env.example` (`HF_API_KEY`, `CEREBRAS_API_KEY`, `TOGETHER_API_KEY`, `SAMBANOVA_API_KEY`, `GEMINI_API_KEY`) is optional — leave blank to skip.

### OpenRouter (cohere/north-mini-code:free + poolside/laguna-xs-2.1:free)

Endpoint: `POST https://openrouter.ai/api/v1/chat/completions`
Get a free key at `openrouter.ai/keys` — no credit card required for `:free`-suffixed models.
Rate limit: 20 requests/minute, 50 requests/day — **account-wide**, shared across both models combined (not per-model; see the correction above and ADR-001).

`OPENROUTER_RECOMMENDED_MODELS` in `openrouter_judge.py`:
```python
OPENROUTER_RECOMMENDED_MODELS = [
    "cohere/north-mini-code:free",
    "poolside/laguna-xs-2.1:free",
]
```

Model provenance:
- **Cohere North Mini Code** — Cohere Labs (2026). 30B-parameter MoE (3B active), Cohere's first agentic coding model. https://cohere.com/blog/north-mini-code
- **Poolside Laguna XS 2.1** — Poolside AI (2026). 33B-parameter MoE (3B active), open-weight coding model. https://poolside.ai/models

**Note on `nvidia/llama-nemotron-rerank-vl-1b-v2:free`:** this model was originally considered as a third judge but verified (via OpenRouter's own model page) to be a **cross-encoder reranker**, not a chat/completions model — it cannot accept a system/user prompt or return the `{is_vulnerable, cwe, severity, confidence, reasoning}` JSON schema VERDICT's judges require. It is not usable as an LLM judge; Mistral (`open-mistral-nemo`, direct API) was used instead.

### HuggingFace (gemma-3-27b-it)

Endpoint: `POST https://router.huggingface.co/v1/chat/completions`  
Token must be **fine-grained** with "Make calls to Inference Providers" permission.

`RECOMMENDED_MODELS` in `huggingface_judge.py` is now a **single-element list**:
```python
RECOMMENDED_MODELS = ["google/gemma-3-27b-it"]
```
`gemma-3-12b-it` was removed — same Google Gemma architecture as 27B inflated Fleiss κ artificially.  
`Llama-3.3-70B-Instruct` was removed — returns 403 on HF Router (routed via Groq/Cerebras, requires HF PRO $9/month) even after license acceptance. Now served via Cerebras (gpt-oss-120b) instead.

**HF Router HTTP error codes — lessons learned:**

| Code | Meaning | Fix |
|---|---|---|
| 200 | Works | — |
| 400 | Model not on the router | Try a different model (Mistral-7B, OLMo, Zephyr are NOT on the router) |
| 402 | Free-tier monthly quota exhausted | Wait for reset, or spread across days |
| 403 (gate form visible on HF page) | Gated model, license not accepted | Accept license at hf.co/model-name |
| 403 (no gate form on HF page) | Model served via Groq/Cerebras — HF PRO required | Pick a different model |

### Cerebras Cloud (gpt-oss-120b) ← THIRD JUDGE (OpenAI family)

Endpoint: `POST https://api.cerebras.ai/v1/chat/completions`  
Free tier: **1M tokens/day**, 30 RPM, 60K TPM. No credit card required.

Get key at: `cloud.cerebras.ai` → API Keys → Create  
Add to `.env` as: `CEREBRAS_API_KEY=<key>`

Model note: `llama-3.3-70b` deprecated 2026-02-16; `gpt-oss-120b` is the current production model.  
Rate handling: single 65s retry on 429. Circuit breaker opens if quota exhausted.

**If you get HTTP 403 / error code 1010 from Cerebras or Groq:** this is a Cloudflare IP block (common on university networks). Try from a mobile hotspot.

### SambaNova Cloud (Meta-Llama-3.3-70B-Instruct) ← FALLBACK (Cerebras preferred)

Endpoint: `POST https://api.sambanova.ai/v1/chat/completions`  
Free tier: 200K tokens/day, **20 RPM** — gets exhausted on a 121-sample run.  
Only used when `CEREBRAS_API_KEY` is not set.

### Mistral AI (open-mistral-nemo)

Endpoint: `POST https://api.mistral.ai/v1/chat/completions`  
Free "Experiment" plan: ~1 RPS, 500K TPM.

### Groq (llama-3.1-8b-instant) ← FOURTH JUDGE (Meta family)

Endpoint: `POST https://api.groq.com/openai/v1/chat/completions`
Free tier: **30 req/min, 14,400 req/day, 6,000 TPM** — verified against [console.groq.com/docs/rate-limits](https://console.groq.com/docs/rate-limits). No credit card required for the free tier (upgrading to the paid Developer tier does require one — do not do this).

Get key at: `console.groq.com` → sign up with email/Google/GitHub (no card, no waitlist).
Model must be explicitly enabled: `console.groq.com → Settings → Model Access`.
Add to `.env` as: `GROQ_API_KEY=<key>`

`src/llm/groq_judge.py` is wired into `judge_factory.py` as the 4th primary judge (ADR-001 Option D) — added specifically for its much larger daily quota relative to OpenRouter's 50 req/day account-wide cap.

**If you get HTTP 403 / error code 1010:** Cloudflare IP block (common on university networks) — try from a mobile hotspot.

Rate handling: 65s retry on 429; circuit breaker if quota exhausted.  
Key already in `.env` as `GROQ_API_KEY`.

### DNS Patch (`src/utils/dns_patch.py`)

On managed/university networks the system DNS may fail to resolve `router.huggingface.co`.  
`dns_patch.apply()` monkey-patches `socket.getaddrinfo` to fall back to Google DNS-over-HTTPS (8.8.8.8:443) on failure. Called at the top of both `validate_hf.py` and `run_all.py`. No external dependencies; harmless if DNS already works.

### `.env` Loading Fix (`experiments/run_all.py`)

`run_all.py` now loads `.env` at startup (same simple parser as `validate_hf.py`). Before this fix, running `--no-mock` silently fell back to mock mode because `os.getenv("HF_API_KEY")` returned empty — the key was in `.env` but never loaded into the process environment.

### Response Schema Resilience (`src/llm/response_parser.py`)

`_assert_schema()` only enforces the 5 critical fields: `is_vulnerable`, `cwe`, `severity`, `confidence`, `reasoning`. The 3 secondary fields are filled with sensible defaults if absent:
- `exploitability` → `"unknown"`
- `recommended_fix` → `"N/A"`
- `false_positive_probability` → `round(1.0 - confidence, 4)`

This prevents smaller models from silently defaulting `is_vulnerable=False` (which would bias recall downward) when they omit non-critical fields.

### validate_hf.py (tests HF + Cerebras + Mistral + Groq)

```powershell
python -X utf8 experiments/validate_hf.py
```

Expected output when all keys are present:
```
🔑  Using token: hf_xxxx…
  ✅ gemma-3-27b-it: OK — model answered is_vulnerable=True

🔑  Cerebras token: <masked>
  ✅ gpt-oss-120b (Cerebras): OK — ...

🔑  Mistral token: <masked>
  ✅ open-mistral-nemo (Mistral): OK — ...

🔑  Groq token: <masked>
  ✅ llama-3.1-8b-instant (Groq): OK — ...

Results: 4/4 models passed
✅  All models reachable. You can run experiments in --no-mock mode.
```

If Cerebras or Groq show `HTTP 403: error code: 1010`:
- This is a **Cloudflare IP ban**, not a key problem. Both services use Cloudflare's aggressive bot filter.
- **Fix**: run from a mobile hotspot (different IP) — almost always resolves it immediately.
- University/corporate network IP ranges are commonly blocked by Cloudflare.

Note: this script predates the OpenRouter-based payment-free redesign and still tests the legacy HF/Cerebras/SambaNova/Mistral/Groq set rather than the current primary panel (OpenRouter + Mistral + Groq) — see `task_98aa1346` in "What Needs Doing Next".

---

## ADR-001: Rate-Limit-Resilient Judge Execution (Colab notebook)

**Status:** Accepted. **Date:** 2026-07-14.

**Context:** OpenRouter's free tier is 50 req/day **account-wide** (Cohere + Poolside combined), not 200/day per model as an earlier version of this doc claimed. A naive full A–F run needs ~2,000 OpenRouter calls: Exp B, C, and D each independently re-derive `judge(sample)` on the same 121 untransformed samples (726 calls where 242 would do), and Exp F's 121-sample × 5-transform sweep alone needs 1,210 calls. At 50/day that's ~40 days for one run.

**Decision:** Implemented in `notebooks/VERDICT_Colab.ipynb`:
1. **Shared judge-result cache** (Section 5d, cell 8) — `cached_judge(judge, sample, code=None, transform='none')`, keyed by `(judge_name, sample_id, transform)`, persisted to `{RESULTS_DIR}/judge_cache.json` on Drive after every successful call. B, C, D, and F's baseline all route through it, so each sample is judged once and reused rather than re-derived per experiment. Errored calls are **never** cached, so a `429` or disconnect only loses the in-flight call — rerunning a cell resumes from where it left off instead of restarting from sample 0.
2. **429 circuit breaker** (same cache cell) — after 3 *consecutive* 429s from one judge, that judge is skipped for the rest of the session (`QUOTA_SKIPPED`, not retried) instead of retrying every remaining sample 3× with 65s backoffs each (~195s/sample wasted otherwise).
3. **Reload-previous-results cell** (Section 9g, inserted before orchestration) — repopulates `EXP_A_RESULTS`..`EXP_F_RESULTS` from Drive JSON at the start of a new session, since Colab doesn't persist Python variables across days but the results files do. Run this before calling `run_all_experiments()` with only that day's remaining experiments flagged `True`.
4. **Stratified subsampling for Exp F** (cell 21) — `stratified_subsample(dataset, n=30, seed=42)` picks a difficulty-balanced subset (matching the existing hard/medium/easy split) instead of running all 121 samples through all 5 transforms. Cuts F's OpenRouter need from 1,210 → ~300 calls. `n_full_dataset` and `subsampled` are recorded in `exp_f_results.json` for transparency.
5. **Groq as a 4th judge** (Option D, adopted) — `GroqJudge` (`llama-3.1-8b-instant`, 14,400 req/day, no card) added to `build_judges()` alongside OpenRouter + Mistral. Doesn't reduce OpenRouter's own call budget (Exp C/D/F still need all 4 judges' votes per sample, so wall-clock time is still governed by the 50 req/day cap), but Groq's own per-judge results (Exp B) complete almost immediately, and it provides a working 2-judge fallback (Mistral + Groq) if OpenRouter is ever unavailable. Changes Fleiss κ from a 3-rater to a 4-rater computation.

Combined effect: ~2,000 → ~550 OpenRouter calls for a full run (~11 days of OpenRouter quota instead of ~40, unaffected by adding Groq since Groq doesn't touch OpenRouter's cap). All mechanisms were smoke-tested (mock judges, synthetic dataset, and a fake always-429 judge) confirming: B/C/D reuse a single cache pass, Exp F reruns produce zero new cache entries, the circuit breaker stops calling after exactly 3 consecutive 429s, and the reload cell correctly repopulates a completed experiment's results while leaving not-yet-run ones as `None`.

**Consequences:**
- Exp F's adversarial robustness score is computed on n≈30 samples (150 cases) rather than n=121 (605 cases) by default — **disclose this as a compute-budget limitation in the dissertation's methodology section.** Pass `n_subsample=None` to `run_experiment_f()` to force the full sweep if quota allows.
- Fleiss κ and inter-rater agreement figures now reflect 4 raters, not 3 — any earlier 3-judge mock-mode numbers in this doc (see "Current Mock-Mode Results") are not directly comparable to a real 4-judge run.
- Not yet ported to `experiments/exp_*.py` (the local, non-Colab pipeline) — those still make redundant B/C/D calls, run Exp F on the full dataset, and have no circuit breaker or reload mechanism. Port this if local real-mode runs start hitting `429`s or need multi-session resumability too.
- Rejected: purchasing $10 OpenRouter credit to unlock the 1000/day tier — contradicts the explicit no-credit-card requirement for this project.

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
  1. `chore: latest project snapshot`
  2. `feat(experiments): switch primary benchmark to SecurityEval (121 samples)`
  3. `data(securityeval): add 121-sample SecurityEval benchmark dataset`
  4. `chore(results): add initial mock-mode experiment outputs`
  5. `feat(experiments): add controlled experiment runners A–F`

**Git push workaround:** The Windows NTFS mount blocks `git add` due to `.git/index.lock`. Always push via:
```bash
cd /tmp
git clone --no-local <remote_url> verdict_push
# copy files, commit, push from /tmp/verdict_push
```

---

## What Needs Doing Next

### Immediate (unblock real results)

1. **Get an OpenRouter API key** — the new primary judge #1 and #2 (Cohere + Poolside), genuinely free, no credit card
   ```
   openrouter.ai  →  sign up (free, no credit card)  →  Keys  →  Create
   ```
   Add to `.env`:
   ```
   OPENROUTER_API_KEY=<your_key>
   ```

2. **Confirm both required keys are in `.env`**
   ```
   OPENROUTER_API_KEY=...       # NEW — get from openrouter.ai/keys
   MISTRAL_API_KEY=...          # already present
   ```
   Everything else in `.env.example` is optional (HF/Cerebras/Together/SambaNova/Groq/Gemini) — leave blank to skip.

3. **Validate providers**
   ```powershell
   python -X utf8 experiments/validate_hf.py
   ```
   Note: as of this writing `validate_hf.py` still probes the old HF/Cerebras/SambaNova/Mistral/Groq set and does not yet test OpenRouter — a follow-up task (`task_98aa1346`, spawned but not yet run) adds an OpenRouter probe and drops the hard HF_API_KEY requirement. Until that lands, confirm OpenRouter connectivity by running a single real-mode experiment (e.g. `python experiments/exp_b_single_llm.py`) and checking for `[Exp B] Using OpenRouter judges: [...]` in the output.

4. **Run real experiments**
   ```powershell
   python -X utf8 experiments/run_all.py --no-mock
   ```
   Watch for these judge lines at startup of each experiment:
   ```
   [Exp B] Using OpenRouter judges: ['cohere/north-mini-code:free', 'poolside/laguna-xs-2.1:free']
   [Exp B] Using Mistral judges: ['open-mistral-nemo']
   ```
   Monitor for `[warn]` lines (sample defaulted to is_vulnerable=False). OpenRouter's free tier is
   rate-limited to 20 req/min and **50 req/day, account-wide across both Cohere and Poolside
   combined** (not per-model — see the correction above). A single 121-sample experiment already
   exceeds the daily cap on its own; running A–F back-to-back needs either the cache/subsampling
   mitigation from ADR-001 (implemented in `notebooks/VERDICT_Colab.ipynb`, not yet ported to
   `experiments/`) or spreading the run across multiple days using `run_all.py --exp`.

5. **Commit real results** — after `run_all.py` completes, `datasets/processed/` will contain final JSON + MD files. Commit and push using the `/tmp` clone workaround.

### After results are in

5. **Statistical interpretation** — check the real Fleiss κ in `exp_d_results.json`.
   - Three architecturally diverse models (Google Gemma, OpenAI GPT OSS, Mistral) should produce lower κ than two same-family models would have.
   - If κ is low (< 0.4) despite high F1, that is a meaningful dissertation finding: models converge on correct verdicts through different reasoning paths.
   - Paired bootstrap p-values in `exp_b` vs `exp_d` determine whether consensus is significantly better than single-LLM.

6. **Dissertation write-up** — copy tables from `exp_*_summary.md` directly into the dissertation. Key narrative:
   - Exp A: SAST alone has 7.4% recall → inadequate for general use
   - Exp B vs C: hybrid adds marginal gain over single LLM
   - Exp D: consensus improves recall; discuss inter-model agreement (Fleiss κ) and note the four-family model selection (Cohere / Poolside / Mistral / Meta Llama via Groq) for diversity
   - Exp E: consensus discrimination score = 1.000 (perfect paired discrimination, n=9 pairs)
   - Exp F: adversarial robustness score and which transforms most degrade detection

7. **Poster (29 Jul 2026)** — headline numbers: Exp D consensus F1 and Exp F robustness score. Secondary: Exp A recall (7.4%) as motivation for LLM-based approaches.

### Optional improvements

8. **Extend SAST coverage** — add detectors for CWE-78, CWE-400, CWE-267/250 to push Exp A recall above 7.4%. Useful dissertation discussion point even without full implementation.

9. **Add safe samples** — synthetically patch some SecurityEval samples to remove the all-positive limitation and enable meaningful precision/Cohen κ metrics.

10. **Beyond Python: PLC code** — after the Python results validate the consensus+SAST approach, port the same methodology to real PLC languages (ladder logic / structured text, IEC 61131-3), building on the industrial_python/SCADA-context samples already in `seed_dataset.json`. This is future work, not required for the dissertation deadline, but should be noted as the natural next research direction in the write-up.

---

## Tests

```bash
python -m pytest tests/ -v      # 46 tests, all pass
```

Key test files: `tests/test_detectors.py`, `tests/test_llm_base_judge.py`, `tests/test_llm_consensus_engine.py`, `tests/test_evaluation_framework.py`
