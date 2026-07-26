# VERDICT — Project Context for AI Assistants (Colab-Only Edition)

**Project name:** VERDICT (Vulnerability Evaluation by Reasoning, Consensus, Integration, and Detection Tiers)
**Type:** MSc Data Science & AI dissertation — University of Leeds
**Author:** Pranit Chatterjee (pranitchatz@gmail.com)
**Deadlines:** Poster 29 July 2026 · Dissertation 10 August 2026
**Canonical artifact:** a single Google Colab notebook. There is no live GitHub dependency during execution — the notebook is self-contained from mount to final figure. After a successful run, the finished notebook (with all tables/charts already rendered as cell outputs) is manually added to `https://github.com/Pranit-NCU/Agent_Security_Detector` as a dated archival snapshot.

---

## Research Goal

Empirically evaluate whether multi-LLM consensus + SAST improves vulnerability detection in AI-generated Python code versus single-tool approaches from present studies then apply those methods for PLC codes. Six controlled experiments (A–F) compare strategies across a standardised benchmark.

**Not Python-only by design.** Python is the validation language for Experiments A–F because mature SAST tooling and benchmarks (SecurityEval, VUDENC) exist for it. Once the consensus+SAST approach is validated in this notebook, the same detection methodology (SAST pattern rules + multi-LLM judge consensus + statistical agreement analysis) is intended to be carried over to **PLC code** (ladder logic / structured text / IEC 61131-3), motivated by the SCADA/PLC-context samples already seeded in `seed_dataset.json`. Python is the proving ground, not the boundary of the research.

---

## Single-Environment Architecture: Everything Lives in One Notebook

VERDICT has no local development environment, no installable `src/` Python package, and no `git clone` step. There is nothing to check out and nothing to `pip install -e`. The entire project — SAST detectors, LLM judge clients, the consensus engine, statistical tests, adversarial transforms, all six experiment runners, and figure generation — is authored directly as cells in one notebook, run top to bottom in a single Colab session.

Key consequences of this design:

* **No `.env` file.** API keys are never written to disk or committed anywhere. They are entered once per session via `getpass` prompts (or read from Colab's built-in secrets manager, `google.colab.userdata`) and held only in the runtime's memory for that session.
* **No `git clone`, no `git push`, no repo checkout at any point during a run.** The notebook does not know or care that a GitHub repo exists while it is executing.
* **Google Drive holds data, not code.** Drive is mounted once per session purely as persistent storage: input datasets (uploaded once, kept permanently), and per-run `results/`, `charts/`, `logs/`, `raw_outputs/`. Every cell that produces an artifact writes it under `MyDrive/VERDICT/...` so nothing is lost if the runtime disconnects mid-run.
* **Code lives in the notebook itself, organized by section, not by file.** Where the old file-based design would have `src/detectors/sql_injection.py`, this design has a cell (or small group of cells) under a "SAST Detectors" section defining the same class in-line. Restructuring the project means reordering or editing cells, not files.
* **The only contact with GitHub happens after the fact.** Once a full run completes and the notebook contains its final summary tables and 300 DPI charts as rendered outputs, it is downloaded (`File → Download → Download .ipynb`) or exported via "Save a copy to Drive" and then manually added to the repo as a dated snapshot, e.g. `notebooks/archive/VERDICT_run_2026-07-06.ipynb`. This is a deliberate, manual archival step taken by the author — never an automated `git commit`/`git push` invoked from inside Colab.

---

## Notebook Structure

The notebook is organized into ordered sections. Cells within each section run top to bottom; later sections depend on classes/functions defined earlier in the same session.

| Section | Purpose |
|---|---|
| **1. Setup** | Mount Drive, create the `MyDrive/VERDICT/{datasets,results,reports,charts,logs,raw_outputs}` folder structure, `pip install` the small dependency set (`matplotlib`; everything else is stdlib). No `requirements.txt` file — the install cell lists packages inline. |
| **2. Config** | A handful of path constants pointing at the Drive folders from Section 1 (the in-notebook equivalent of `src/config.py`) plus a top-level `USE_MOCK_JUDGES = True/False` flag that controls the whole run. |
| **3. Datasets** | Load `securityeval_dataset.json` (121 Python samples, 69 CWEs — primary benchmark for Exp A–D, F) and `seed_dataset.json` (25 paired vuln/patch/clean samples — Exp E) from a Drive folder they were uploaded to once, ahead of time. |
| **4. SAST Detectors** | `SQLInjectionDetector` (CWE-89), `SecretsDetector` (CWE-798), `AuthDetector` (CWE-287) defined as in-notebook classes. |
| **5. LLM Judges** | `BaseLLMJudge` plus one class per provider (HuggingFace/Gemma, Cerebras/GPT-OSS, Mistral/Nemo, Together/Llama, Groq and Gemini as fallbacks) and a judge-factory cell implementing the same provider priority chain used across experiments. |
| **6. Consensus Engine + Prompt Builder** | Majority-vote and weighted-vote consensus logic, and the shared prompt template used by every judge call. |
| **7. Statistical Tests** | Cohen's κ, Fleiss' κ, paired bootstrap significance test, Benjamini-Hochberg FDR correction. |
| **8. Adversarial Transforms** | The five transformation techniques used by Experiment F. |
| **9. Experiment Runners A–F** | Each experiment (SAST baseline, single LLM, hybrid, multi-LLM consensus, paired discrimination, adversarial robustness) as a callable function/cell, mirroring the logic of the file-based `experiments/exp_*.py` scripts one-for-one but with no imports across files. |
| **10. Orchestration ("Run All")** | One cell that calls Experiments A–F in sequence, with progress logging, timing, and a real-mode sanity check (elapsed time per experiment should be minutes, not fractions of a second, once `USE_MOCK_JUDGES = False`). |
| **11. Figures** | Generates the publication-quality 300 DPI PNGs (headline F1, per-model bars, latency, Cohen's-κ agreement matrix, paired discrimination, adversarial robustness) straight to `MyDrive/VERDICT/charts`. |
| **12. Results Export + Summary Tables** | Writes `exp_<x>_results.json` and renders the dissertation-ready markdown tables inline as cell output. |
| **13. Archival** | A short markdown cell with the manual steps for downloading the finished notebook and adding it to the GitHub repo as a dated snapshot — the only point in the whole workflow that references GitHub. |

---

## Running the Notebook

1. Open the notebook in Colab.
2. Run Section 1 — mount Drive, authorize when prompted, confirm the six folders under `MyDrive/VERDICT` exist.
3. Run Section 2 — set `USE_MOCK_JUDGES = False` for a real run (or leave `True` for an offline dry run with seeded random judges).
4. Enter API keys when prompted by the `getpass` cells in Section 5 (or pre-load them into Colab's Secrets panel and reference them via `google.colab.userdata.get(...)`).
5. Run Sections 3–9 top to bottom to define all datasets, detectors, judges, and experiment logic for this session.
6. Run Section 10 ("Run All") and let Experiments A–F execute in sequence — expect **2–6 hours** for a full real run across 121 samples with 3+ live judges.
7. Run Section 11 and 12 to render figures and summary tables inline.
8. Inspect the rendered tables/charts directly in the notebook output.
9. Follow Section 13 to download the completed `.ipynb` and manually place it in the GitHub repo's archive folder.

There are no CLI flags (`--mock`, `--no-mock`, `--exp A D F`) — the equivalent controls are the `USE_MOCK_JUDGES` flag and simply commenting out experiment calls in the Section 10 orchestration cell.

---

## LLM Providers & Keys

Three providers form the active 3-judge design (one per model family, for Fleiss κ diversity). All free-tier, no credit card. Keys are entered once per session via `getpass` (or pulled from Colab Secrets) — never written to a file.

| Provider | Judge class | Session variable | Model | Architecture | Daily quota |
|---|---|---|---|---|---|
| HuggingFace Router | `HuggingFaceJudge` | `HF_API_KEY` | `google/gemma-3-27b-it` | Google Gemma | HF Router |
| **Cerebras** | `CerebasJudge` | `CEREBRAS_API_KEY` | `gpt-oss-120b` | OpenAI GPT OSS | free public endpoint |
| Mistral AI | `MistralJudge` | `MISTRAL_API_KEY` | `open-mistral-nemo` | Mistral Nemo | ~500K TPM |

Optional fourth judge and fallbacks:

* **Together AI** (`TOGETHER_API_KEY`) — `Llama-3.3-70B-Instruct-Turbo-Free`, Meta family, opt-in.
* **SambaNova** (`SAMBANOVA_API_KEY`) — `Meta-Llama-3.3-70B-Instruct`, used only if `CEREBRAS_API_KEY` is not supplied this session; free tier is 200K tokens/day at 20 RPM, which gets exhausted on a 121-sample run.
* **Groq** (`GROQ_API_KEY`) — `llama-3.1-8b-instant`, supplementary/emergency judge.
* **Gemini** (`GEMINI_API_KEY`) — last-resort fallback.

**Priority chain (same logic as the judge-factory cell in Section 5):**
```
HF (Gemma) → Cerebras (GPT-OSS 120B) → Mistral (Nemo)
    → SambaNova (if no Cerebras key) → Together (if enabled) → Groq (supplementary)
    → Gemini (emergency) → mock
```

### HuggingFace (gemma-3-27b-it)

Endpoint: `POST https://router.huggingface.co/v1/chat/completions`. Token must be **fine-grained** with "Make calls to Inference Providers" permission.

Only `google/gemma-3-27b-it` is used — `gemma-3-12b-it` was dropped (same architecture inflated Fleiss κ artificially) and `Llama-3.3-70B-Instruct` was dropped (403s on the HF Router without HF PRO; served via Cerebras instead).

**HF Router HTTP error codes:**

| Code | Meaning | Fix |
|---|---|---|
| 200 | Works | — |
| 400 | Model not on the router | Try a different model |
| 402 | Free-tier monthly quota exhausted | Wait for reset, or spread runs across days |
| 403 (gate form visible on HF page) | Gated model, license not accepted | Accept license at hf.co/model-name |
| 403 (no gate form) | Model served via Groq/Cerebras — needs HF PRO | Pick a different model |

### Cerebras Cloud (gpt-oss-120b) — third judge, OpenAI family

Endpoint: `POST https://api.cerebras.ai/v1/chat/completions`. Free tier: 1M tokens/day, 30 RPM, 60K TPM, no credit card. `llama-3.3-70b` was deprecated 2026-02-16; `gpt-oss-120b` is current. Single 65s retry on 429; circuit breaker opens if quota exhausted.

**If Cerebras or Groq return HTTP 403 / error code 1010:** this is a Cloudflare IP block, common on university/corporate networks and equally possible from a Colab runtime's egress IP. Restarting the Colab runtime sometimes reassigns a different IP; otherwise this provider is simply unavailable for that session and the priority chain falls through to the next one.

### SambaNova Cloud (Meta-Llama-3.3-70B-Instruct) — fallback

Endpoint: `POST https://api.sambanova.ai/v1/chat/completions`. Free tier: 200K tokens/day, 20 RPM. Only engaged when no Cerebras key is entered this session.

### Mistral AI (open-mistral-nemo)

Endpoint: `POST https://api.mistral.ai/v1/chat/completions`. Free "Experiment" plan: ~1 RPS, 500K TPM.

### Groq (llama-3.1-8b-instant) — supplementary

Model must be explicitly enabled under `console.groq.com → Settings → Model Access`. Same Cloudflare 403/1010 caveat as Cerebras. 65s retry on 429; circuit breaker if quota exhausted.

### DNS considerations

If `router.huggingface.co` fails to resolve from a given Colab runtime, a DNS-over-HTTPS fallback (querying 8.8.8.8 over HTTPS) resolves the same class of failure that affects managed campus networks locally — the fallback logic lives in the Setup section's networking cell and is harmless if DNS already works.

---

## SAST Detectors

Three detectors, defined as classes in the notebook's Section 4:

| Detector | CWE | Severity trigger |
|---|---|---|
| `SQLInjectionDetector` | CWE-89 | CRITICAL / HIGH |
| `SecretsDetector` | CWE-798 | CRITICAL / HIGH |
| `AuthDetector` | CWE-287 | CRITICAL / HIGH |

Only 3 CWEs are covered — intentional, to demonstrate SAST's narrow coverage (Exp A finding: recall = 7.4% on SecurityEval's 69 CWEs).

**Possible future work:** add detectors for CWE-78 (command injection), CWE-400 (resource exhaustion), CWE-267/250 (unsafe dynamic exec/import) as additional cells in Section 4.

---

## Datasets

Both datasets are uploaded once to a Drive folder (`MyDrive/VERDICT/datasets/`) and loaded from there every session — there is no repo-tracked `datasets/` directory.

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

---

## Statistical Tests

All stdlib-only, defined inline in Section 7:

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
- Exp E uses the paired seed dataset. All other experiments use SecurityEval.
- Mock results use seeded random accuracy — not meaningful for the dissertation. Real API runs needed for final results.

---

## What Needs Doing Next

### Immediate (unblock real results)

1. **Get a Cerebras API key** (`cloud.cerebras.ai` → sign up, free, no credit card → API Keys → Create). Have it ready to paste into the Section 5 `getpass` prompt or Colab Secrets panel.
2. **Confirm all keys are ready to enter each session**: HF, Cerebras, Mistral, SambaNova (fallback), Groq. None of these are stored in a file — re-enter (or re-reference from Secrets) at the start of every session.
3. **Run the validation cell** (equivalent of `validate_hf.py`) before a real run — confirms all providers are reachable and prints which models responded.
4. **Run the notebook top to bottom with `USE_MOCK_JUDGES = False`.** Expected runtime: 2–4 hours. Watch the Section 10 orchestration output for judge selection lines per experiment and any rate-limit backoff messages (handled automatically).
5. **Archive the finished notebook** — download the completed `.ipynb` (with all tables/charts rendered as outputs) and manually add it to the GitHub repo's archive folder as a dated snapshot. This is the only step that touches GitHub.

### After results are in

6. **Statistical interpretation** — check the real Fleiss κ from Section 10's Exp D output. Three architecturally diverse models (Google Gemma, OpenAI GPT OSS, Mistral) should produce lower κ than two same-family models would. A low κ (<0.4) despite high F1 is a meaningful dissertation finding: models converge on correct verdicts through different reasoning paths. Compare Exp B vs Exp D paired-bootstrap p-values to determine whether consensus is significantly better than single-LLM.
7. **Dissertation write-up** — copy the Section 12 summary tables directly into the dissertation. Key narrative:
   - Exp A: SAST alone has 7.4% recall → inadequate for general use
   - Exp B vs C: hybrid adds marginal gain over single LLM
   - Exp D: consensus improves recall; discuss inter-model agreement (Fleiss κ) and the three-family model selection (Google Gemma / OpenAI GPT-OSS / Mistral) for diversity
   - Exp E: consensus discrimination score = 1.000 (perfect paired discrimination, n=9 pairs)
   - Exp F: adversarial robustness score and which transforms most degrade detection
8. **Poster (29 Jul 2026)** — headline numbers: Exp D consensus F1 and Exp F robustness score. Secondary: Exp A recall (7.4%) as motivation for LLM-based approaches.

### Optional improvements

9. **Extend SAST coverage** — add detector cells for CWE-78, CWE-400, CWE-267/250 to push Exp A recall above 7.4%. Useful dissertation discussion point even without full implementation.
10. **Add safe samples** — synthetically patch some SecurityEval samples to remove the all-positive limitation and enable meaningful precision/Cohen κ metrics.
11. **Beyond Python: PLC code** — after the Python results validate the consensus+SAST approach, port the same methodology to real PLC languages (ladder logic / structured text, IEC 61131-3), building on the industrial_python/SCADA-context samples already in `seed_dataset.json`. Future work, not required for the dissertation deadline, but worth flagging as the natural next research direction in the write-up.

---

## Verification Cells (in place of a test suite)

There is no standalone `tests/` directory or `pytest` project — that structure assumes a repo checkout, which this workflow deliberately avoids during execution. Instead, each major section (detectors, judges, consensus engine, statistics) ends with a small "sanity check" cell that asserts known-good behavior against a hand-picked example (e.g. a known-SQL-injection snippet must trigger `SQLInjectionDetector`; `cohens_kappa` on identical rater vectors must return 1.0). These run once per session as part of the normal top-to-bottom execution, trading automated CI-style coverage for inline confidence at definition time.
