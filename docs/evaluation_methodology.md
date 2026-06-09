# Evaluation Methodology Specification

**Project:** Hybrid Symbolic–Semantic Vulnerability Detection Framework
**Document Status:** Authoritative methodology blueprint (v1.0)
**Audience:** MSc dissertation supervisor, examiners, and implementation engineers
**Scope:** Defines all evaluation procedures, datasets, metrics, statistical analysis, and outputs that downstream implementation must conform to. No code is prescribed here.

---

## 1. Research Objectives

The evaluation framework is designed to answer one overarching question: *Does combining static symbolic analysis (SAST) with semantic reasoning from Large Language Models (LLMs), and aggregating multiple LLMs through a consensus mechanism, produce a measurably more reliable Python vulnerability detector than any single component used in isolation?*

The specific objectives derived from this question are:

1. **O1 — Quantify single-component baselines.** Establish reference performance for (a) the SAST detector suite alone and (b) each individual LLM judge alone, on a controlled, multi-tier dataset.
2. **O2 — Quantify hybrid lift.** Measure the incremental classification quality obtained by combining SAST signals with a single LLM judge versus either component alone.
3. **O3 — Quantify consensus lift.** Measure the incremental classification quality and stability obtained by aggregating multiple heterogeneous LLM judges through a consensus engine, relative to the best single LLM.
4. **O4 — Test discrimination on paired data.** Determine whether the framework can reliably distinguish vulnerable code from its semantically-similar fixed counterpart, isolating *vulnerability detection* from *code-style classification*.
5. **O5 — Characterise robustness.** Quantify how performance degrades under adversarial transformations (renaming, dead-code insertion, comment injection, control-flow obfuscation) and identify which configuration is most robust.
6. **O6 — Characterise operational cost.** Report latency, token cost, and disagreement rate so that the recommended configuration is justified on a quality–cost frontier, not on quality alone.
7. **O7 — Produce a reproducible artefact.** Ensure every reported number can be regenerated from a fixed dataset snapshot, fixed prompt templates, fixed model identifiers, and fixed seeds.

These objectives are intentionally written so that each maps to at least one experiment (Section 4) and at least one statistical test (Section 9).

---

## 2. Research Questions

The objectives are operationalised as the following research questions (RQs). Each RQ is paired with the experiments that answer it and the primary metric used.

| ID  | Research Question | Primary Experiment(s) | Primary Metric |
|-----|-------------------|------------------------|----------------|
| RQ1 | Does the hybrid SAST+LLM pipeline outperform SAST alone on Python vulnerability detection? | A vs C | F1 |
| RQ2 | Does the hybrid SAST+LLM pipeline outperform any single LLM alone? | B vs C | F1 |
| RQ3 | Does multi-LLM consensus outperform the best single LLM? | B vs D | F1, disagreement-adjusted F1 |
| RQ4 | Can the framework reliably discriminate vulnerable code from its fixed counterpart? | E | Paired accuracy, ΔConfidence |
| RQ5 | How robust is each configuration to adversarial transformations? | F | F1 degradation Δ, attack success rate |
| RQ6 | How well-calibrated and how consistent are the LLM judges, individually and under consensus? | B, D | ECE, Brier, run-to-run agreement |
| RQ7 | What is the latency / quality trade-off across configurations? | A–D | Latency vs F1 Pareto frontier |

RQ1–RQ3 are *primary* (directly tied to the dissertation's thesis statement). RQ4–RQ7 are *secondary* and exist to defend the framework against examiner criticism (validity, robustness, deployability).

---

## 3. Research Hypotheses

Each hypothesis is stated in null/alternative form so that Section 9's statistical tests have a precise target. All comparisons are made on the held-out *test* split unless otherwise noted.

### Required hypotheses

- **H1 — Hybrid > SAST.**
  - $H_{1,0}$: $F1_{\text{Hybrid}} \le F1_{\text{SAST}}$
  - $H_{1,1}$: $F1_{\text{Hybrid}} > F1_{\text{SAST}}$
  - Rationale: SAST has high precision on its narrow rule set but low recall on semantic bugs; LLMs should fill the recall gap.

- **H2 — Consensus > Single LLM.**
  - $H_{2,0}$: $F1_{\text{Consensus}} \le \max_i F1_{\text{LLM}_i}$
  - $H_{2,1}$: $F1_{\text{Consensus}} > \max_i F1_{\text{LLM}_i}$
  - Rationale: Heterogeneous models make decorrelated errors; aggregation should reduce variance.

- **H3 — Vulnerable vs Fixed discrimination.**
  - $H_{3,0}$: On paired (vulnerable, fixed) samples, the framework's predicted vulnerability probability for the vulnerable variant is not greater than for the fixed variant.
  - $H_{3,1}$: $P(\text{vuln} \mid \text{vulnerable}) > P(\text{vuln} \mid \text{fixed})$, paired.
  - Rationale: A detector that only learns surface style will fail this test even if its marginal F1 is high.

- **H4 — Adversarial degradation.**
  - $H_{4,0}$: Performance on adversarial variants is statistically equal to performance on the original samples.
  - $H_{4,1}$: $F1_{\text{adv}} < F1_{\text{clean}}$ (one-sided).
  - Rationale: Establishes that the benchmark is non-trivial; an undegraded score would suggest the model is memorising fingerprints.

- **H5 — Consensus robustness.**
  - $H_{5,0}$: The relative degradation under adversarial transformation for the consensus is equal to the worst single LLM's relative degradation.
  - $H_{5,1}$: $\Delta F1_{\text{Consensus}} < \Delta F1_{\text{worst single LLM}}$
  - Rationale: Consensus should not only be more accurate (H2) but also fail more gracefully.

### Additional hypotheses (justified additions)

The following are recommended in addition to H1–H5 because they directly address threats to validity that an examiner is likely to raise:

- **H6 — Calibration of consensus.** $H_{6,1}$: Expected Calibration Error (ECE) of the consensus aggregator is lower than the mean ECE of the individual LLMs. Justification: a system that is more accurate but less calibrated is harder to deploy and harder to defend.
- **H7 — Independence of gains.** $H_{7,1}$: The hybrid (C) and consensus (D) gains are *additive* rather than redundant; i.e. SAST+Consensus > Consensus alone and > Hybrid alone. Justification: shows that the symbolic and semantic streams contribute non-overlapping information.

H6 and H7 are MSc-appropriate (they require no extra data collection, only extra analysis on already-collected predictions) and substantially strengthen the dissertation's claims.

---

## 4. Experimental Design

All six experiments share the same evaluation harness, the same test split, the same prompt template (Section 7), the same scoring code, and the same random seeds. Only the *configuration under test* varies.

### Common protocol

- **Inputs.** Each sample is a tuple `(sample_id, code, label, cwe, source_dataset, tier, is_adversarial, pair_id)`.
- **Output of any configuration.** A per-sample record `(sample_id, predicted_label ∈ {vuln, safe}, confidence ∈ [0,1], predicted_cwe?, latency_ms, raw_response)`.
- **Determinism.** LLM temperature = 0, top_p = 1, fixed seed where the provider supports it; for providers without seed support this is declared as a threat to validity (Section 10).
- **Repetition.** Each LLM-based experiment is run **3 times** on the test split. The reported point estimate is the mean across runs; the run-to-run agreement is reported as a *consistency* metric (Section 8).
- **Blinding.** The configuration under test never sees the `label`, `source_dataset`, `tier`, or `is_adversarial` fields. Only `code` (and language hint = Python) is passed to the model.

### Experiment A — SAST-only baseline

- **Configuration.** Existing SAST detectors in `src/detectors/` (SQLInjection, Secrets, plus any others available at evaluation time).
- **Input.** Test split, raw Python source.
- **Output.** Binary label = (any vulnerability detected); confidence = max detector confidence; predicted_cwe = highest-severity CWE.
- **Metrics.** Full classification suite (Section 8). Latency. Per-CWE recall.
- **Expected finding.** High precision (≥0.90 on its covered CWEs), low recall on CWEs outside its rule set (~0.20–0.40 overall).

### Experiment B — Single LLM baseline

- **Configuration.** Each LLM judge run independently: Gemini, an OpenRouter-hosted model, an Ollama-hosted local model, and a HuggingFace-hosted model. (The exact models are pinned in the run manifest; see Section 10.)
- **Input.** Test split + standardised prompt (Section 7).
- **Output.** Per-judge per-sample prediction.
- **Metrics.** Full classification suite, per judge. Latency per judge. Confidence calibration (ECE, Brier). Hallucination rate. Run-to-run consistency.
- **Expected finding.** Higher recall than SAST, lower precision, with substantial inter-judge variance.

### Experiment C — Hybrid SAST + LLM

- **Configuration.** SAST output is supplied to the LLM as evidence in the prompt (the prompt carries a structured "static_findings" field). Final label is produced by the LLM conditioned on this evidence. The single LLM used here is the **best** single LLM from Experiment B (selected on the *validation* split, not test).
- **Input.** Test split + prompt enriched with SAST findings.
- **Output.** Single label/confidence per sample.
- **Metrics.** Full classification suite. Δ vs Experiment A. Δ vs Experiment B (best single LLM).
- **Expected finding.** Recall ≥ best single LLM, precision ≥ best single LLM, with the largest gain on CWEs that SAST already covers (SAST acts as a high-precision anchor).

### Experiment D — Multi-LLM Consensus

- **Configuration.** All judges from Experiment B aggregated by the chosen consensus rule (Section 6). Two variants are reported:
  - D1: consensus over the LLMs alone.
  - D2: consensus over the LLMs *plus* SAST as an additional voter (this directly tests H7).
- **Input.** Test split + standardised prompt; SAST findings included for D2.
- **Output.** Aggregated label, aggregated confidence, abstention flag, disagreement score.
- **Metrics.** Full classification suite. Disagreement rate. Calibration (ECE, Brier) of the aggregated confidence. Abstention-conditioned F1 (F1 on the non-abstained subset, with abstention rate reported alongside).
- **Expected finding.** D1 ≥ best single LLM on F1 with materially lower variance across the 3 repetitions; D2 ≥ D1 on precision.

### Experiment E — Vulnerable vs Fixed discrimination

- **Configuration.** Each system from A, B (best single), C, D1, D2 is evaluated on the *paired* subset only (samples where both a vulnerable and a fixed variant exist; Juliet "good"/"bad" pairs and synthetic-fix pairs).
- **Input.** Paired samples, predicted independently (the model never sees both halves of a pair in the same call).
- **Output.** For each pair: $\hat{p}_{\text{vuln}}$ on vulnerable variant, $\hat{p}_{\text{vuln}}$ on fixed variant.
- **Metrics.** Paired accuracy = fraction of pairs where $\hat{p}_{\text{vuln}}^{\text{bad}} > \hat{p}_{\text{vuln}}^{\text{good}}$. Mean ΔConfidence. McNemar's test (Section 9). Per-CWE breakdown.
- **Expected finding.** Paired accuracy ≥ 0.80 for hybrid/consensus; SAST-only paired accuracy near the per-CWE coverage rate.

### Experiment F — Adversarial robustness

- **Configuration.** Each system from A, B (each judge individually), C, D1, D2 is evaluated on the Tier-4 adversarial set, which contains transformed copies of test-split samples.
- **Transformations** (each applied independently and reported separately, then jointly):
  - Identifier renaming (variables, functions) to neutral tokens.
  - Dead-code injection (unused branches, unreachable functions).
  - Comment injection (misleading or benign comments).
  - Control-flow obfuscation (semantically-equivalent rewrites: `if/else` ↔ ternary, loop unrolling, function inlining).
- **Input.** Adversarial split + standardised prompt.
- **Output.** Per-sample prediction, joined back to its clean-sample ancestor by `pair_id`.
- **Metrics.** Attack Success Rate (ASR) = fraction of clean-correct samples that flip to incorrect under attack. Δ F1, Δ Recall, Δ Precision per transformation. Per-configuration robustness ranking.
- **Expected finding.** SAST is most robust to renaming (regex-based) but breaks on control-flow obfuscation that hides patterns; LLMs are most robust to control-flow rewrites but vulnerable to misleading comments; consensus has the lowest ASR overall (H5).

---

## 5. Dataset Methodology

### Composition and target sample counts

| Tier | Source | Role | Target n (test split) | Notes |
|------|--------|------|------------------------|-------|
| 1 | Juliet Test Suite (Python subset) | Controlled, labelled, paired | 600 (300 vuln + 300 fixed) | Pairs by construction (`good_*` / `bad_*`). |
| 2 | DiverseVul (Python only) | Real-world diversity | 600 | Labels at function level; CWE-stratified sampling. |
| 3 | Synthetic samples | Targeted CWE coverage | 200 (100 vuln + 100 fixed) | Authored to cover CWEs underrepresented in T1/T2. |
| 4 | Adversarial variants | Robustness | up to 4× the clean test set | Generated from T1+T2+T3 test samples only — never from train/val. |
| — | Big-Vul | *Excluded* from initial evaluation | 0 | Reserved for future work; declared in Section 10. |

Total clean test set ≈ **1 400 samples** with ~50/50 class balance. Sample counts may be reduced uniformly if API budget is binding, but the *ratios* and the *paired* property must be preserved.

### Sampling strategy

- **Stratification axes:** class (vuln/safe), CWE category, source tier, code length bucket (short/medium/long).
- **Method:** stratified random sampling with a fixed seed, performed once and persisted as `datasets/processed/splits.json`. All experiments load from this file; no on-the-fly resampling.

### Train / Validation / Test rationale

The framework is *not* trained — LLMs are used in zero-shot mode and SAST is rule-based — so "train" is replaced by "development":

- **Development split (≈ 20 %).** Used only to (a) iterate on prompts, (b) select the best single LLM for Experiment C, (c) tune the consensus rule's threshold and abstention cutoff (Section 6).
- **Validation split (≈ 10 %).** Used once, after development is frozen, to verify that the chosen prompt / consensus configuration generalises before locking it.
- **Test split (≈ 70 %).** Used exactly once per configuration to produce the numbers reported in the dissertation. No prompt or threshold change is permitted after the test split is touched; if a change is made, the affected experiment is re-run on a *fresh* held-out subset and this is declared.

Splits are defined at the **`pair_id`** level (not the sample level) so that a vulnerable sample and its fixed counterpart always land in the same split.

### Pair generation strategy

- **Juliet:** pairs are intrinsic — `bad_*` and corresponding `good_*` functions share a `pair_id`.
- **Synthetic:** each authored vulnerability is committed alongside a hand-written fix; both share a `pair_id`.
- **DiverseVul:** where the dataset provides a fix commit, the pre-fix function is the vulnerable half and the post-fix function is the safe half. Where no fix exists, the sample is unpaired and is excluded from Experiment E.
- **Adversarial:** each transformed sample shares its `pair_id` with the clean ancestor and additionally carries `adversarial_of=<clean_sample_id>` and `transformation=<rename|dead_code|comment|cf_obfuscate|combined>`.

### Contamination prevention strategy

LLM training-data contamination is the single largest threat to external validity for this work. Mitigations:

1. **No identifiable strings.** The prompt strips file paths, repository URLs, author names, and Juliet-specific banner comments before the code reaches the model.
2. **Canary probe.** A small set of well-known CVE function snippets (verbatim) is included in the development split and inspected; if a model reproduces the original CVE identifier from code alone, contamination is acknowledged in the threats section.
3. **Held-out adversarial set.** Tier 4 contains transformations that are guaranteed not to appear verbatim in any public corpus; H4 / H5 results are reported as the *contamination-resistant* headline numbers.
4. **Synthetic samples (Tier 3)** are authored *after* the model release dates that are pinned in the run manifest, where feasible, and this is documented.
5. **Versioned model pins.** Every reported number is attached to a model identifier *with version*, and the full run manifest (model IDs, prompt hash, dataset hash, seed) is committed alongside results.

---

## 6. Consensus Methodology

Three candidates were considered. The recommendation is justified explicitly so that the dissertation can defend the choice.

| Rule | How it works | Strengths | Weaknesses |
|------|--------------|-----------|------------|
| Majority voting | Each judge casts a hard {vuln, safe} vote; ties broken by abstention | Simple; transparent; no calibration assumption | Discards confidence; fragile on small odd-numbered juries |
| Confidence-weighted voting | Each judge contributes $\text{sign}(\text{vote}) \cdot c_i$; sum thresholded | Uses richer signal; smoother decision surface | Requires reasonably-calibrated confidences; sensitive to one over-confident judge |
| Abstention-thresholded consensus | As confidence-weighted, but abstain (no decision) when $\lvert \sum w_i \cdot c_i \rvert < \tau$ | Reports an *uncertainty band*; cleaner deployability story | Needs a held-out split to choose $\tau$; introduces an abstention rate metric |

**Recommended approach for this MSc dissertation: confidence-weighted voting with an abstention threshold $\tau$ tuned on the development split.**

Justification:

1. It strictly generalises the other two: setting all confidences to 1 reduces it to majority voting; setting $\tau = 0$ removes abstention.
2. It directly enables H6 (calibration) — confidence-weighted aggregation produces a continuous score that has a meaningful Brier/ECE.
3. The abstention rate is a defensible *operational* metric (deployability) rather than a research weakness, and gives a natural mechanism for fair comparison: F1 is reported both *with abstentions counted as errors* and *on the non-abstained subset* (with abstention rate disclosed).
4. It is implementable within MSc scope using only the per-judge `{label, confidence}` already produced.

The threshold $\tau$ and any per-judge weights $w_i$ are frozen on the development split and never re-tuned on test.

---

## 7. Prompt Standardization Methodology

Fair comparison across heterogeneous LLM providers requires that every model receives semantically-identical input and is graded on a structurally-identical output.

### Common prompt template

The prompt has a fixed structure with five sections, in this order:

1. **Role.** "You are a security code reviewer specialised in Python."
2. **Task.** Single binary classification ("Decide whether the snippet contains a security vulnerability") plus a request for the most likely CWE if positive.
3. **Static evidence (optional).** A `static_findings` block listing SAST findings as `(rule_id, cwe, line, message)`. Empty for Experiments B and D1; populated for C and D2.
4. **Code.** The Python snippet, fenced, with no surrounding metadata.
5. **Output contract.** A strict instruction to reply with a single JSON object matching the schema below — no prose, no markdown.

The prompt template is committed under version control and referenced by SHA-256 hash in every run manifest. Any prompt change forces a new hash and a re-run.

### JSON output schema

```
{
  "vulnerable":   <bool>,
  "confidence":   <float in [0, 1]>,
  "cwe":          <string|null>,    // e.g. "CWE-89", null if not vulnerable or unknown
  "rationale":    <string>,         // <= 280 characters, used for hallucination scoring
  "evidence_lines": <list[int]>     // 1-based line numbers from the snippet
}
```

The parser tolerates fenced code blocks around the JSON and re-prompts once on parse failure; persistent parse failure is recorded as a *hallucination* (Section 8).

### Provider-specific adaptations

The *content* of the prompt is identical across providers. The following parameters are allowed to differ and are documented per provider in the run manifest:

- System / user message split (Gemini, OpenRouter use system+user; Ollama / HF-text-generation use a single concatenated prompt with the role section as a preamble).
- JSON-mode flag (enabled where supported — Gemini, OpenRouter; emulated via stop-sequences elsewhere).
- Maximum output tokens (set generously, identical across providers).
- Temperature = 0, top_p = 1 everywhere.

No provider receives extra few-shot examples, extra hints, or different instructions. Any deviation is a documented threat to validity.

---

## 8. Metrics

All metrics are computed by a single shared evaluation routine so that every experiment uses identical definitions.

### Classification metrics (computed per-configuration, per-tier, and overall)

Let TP, FP, TN, FN be defined with the *positive class = vulnerable*.

- **TP:** vulnerable sample predicted vulnerable.
- **FP:** safe sample predicted vulnerable.
- **TN:** safe sample predicted safe.
- **FN:** vulnerable sample predicted safe.
- **Precision** $= \dfrac{TP}{TP + FP}$. Reported with 95 % CI (Section 9).
- **Recall** $= \dfrac{TP}{TP + FN}$. Reported with 95 % CI.
- **F1** $= \dfrac{2 \cdot P \cdot R}{P + R}$. Primary headline metric.
- **Accuracy** $= \dfrac{TP + TN}{TP + FP + TN + FN}$. Reported but never used as the primary metric (class imbalance possible after stratification).

When a configuration *abstains* (Experiment D only), two F1 values are reported: (i) abstentions counted as errors, (ii) abstentions excluded, with abstention rate disclosed.

### Advanced metrics

- **Confidence calibration.**
  - *Expected Calibration Error (ECE)* with 10 equal-width bins on $[0,1]$: $\text{ECE} = \sum_b \frac{|B_b|}{N} \cdot \lvert \text{acc}(B_b) - \text{conf}(B_b) \rvert$.
  - *Brier score* $= \frac{1}{N}\sum_i (\hat{p}_i - y_i)^2$.
  - Reliability diagrams produced per configuration.

- **Hallucination rate.** Fraction of model responses that satisfy *any* of: (a) JSON parse failure after one re-prompt; (b) cited `evidence_lines` outside the snippet's line range; (c) cited a CWE identifier not present in the project's CWE registry; (d) `vulnerable=true` but `evidence_lines=[]`. Reported per judge and for the consensus.

- **Disagreement rate.** For Experiment D only. Fraction of test samples where the per-judge votes are not unanimous. Also reported as *pairwise Cohen's $\kappa$* between judges.

- **Latency.** End-to-end wall-clock per sample, measured from prompt dispatch to parsed response. Reported as median, p95, and mean ± std. SAST latency reported separately. Consensus latency = max(judge latencies) when judges run in parallel, sum when sequential — both are reported.

- **Consistency.** Run-to-run agreement across the 3 repetitions per LLM-based experiment, measured as (i) Fleiss' $\kappa$ across the 3 runs and (ii) the standard deviation of F1 across runs. A configuration with high mean F1 but high std is flagged as *unstable*.

### Robustness metrics (Experiment F)

- **Attack Success Rate (ASR)** $= \dfrac{\#\{\text{clean-correct} \to \text{adv-incorrect}\}}{\#\{\text{clean-correct}\}}$, per transformation.
- **$\Delta F1$** $= F1_{\text{adv}} - F1_{\text{clean}}$, with paired bootstrap CI.

### Discrimination metrics (Experiment E)

- **Paired accuracy** = fraction of pairs where the vulnerable variant receives strictly higher predicted vulnerability probability than the fixed variant.
- **Mean ΔConfidence** $= \mathbb{E}[\hat{p}^{\text{bad}} - \hat{p}^{\text{good}}]$, with paired CI.

---

## 9. Statistical Analysis

The methodology applies tests appropriate to the data shape (paired vs unpaired, binary vs continuous) and to MSc scope.

- **Significance tests.**
  - For F1 / accuracy comparisons between two configurations on the *same* test set: **paired bootstrap test** with 10 000 resamples, two-sided, $\alpha = 0.05$. (Used for H1, H2, H4, H5, H7.) Bootstrap is preferred over a parametric test because F1 is non-linear in the underlying counts.
  - For per-sample binary disagreement on the same test set: **McNemar's test** (exact binomial for small discordant counts). Used to corroborate H1, H2, and H3.
  - For Experiment E specifically: McNemar on (correct, incorrect) of vulnerable vs fixed predictions; additionally **paired sign test** on $\hat{p}^{\text{bad}} - \hat{p}^{\text{good}}$.
  - For Experiment F per-transformation degradation: **paired bootstrap** on $\Delta F1$.

- **Confidence intervals.**
  - For Precision, Recall, F1: **bootstrap percentile 95 % CI** with 10 000 resamples.
  - For Accuracy and ASR (binomial proportions): **Wilson 95 % CI**.

- **Effect sizes.**
  - For F1 / accuracy differences: report the **absolute difference** and its CI; in addition report **Cohen's $h$** for proportion-style metrics.
  - For paired continuous differences (latency, ΔConfidence): **Cohen's $d_z$** (paired).
  - For agreement across judges / runs: **Cohen's / Fleiss' $\kappa$** as already specified.

- **Multiple-comparison control.** With seven hypotheses (H1–H7), p-values for the *primary* family (H1, H2, H3) are reported raw; the secondary family (H4–H7) is corrected with the **Benjamini–Hochberg** procedure at $\alpha = 0.05$. This is declared in advance to avoid p-hacking.

---

## 10. Threats to Validity

Threats are organised by the standard four categories so the dissertation chapter has a clear template.

### Internal validity

- **Prompt sensitivity.** Small wording changes can swing LLM outputs. Mitigation: a single frozen prompt template (SHA-256 pinned), plus an ablation in the appendix that reports F1 under three paraphrased prompts on the development split only.
- **Provider non-determinism.** Some providers ignore `seed` or apply server-side stochasticity. Mitigation: 3 repetitions per configuration, consistency reported, and any provider that exhibits std(F1) > 0.02 is explicitly flagged.
- **Parser leakage.** A lenient parser could "rescue" malformed responses. Mitigation: parser behaviour is fixed, and persistent parse failures are counted as hallucinations rather than silently dropped.

### External validity

- **Dataset bias.** Juliet is synthetic and pattern-heavy; DiverseVul is biased toward popular open-source projects. Mitigation: tiered design — headline numbers are reported per tier and overall, never overall only.
- **Language scope.** Python-only. Cross-language generalisation is *not* claimed.
- **CWE coverage.** Tier-1+2 do not uniformly cover all CWEs. Mitigation: Tier 3 is sized to plug gaps; per-CWE recall is reported and discussed.

### Construct validity

- **Benchmark contamination.** Public datasets (especially Juliet) almost certainly appear in LLM pre-training corpora. Mitigation: identifier stripping, canary probe, Tier-4 adversarial set treated as the contamination-resistant headline. Residual risk is acknowledged.
- **Label noise.** DiverseVul labels are commit-derived and known to be imperfect. Mitigation: a manually-audited 5 % sample of DiverseVul test items; if audited disagreement > 10 %, the affected results are reported with an asterisk and a sensitivity analysis.
- **Model bias.** LLM judges may share training data and therefore make correlated errors, weakening consensus. Mitigation: deliberately heterogeneous provider mix (Gemini, OpenRouter, Ollama-local, HuggingFace); pairwise $\kappa$ reported.

### Conclusion / reproducibility validity

- **Run manifest.** Every reported number is attached to a manifest containing: dataset hash, splits hash, prompt hash, model identifiers + versions, decoding parameters, seeds, and software commit SHA.
- **Big-Vul exclusion.** Declared upfront and motivated by scope, not by results. Re-running this methodology with Big-Vul is left as future work.
- **Cost / API drift.** Hosted-model behaviour can change post-publication. Mitigation: archive raw model responses alongside parsed predictions so that scoring is reproducible even if the model is later deprecated.

---

## 11. Dissertation Outputs

The evaluation framework must produce, at minimum, the artefacts below. Each is named so that the implementation roadmap can map one-to-one onto a generator function.

### Tables

- T1 — Per-configuration headline (Precision, Recall, F1, Accuracy ± 95 % CI), overall and per tier.
- T2 — Per-CWE recall, configurations × CWE.
- T3 — Hypothesis test results: H1–H7 with effect size, p-value, raw and BH-corrected.
- T4 — Calibration: ECE and Brier per configuration.
- T5 — Disagreement / agreement: pairwise Cohen's $\kappa$ between judges, plus Fleiss' $\kappa$.
- T6 — Latency: median, p95, mean ± std per configuration.
- T7 — Robustness: F1 on clean vs each adversarial transformation, with $\Delta F1$ and ASR.
- T8 — Paired discrimination (Experiment E): paired accuracy, mean ΔConfidence, McNemar p.
- T9 — Hallucination rate breakdown by failure mode.
- T10 — Run manifest summary (dataset hash, prompt hash, model versions, seeds).

### Figures and charts

- F1 — Bar chart of F1 across A, B (per judge), C, D1, D2, with 95 % CI error bars.
- F2 — Reliability diagram (calibration) for each LLM and the consensus.
- F3 — ROC and Precision–Recall curves for each configuration that produces continuous scores.
- F4 — Confusion matrices (one per configuration), overall and per tier.
- F5 — Per-CWE recall heatmap (configurations × CWE).
- F6 — Robustness bar chart: $\Delta F1$ per transformation per configuration.
- F7 — Latency vs F1 Pareto scatter (one point per configuration; ideal frontier highlighted).
- F8 — Disagreement matrix between LLM judges (heatmap of pairwise $\kappa$).
- F9 — Paired-discrimination scatter: $\hat{p}^{\text{bad}}$ vs $\hat{p}^{\text{good}}$ per pair, diagonal reference line.
- F10 — Abstention curve: F1 vs abstention rate as $\tau$ varies (shown for the consensus only, on the development split, to justify the chosen $\tau$).

### Reports

- R1 — Auto-generated benchmark report (Markdown + HTML) summarising T1–T10 and embedding F1–F10. One report per experimental run, identified by manifest hash.
- R2 — Per-sample audit log (JSONL) containing every prediction, raw response, latency, and parser status — required for reproducibility and for the threats-to-validity audit (label-noise sample).
- R3 — Threats-to-validity appendix populated from automated checks (canary probe results, std(F1) across runs, audited DiverseVul subset disagreement).

---

## Closing note

This document is the authoritative methodology for the project. Subsequent implementation work (dataset loaders, runners, scoring, reporting) must conform to the splits, prompt template, metric definitions, statistical tests, and output artefacts specified above. Any deviation requires a documented amendment to this specification *before* test-split numbers are produced.
