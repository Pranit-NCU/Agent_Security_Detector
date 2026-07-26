# Results: pinned vs. per-run

There are two kinds of result artefact in this repository, and confusing them is the single
easiest way to cite a wrong number.

## `results/final_run_results.json` — pinned and citable

This is the **authoritative summary** of the final Google Colab run, and it is the source of
every figure quoted in the README and the dissertation.

* Judge panel: `Local/Phi-2` (2.7B, 4-bit) · `Local/Qwen2.5-1.5B` (4-bit) · `Mistral/Nemo` (12B, free API)
* Environment: one free Colab T4, greedy decoding
* It is **hand-maintained and version-controlled on purpose**: it does not change when someone
  re-runs an experiment with a different panel.

`scripts/make_report_figures.py` reads only this file, so the README charts can be regenerated
by anyone without a GPU, API keys, or the multi-hour run.

## `datasets/processed/exp_*_results.json` — per-run and overwritten

These are written fresh by **every** execution of `experiments/run_all.py`, including
`--mock` runs. They reflect whatever judge panel happened to be active at the time.

**Do not cite these.** In particular:

* A `--mock` run overwrites them with mock-judge numbers that are *not* model measurements.
* Earlier development runs used a different panel entirely (Qwen2.5-Coder-7B, Cohere
  command-r7b, Llama-3.1-8B) and produced materially different figures — for example a Fleiss κ
  of +0.667 rather than the final −0.078. Any file left over from such a run is stale.

If a number in `datasets/processed/` disagrees with `results/final_run_results.json`, the pinned
file is correct and the per-run file is simply from a different run.

## Reproducing the pinned numbers

The full pipeline is in `notebooks/VERDICT_ON_COLAB_Python.ipynb`. Run it top to bottom on a
free Colab T4. Phase 1 warms the judge cache (~2 hours, models loaded one at a time); Phase 2
scores every experiment from that cache in minutes.
