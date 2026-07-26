# VERDICT — Google Colab Notebook: Cell-by-Cell Guide

Repo: `https://github.com/Pranit-NCU/Agent_Security_Detector.git` (branch `feat/experiment-runners-a-f`)  
Free providers only. Run cells top-to-bottom; 2–9 need no keys, 10+ do.

> Each cell below is copy-paste ready. The same cells are pre-assembled in `VERDICT_Colab.ipynb` — open that directly in Colab.

## Cell 1 — Project Overview

**Purpose.** Orient the reader: what VERDICT is, what this notebook runs, and the free-provider-only policy.

**Type.** Markdown cell (no code). Content:

```markdown
# VERDICT — Google Colab Experimentation Notebook

**VERDICT** (Vulnerability Evaluation by Reasoning, Consensus, Integration and Detection Tiers) empirically tests whether **multi-LLM consensus + SAST** beats single-tool vulnerability detection in AI-generated Python code.

This notebook runs the **full six-experiment pipeline (A–F)** in the cloud, using **free-tier providers only** (no billing, no credit card):

| Judge slot | Provider | Model | Family |
|---|---|---|---|
| 1 | HuggingFace Router | google/gemma-3-27b-it | Google Gemma |
| 2 | Cerebras | gpt-oss-120b | OpenAI GPT-OSS |
| 3 | Mistral AI | open-mistral-nemo | Mistral |
| + | Together AI *(optional)* | Llama-3.3-70B-Turbo-Free | Meta Llama |
| + | Groq / Gemini *(fallback)* | llama-3.1-8b / gemini-1.5-flash | — |

**Dual-environment design:** the GitHub repo is the *single source of truth* (SAST detectors, datasets, statistics, reporting, CLI, Streamlit all stay local). This notebook only runs the *computational experimentation layer* and writes every artifact to **Google Drive** so nothing is lost on disconnect.

**Datasets:** the active benchmark is **SecurityEval** (121 Python samples, 69 CWEs) plus the **paired seed** set (Exp E). Juliet / DiverseVul cells are included as clearly-marked *optional future work* — both are C/C++/Java and incompatible with VERDICT's snippet-level Python evaluation (the same reason VUDENC was excluded).

**Run order:** execute cells top-to-bottom. Cells 2–9 need no API keys; cells 10+ do.
```

**Expected output.** A rendered overview — no code executes.

**Troubleshooting.** If the markdown does not render, ensure you opened this as a notebook (.ipynb), not raw text.

---

## Cell 2 — Clone Repository

**Purpose.** Pull the single-source-of-truth repo at the correct branch and enter it.

**Code (copy-paste ready):**

```python
!git clone --branch feat/experiment-runners-a-f https://github.com/Pranit-NCU/Agent_Security_Detector.git
%cd Agent_Security_Detector
!git log --oneline -1
```

**Expected output.** Cloning ... done, then the working dir becomes /content/Agent_Security_Detector and the latest commit hash prints.

**Troubleshooting.** If 'fatal: Remote branch not found', the branch may have merged to main — replace the branch name with `main`. If the repo is private, run `!git clone https://<TOKEN>@github.com/...` with a PAT.

---

## Cell 3 — Mount Google Drive

**Purpose.** Mount Drive and create the persistent folder structure; point VERDICT's env vars at Drive so every result is written there directly (survives runtime disconnects).

**Code (copy-paste ready):**

```python
from google.colab import drive
drive.mount('/content/drive')
import os
BASE = '/content/drive/MyDrive/VERDICT'
for d in ['datasets','results','reports','charts','logs','raw_outputs','raw_outputs/adversarial']:
    os.makedirs(f'{BASE}/{d}', exist_ok=True)
# Redirect VERDICT outputs to Drive (read by src/config.py). Backwards-compatible:
# unset -> local repo paths; set -> Drive paths.
os.environ['VERDICT_OUTPUT_DIR']      = f'{BASE}/results'
os.environ['VERDICT_FIGURES_DIR']     = f'{BASE}/charts'
os.environ['VERDICT_ADVERSARIAL_DIR'] = f'{BASE}/raw_outputs/adversarial'
print('Drive mounted. VERDICT will write to', BASE)
```

**Expected output.** An auth prompt, then 'Mounted at /content/drive' and the six folders created under MyDrive/VERDICT.

**Troubleshooting.** If mount hangs, Runtime → Restart, then re-run. If you use a Shared Drive, change BASE to '/content/drive/Shareddrives/<name>/VERDICT'.

---

## Cell 4 — Install Dependencies

**Purpose.** Install the tiny dependency set. VERDICT's core is stdlib-only (urllib HTTP, math/json stats); only matplotlib is needed for figures (already on Colab). click/streamlit are optional (CLI/dashboard).

**Code (copy-paste ready):**

```python
!pip install -q -r requirements.txt
print('Dependencies installed.')
```

**Expected output.** A short pip log, then 'Dependencies installed.' (matplotlib is usually already satisfied).

**Troubleshooting.** If streamlit's install is slow or noisy, it is not needed for experiments — you can instead run `!pip install -q matplotlib` only.

---

## Cell 5 — Verify Installation

**Purpose.** Fail fast: confirm Python, matplotlib, the VERDICT package imports, and that config resolves to Drive.

**Code (copy-paste ready):**

```python
import sys, json, matplotlib
print('Python', sys.version.split()[0], '| matplotlib', matplotlib.__version__)
from src import config
from src.llm.judge_factory import build_real_judges  # noqa: F401
from src.evaluation import figures  # noqa: F401
print(json.dumps(config.summary(), indent=2))
print('VERDICT import OK')
```

**Expected output.** Python/matplotlib versions, a JSON dump of resolved paths (PROCESSED_DIR etc. pointing at MyDrive/VERDICT/results), and 'VERDICT import OK'.

**Troubleshooting.** If 'ModuleNotFoundError: src', you are not in the repo dir — re-run Cell 2's `%cd`. If paths show local repo instead of Drive, re-run Cell 3.

---

## Cell 6 — Download / Prepare Juliet  (optional — future work)

**Purpose.** Honest scaffold: Juliet (NIST SARD) is C/C++/Java and NOT snippet-compatible with VERDICT's Python evaluation, so it is disabled by default. The active benchmark stays SecurityEval.

**Code (copy-paste ready):**

```python
import json
DATA = 'datasets/benchmark'
n = len(json.load(open(f'{DATA}/securityeval_dataset.json', encoding='utf-8')))
print(f'ACTIVE benchmark: securityeval_dataset.json -> {n} Python samples')

ENABLE_JULIET = False  # Juliet is C/C++/Java; needs a Python normaliser before it is usable.
if ENABLE_JULIET:
    # Placeholder for future multi-language SAST work. Not used in the dissertation pipeline.
    !wget -q https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip -O /content/juliet.zip || echo 'download skipped/unavailable'
    print('Juliet downloaded — add a src/evaluation loader before using it.')
else:
    print('Juliet skipped (default). SecurityEval remains the primary benchmark.')
```

**Expected output.** 'ACTIVE benchmark: securityeval_dataset.json -> 121 Python samples' and 'Juliet skipped (default)'.

**Troubleshooting.** Only flip ENABLE_JULIET if you are extending VERDICT to C/C++ and have written a normaliser. The SARD URL may change; treat a failed download as non-fatal.

---

## Cell 7 — Download / Prepare DiverseVul  (optional — future work)

**Purpose.** Same honest scaffold: DiverseVul is a large C/C++ commit-level corpus, not Python snippets. Disabled by default; documented for completeness.

**Code (copy-paste ready):**

```python
ENABLE_DIVERSEVUL = False  # C/C++ commit-level data; incompatible with Python snippet evaluation.
if ENABLE_DIVERSEVUL:
    # Example (requires `pip install datasets` + a Python-subset filter you must write):
    # from datasets import load_dataset
    # ds = load_dataset('bstee615/diversevul')
    print('DiverseVul enabled — implement a Python-subset filter before use.')
else:
    print('DiverseVul skipped (default). SecurityEval + seed remain the benchmarks.')
```

**Expected output.** 'DiverseVul skipped (default). SecurityEval + seed remain the benchmarks.'

**Troubleshooting.** DiverseVul yields almost no Python; enabling it without a language filter will not integrate with VERDICT's binary snippet schema.

---

## Cell 8 — Dataset Validation

**Purpose.** Validate the ACTIVE datasets before spending API budget: sample counts, schema, CWE coverage, difficulty split, and paired-set integrity.

**Code (copy-paste ready):**

```python
import json
from collections import Counter
sec = json.load(open('datasets/benchmark/securityeval_dataset.json', encoding='utf-8'))
seed = json.load(open('datasets/benchmark/seed_dataset.json', encoding='utf-8'))
req = {'sample_id','code','cwe','expected_is_vulnerable','difficulty'}
assert all(req <= set(s) for s in sec), 'SecurityEval schema check failed'
cwes = sorted({s['cwe'] for s in sec})
paired = [s for s in seed if s.get('paired_sample_id')]
print('SecurityEval :', len(sec), 'samples,', len(cwes), 'CWEs')
print('Difficulty   :', dict(Counter(s['difficulty'] for s in sec)))
print('Seed set     :', len(seed), 'samples,', len(paired), 'with a paired counterpart')
print('Validation OK')
```

**Expected output.** SecurityEval : 121 samples, 69 CWEs; a difficulty breakdown; Seed set : 25 samples with paired counterparts; 'Validation OK'.

**Troubleshooting.** An AssertionError means the dataset JSON was modified — re-clone (Cell 2). Counts other than 121/25 indicate a stale checkout.

---

## Cell 9 — Run SAST Baseline  (Experiment A)

**Purpose.** Run the SAST-only baseline (no API keys needed). Establishes the motivating result: narrow CWE coverage => low recall.

**Code (copy-paste ready):**

```python
!python -X utf8 experiments/run_all.py --exp A 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_a.log"
import os, json
m = json.load(open(os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_a_results.json')))['overall_metrics']
print('Exp A overall:', {k: round(v,3) for k,v in m.items()})
```

**Expected output.** Exp A runs in a couple of seconds and prints overall metrics — recall ~0.074, F1 ~0.138 on SecurityEval. Results land in Drive/results.

**Troubleshooting.** If FileNotFoundError on the log path, ensure Cell 3 ran (it creates logs/). Exp A finishing instantly is expected — it is pure SAST, no LLM calls.

---

## Cell 10 — Configure API Keys  (Gemini + all providers — secure, once)

**Purpose.** Enter every provider key ONCE via getpass (never hard-coded, never echoed). Keys live in os.environ for the whole session and propagate to the experiment subprocesses. Leave a prompt blank to skip.

**Code (copy-paste ready):**

```python
import os, getpass
def setkey(name, prompt):
    if os.environ.get(name):
        print(name, 'already set'); return
    v = getpass.getpass(prompt).strip()
    if v:
        os.environ[name] = v; print(name, 'set')
    else:
        print(name, 'skipped')
# 3-judge active design = HF + Cerebras + Mistral. Others are optional/fallback.
setkey('GEMINI_API_KEY',   'Gemini API key (optional, emergency fallback): ')
setkey('HF_API_KEY',       'HuggingFace token (Gemma-3-27B) [judge 1]: ')
setkey('CEREBRAS_API_KEY', 'Cerebras API key (gpt-oss-120b) [judge 2]: ')
setkey('MISTRAL_API_KEY',  'Mistral API key (open-mistral-nemo) [judge 3]: ')
setkey('GROQ_API_KEY',     'Groq API key (optional supplementary): ')
setkey('TOGETHER_API_KEY', 'Together AI key (optional Meta-Llama): ')
print('\nKeys captured for this session.')
```

**Expected output.** One masked prompt per provider; each prints 'set' or 'skipped'. Nothing is written to disk.

**Troubleshooting.** Get free keys: HF hf.co/settings/tokens (fine-grained, 'Make calls to Inference Providers'); Cerebras cloud.cerebras.ai; Mistral console.mistral.ai; Together api.together.ai; Groq console.groq.com; Gemini aistudio.google.com. Re-run this cell to add a key you skipped.

---

## Cell 11 — Configure & Verify HuggingFace  (Gemma-3-27B — judge 1)

**Purpose.** Smoke-test the HF Router judge with one tiny call so a bad token fails here, not 100 samples in.

**Code (copy-paste ready):**

```python
import os
if os.environ.get('HF_API_KEY') or os.environ.get('HUGGINGFACE_API_KEY'):
    from src.llm.huggingface_judge import RECOMMENDED_MODELS, make_hf_judge
    j = make_hf_judge(RECOMMENDED_MODELS[0])
    r = j.analyze_code("password = 'admin123'\nquery = 'SELECT * FROM u WHERE p=' + password", [])
    print('HF OK ->', RECOMMENDED_MODELS[0], '| is_vulnerable=', r.is_vulnerable, '| cwe=', r.cwe)
else:
    print('HF key not set — skipping (judge 1 will be absent).')
```

**Expected output.** 'HF OK -> google/gemma-3-27b-it | is_vulnerable= True | cwe= CWE-...'

**Troubleshooting.** HTTP 402 = free monthly quota exhausted (wait/spread across days). HTTP 403 with no gate form = model needs HF PRO — keep gemma-3-27b-it. HTTP 400 = model not on the router.

---

## Cell 12 — Configure & Verify Groq  (Llama-3.1-8B — supplementary)

**Purpose.** Smoke-test Groq. University/corporate IPs are often Cloudflare-blocked; verifying here tells you immediately whether to switch networks.

**Code (copy-paste ready):**

```python
import os
if os.environ.get('GROQ_API_KEY'):
    from src.llm.groq_judge import GROQ_RECOMMENDED_MODELS, make_groq_judge
    j = make_groq_judge(GROQ_RECOMMENDED_MODELS[0])
    r = j.analyze_code("eval(input())", [])
    print('Groq OK ->', GROQ_RECOMMENDED_MODELS[0], '| is_vulnerable=', r.is_vulnerable)
else:
    print('Groq key not set — skipping.')
```

**Expected output.** 'Groq OK -> llama-3.1-8b-instant | is_vulnerable= True'

**Troubleshooting.** HTTP 403 / 'error code: 1010' = Cloudflare IP block (common on Colab too) — usually transient; retry, or rely on HF+Cerebras+Mistral. Model must be enabled at console.groq.com → Model Access.

---

## Cell 13 — Configure & Verify Together AI  (optional — Llama-3.3-70B Free)

**Purpose.** Optional fourth vote / Meta-family fallback. Only runs if you supplied a Together key.

**Code (copy-paste ready):**

```python
import os
if os.environ.get('TOGETHER_API_KEY'):
    from src.llm.together_judge import TOGETHER_RECOMMENDED_MODELS, make_together_judge
    j = make_together_judge(TOGETHER_RECOMMENDED_MODELS[0])
    r = j.analyze_code("import pickle; pickle.loads(data)", [])
    print('Together OK ->', TOGETHER_RECOMMENDED_MODELS[0], '| is_vulnerable=', r.is_vulnerable)
else:
    print('Together key not set — skipping (optional).')
```

**Expected output.** 'Together OK -> meta-llama/Llama-3.3-70B-Instruct-Turbo-Free | is_vulnerable= True'

**Troubleshooting.** If the '-Free' model name is deprecated, pass a current Together model to make_together_judge(...). Together is Meta-family like Cerebras, so it is treated as supplementary, not a 4th distinct family.

---

## Cell 14 — Run Single-LLM Evaluation  (Experiment B)

**Purpose.** Each configured judge scores all 121 samples independently => per-model precision/recall/F1 + latency. This is the single-tool baseline the consensus must beat.

**Code (copy-paste ready):**

```python
import os
!python -X utf8 experiments/run_all.py --no-mock --exp B 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_b.log"
import json
p = os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_b_results.json')
print('Wrote:', p, '| exists =', os.path.exists(p))
```

**Expected output.** Startup lines like '[Exp B] Using HF judges: [...]' / 'Using Cerebras judges' / 'Using Mistral judges', then per-model metrics; JSON written to Drive. Expect minutes, not seconds (real API).

**Troubleshooting.** If it finishes in <2s it silently ran in mock mode — check Cell 10 keys are set in os.environ. Occasional '[warn] ... failed' lines are tolerated (that sample defaults to not-vulnerable).

---

## Cell 15 — Run Hybrid Evaluation  (Experiment C)

**Purpose.** SAST findings are injected into each judge's prompt (hybrid fusion). Compared to Exp A/B with a paired bootstrap significance test.

**Code (copy-paste ready):**

```python
import os
!python -X utf8 experiments/run_all.py --no-mock --exp C 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_c.log"
import json
p = os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_c_results.json')
print('Wrote:', p, '| exists =', os.path.exists(p))
```

**Expected output.** Per-model hybrid F1 plus ΔF1 vs SAST-only and p-values; JSON on Drive.

**Troubleshooting.** Exp C reads exp_a_results.json for the bootstrap — make sure Cell 9 ran first.

---

## Cell 16 — Run Multi-LLM Consensus  (Experiment D)

**Purpose.** ConsensusEngine fuses all judges (majority + weighted vote), then computes Fleiss' κ and pairwise Cohen's κ across the architecturally-diverse panel. The headline result.

**Code (copy-paste ready):**

```python
import os
!python -X utf8 experiments/run_all.py --no-mock --exp D 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_d.log"
import json
p = os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_d_results.json')
print('Wrote:', p, '| exists =', os.path.exists(p))
```

**Expected output.** '[Exp D] Majority-vote: F1=... Fleiss' κ=...'. With 3 diverse judges, low κ + high F1 is the key finding (models agree on verdicts via different reasoning).

**Troubleshooting.** Needs >=2 live judges for a meaningful κ. Reads exp_b_results.json for the consensus-vs-best bootstrap, so run Cell 14 first.

---

## Cell 17 — Run Vulnerable-vs-Fixed Evaluation  (Experiment E)

**Purpose.** Paired discrimination on the seed set: does the strategy flag the vulnerable member AND clear the patched one? Uses the paired seed dataset, not SecurityEval.

**Code (copy-paste ready):**

```python
import os
!python -X utf8 experiments/run_all.py --no-mock --exp E 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_e.log"
import json
p = os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_e_results.json')
print('Wrote:', p, '| exists =', os.path.exists(p))
```

**Expected output.** '[Exp E] Pairs=9' and per-strategy discrimination accuracy (SAST vs consensus vs each model).

**Troubleshooting.** If 'No paired samples found', VERDICT_SEED_FILE is mispointed — leave it unset to use the repo's seed_dataset.json.

---

## Cell 18 — Run Adversarial Evaluation  (Experiment F)

**Purpose.** Applies 5 evasion transforms to every vulnerable sample (605 cases) and measures robustness / detection degradation per technique.

**Code (copy-paste ready):**

```python
import os
!python -X utf8 experiments/run_all.py --no-mock --exp F 2>&1 | tee "$VERDICT_OUTPUT_DIR/../logs/exp_f.log"
import json
p = os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_f_results.json')
print('Wrote:', p, '| exists =', os.path.exists(p))
```

**Expected output.** '[Exp F] Evaluating 121 vulnerable samples × 5 techniques' then an overall robustness score and per-technique table (605 cases). Transformed samples saved under raw_outputs/adversarial.

**Troubleshooting.** Exp F uses a single judge by design (Cerebras→Together→SambaNova→Groq→Gemini→mock). This is the longest cell; if a runtime disconnects, results already written to Drive are safe.

---

## Cell 19 — Generate Metrics  (consolidated CSV + JSON)

**Purpose.** Flatten the six result JSONs into one tidy metrics table for the dissertation appendix.

**Code (copy-paste ready):**

```python
import os, json, csv
R = os.environ['VERDICT_OUTPUT_DIR']; REP = os.path.join(R,'..','reports')
os.makedirs(REP, exist_ok=True)
rows = []
def grab(exp, label, metrics):
    rows.append({'experiment':exp,'strategy':label, **{k:round(metrics.get(k,0),4) for k in ['precision','recall','f1_score','accuracy']}})
a=json.load(open(f'{R}/exp_a_results.json')); grab('A','SAST-only',a['overall_metrics'])
b=json.load(open(f'{R}/exp_b_results.json'))
for m,mm in b['per_model_metrics'].items(): grab('B',f'LLM:{m.split(chr(47))[-1]}',mm)
d=json.load(open(f'{R}/exp_d_results.json')); grab('D','Consensus-majority',d['majority_vote_metrics'])
out=os.path.join(REP,'metrics_summary.csv')
with open(out,'w',newline='') as fh:
    w=csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
json.dump(rows, open(os.path.join(REP,'metrics_summary.json'),'w'), indent=2)
print('Wrote', out, '(', len(rows), 'rows )')
for r in rows: print(r)
```

**Expected output.** A metrics_summary.csv/json under reports/ and the rows printed (SAST, each LLM, consensus).

**Troubleshooting.** KeyError means an experiment JSON is missing — re-run its cell. Adjust the grab() calls if you add more strategies.

---

## Cell 20 — Generate Confusion Matrices

**Purpose.** Render the SAST confusion matrix (and any per-strategy ones) as publication PNGs. Note: SecurityEval is all-positive, so confusion matrices for LLMs have no true-negative column by construction.

**Code (copy-paste ready):**

```python
import os, json
from src.evaluation.figures import confusion_matrix_figure
from src import config
a = json.load(open(os.path.join(os.environ['VERDICT_OUTPUT_DIR'],'exp_a_results.json')))
p = confusion_matrix_figure(a['confusion_matrix'], 'Exp A — SAST-only confusion matrix', config.FIGURES_DIR, 'fig_exp_a_confusion.png')
from IPython.display import Image, display
display(Image(str(p)))
```

**Expected output.** A blue confusion-matrix heatmap for Exp A saved to charts/ and shown inline.

**Troubleshooting.** 'no true negatives' is expected on the all-positive benchmark; use Exp E (paired) for balanced confusion analysis.

---

## Cell 21 — Generate Comparison Tables

**Purpose.** Build a cross-experiment comparison (Markdown + CSV) suitable for pasting into the dissertation.

**Code (copy-paste ready):**

```python
import os, json
R = os.environ['VERDICT_OUTPUT_DIR']; REP = os.path.join(R,'..','reports'); os.makedirs(REP, exist_ok=True)
def f1_of(path, getter):
    try: return round(getter(json.load(open(path))),3)
    except Exception: return None
best = lambda d: max(m['f1_score'] for m in d['per_model_metrics'].values())
table = [
    ('A  SAST-only',        f1_of(f'{R}/exp_a_results.json', lambda d:d['overall_metrics']['f1_score'])),
    ('B  Best single LLM',  f1_of(f'{R}/exp_b_results.json', best)),
    ('C  Best hybrid',      f1_of(f'{R}/exp_c_results.json', best)),
    ('D  Consensus (maj.)', f1_of(f'{R}/exp_d_results.json', lambda d:d['majority_vote_metrics']['f1_score'])),
]
md = '| Strategy | F1 |\n|---|---:|\n' + '\n'.join(f'| {n} | {v} |' for n,v in table)
open(os.path.join(REP,'comparison_table.md'),'w').write(md+'\n')
print(md)
```

**Expected output.** A Markdown F1 comparison table printed and saved to reports/comparison_table.md.

**Troubleshooting.** None in a row means that experiment did not complete — re-run the relevant cell (14–18).

---

## Cell 22 — Generate Publication-quality Charts

**Purpose.** One call renders every figure the source data supports (headline F1, per-model bars, latency, agreement matrix, paired discrimination, adversarial robustness) at 300 DPI into charts/.

**Code (copy-paste ready):**

```python
from src.evaluation.figures import generate_all
paths = generate_all()  # reads Drive/results, writes Drive/charts
from IPython.display import Image, display
for p in paths:
    print(p.name); display(Image(str(p)))
print('Total figures:', len(paths))
```

**Expected output.** Each PNG name printed and displayed inline; files saved under MyDrive/VERDICT/charts. Up to ~10 figures depending on which experiments ran.

**Troubleshooting.** A figure is silently skipped if its source JSON is missing — run the matching experiment. matplotlib uses the headless 'Agg' backend, so no display server is needed.

---

## Cell 23 — Export Results  (single zip bundle)

**Purpose.** Bundle results + charts + reports + logs into one timestamped zip for archival / dissertation submission.

**Code (copy-paste ready):**

```python
import os, shutil, datetime
BASE = os.path.join(os.environ['VERDICT_OUTPUT_DIR'], '..')
stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
staging = f'/content/verdict_export_{stamp}'
os.makedirs(staging, exist_ok=True)
for d in ['results','charts','reports','logs']:
    src = os.path.join(BASE, d)
    if os.path.isdir(src): shutil.copytree(src, os.path.join(staging, d), dirs_exist_ok=True)
zip_path = shutil.make_archive(f'{BASE}/reports/verdict_export_{stamp}', 'zip', staging)
print('Export bundle:', zip_path)
```

**Expected output.** 'Export bundle: /content/drive/MyDrive/VERDICT/reports/verdict_export_<stamp>.zip'.

**Troubleshooting.** If the zip is large, Drive may take a moment to sync — wait for the Drive icon to stop spinning before closing the tab.

---

## Cell 24 — Save Everything to Google Drive  (verify & snapshot)

**Purpose.** Because every experiment already writes straight to Drive, this cell just snapshots the datasets for provenance and confirms nothing is missing.

**Code (copy-paste ready):**

```python
import os, shutil, json
BASE = os.path.join(os.environ['VERDICT_OUTPUT_DIR'], '..')
shutil.copytree('datasets/benchmark', os.path.join(BASE,'datasets','benchmark'), dirs_exist_ok=True)
print('Drive contents under', os.path.realpath(BASE), ':')
for d in ['datasets','results','reports','charts','logs','raw_outputs']:
    p = os.path.join(BASE, d)
    n = sum(len(files) for _,_,files in os.walk(p)) if os.path.isdir(p) else 0
    print(f'  {d:12s} {n} file(s)')
print('\nDone — all VERDICT artifacts are on Google Drive and survive runtime disconnects.')
```

**Expected output.** A per-folder file count under MyDrive/VERDICT and a completion message. datasets/ now holds a benchmark snapshot for reproducibility.

**Troubleshooting.** If results/ shows 0 files, the experiment cells ran before Cell 3 set VERDICT_OUTPUT_DIR — re-run Cell 3 then the experiments.

---
