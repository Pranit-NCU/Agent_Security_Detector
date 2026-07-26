"""Validate HuggingFace token and models before a full experiment run.

Usage
-----
    python experiments/validate_hf.py            # test all RECOMMENDED_MODELS
    python experiments/validate_hf.py --quick    # test only the first model

Prints PASS / FAIL for each model and exits with code 0 if all pass,
code 1 if any fail.  Run this once after setting HF_API_KEY in .env to
confirm everything works before kicking off a multi-hour experiment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Load .env if present (simple parser — no dotenv dependency needed)
_ENV_PATH = ROOT / ".env"
if _ENV_PATH.exists():
    for line in _ENV_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

from src.utils.dns_patch import apply as _apply_dns_patch
_apply_dns_patch()

from src.llm.huggingface_judge import RECOMMENDED_MODELS, _HF_ROUTER_URL
from src.llm.sambanova_judge import SAMBANOVA_RECOMMENDED_MODELS, SAMBANOVA_API_URL
from src.llm.mistral_judge import MISTRAL_RECOMMENDED_MODELS, MISTRAL_API_URL
from src.llm.cerebras_judge import CEREBRAS_RECOMMENDED_MODELS, CEREBRAS_API_URL
from src.llm.groq_judge import GROQ_RECOMMENDED_MODELS, GROQ_API_URL


_PROBE_CODE = """\
def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query).fetchone()
"""

_PROBE_PAYLOAD = {
    "messages": [
        {
            "role": "system",
            "content": "Respond ONLY with a valid JSON object.",
        },
        {
            "role": "user",
            "content": (
                "Does this Python code contain a SQL injection vulnerability? "
                "Reply with exactly: "
                '{"is_vulnerable": true, "cwe": "CWE-89", "confidence": 0.9}'
                "\n\nCode:\n" + _PROBE_CODE
            ),
        },
    ],
    "max_tokens": 128,
    "temperature": 0.0,
}

_MAX_LOADING_WAITS = 4
_TIMEOUT_S = 90.0


def _probe_model(model: str, api_key: str, url: str = _HF_ROUTER_URL) -> tuple[bool, str]:
    """Return (success, message) for a minimal inference call to `model`."""
    payload = {"model": model, **_PROBE_PAYLOAD}
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(_MAX_LOADING_WAITS + 1):
        req = urllib.request.Request(url=url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                raw = resp.read().decode("utf-8")

            data = json.loads(raw)
            content = data["choices"][0]["message"]["content"]

            # Verify it returned something that looks like JSON
            inner = json.loads(content) if content.strip().startswith("{") else {}
            if "is_vulnerable" in inner:
                return True, f"OK — model answered is_vulnerable={inner['is_vulnerable']}"
            return True, f"OK — response: {content[:120]}"

        except urllib.error.HTTPError as exc:
            if exc.code == 503:
                try:
                    err_data = json.loads(exc.read().decode("utf-8", errors="replace"))
                    wait_s = min(float(err_data.get("estimated_time", 30)), 60)
                except Exception:
                    wait_s = 30.0
                if attempt < _MAX_LOADING_WAITS:
                    print(f"    ⏳ model loading, waiting {wait_s:.0f}s (attempt {attempt+1}/{_MAX_LOADING_WAITS})…")
                    time.sleep(wait_s)
                    continue
                return False, f"FAIL — model still loading after {_MAX_LOADING_WAITS} waits"
            try:
                raw_body = exc.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw_body)
                    err_detail = (
                        parsed.get("error", {}).get("message")
                        or parsed.get("message")
                        or raw_body[:400]
                    )
                except Exception:
                    err_detail = raw_body[:400] or exc.reason
            except Exception:
                err_detail = exc.reason
            return False, f"FAIL — HTTP {exc.code}: {err_detail}"

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < _MAX_LOADING_WAITS:
                print(f"    ⚠  transient error: {exc} — retrying…")
                time.sleep(5)
                continue
            return False, f"FAIL — network error: {exc}"

        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            return False, f"FAIL — unexpected response shape: {exc}"

    return False, "FAIL — exhausted retries"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate HF token and models")
    parser.add_argument("--quick", action="store_true", help="Test only the first model")
    args = parser.parse_args()

    api_key = (
        os.getenv("HF_API_KEY", "").strip()
        or os.getenv("HUGGINGFACE_API_KEY", "").strip()
    )
    if not api_key:
        print("❌  No HF_API_KEY found in environment or .env file.")
        print("    Set it with:  echo 'HF_API_KEY=hf_...' >> .env")
        return 1

    masked = api_key[:8] + "…" + api_key[-4:]
    print(f"🔑  Using token: {masked}")
    print()

    models = RECOMMENDED_MODELS[:1] if args.quick else RECOMMENDED_MODELS
    results: list[tuple[str, bool, str]] = []

    for model in models:
        short = model.split("/")[-1]
        print(f"  Testing {model} …")
        ok, msg = _probe_model(model, api_key)
        symbol = "✅" if ok else "❌"
        print(f"  {symbol} {short}: {msg}")
        results.append((model, ok, msg))
        print()

    # ── SambaNova models ──────────────────────────────────────────────────────
    sn_key = os.getenv("SAMBANOVA_API_KEY", "").strip()
    if sn_key:
        masked_sn = sn_key[:8] + "…" + sn_key[-4:]
        print(f"\n🔑  SambaNova token: {masked_sn}")
        print()
        sn_models = SAMBANOVA_RECOMMENDED_MODELS[:1] if args.quick else SAMBANOVA_RECOMMENDED_MODELS
        for model in sn_models:
            print(f"  Testing {model} (SambaNova) …")
            ok, msg = _probe_model(model, sn_key, url=SAMBANOVA_API_URL)
            symbol = "✅" if ok else "❌"
            print(f"  {symbol} {model}: {msg}")
            results.append((model, ok, msg))
            print()
    else:
        print("⚠   No SAMBANOVA_API_KEY found — skipping SambaNova models.")
        print("    Get a free key at cloud.sambanova.ai → API Keys")

    # ── Mistral models ────────────────────────────────────────────────────────
    mistral_key = os.getenv("MISTRAL_API_KEY", "").strip()
    if mistral_key:
        masked_m = mistral_key[:8] + "…" + mistral_key[-4:]
        print(f"\n🔑  Mistral token: {masked_m}")
        print()
        m_models = MISTRAL_RECOMMENDED_MODELS[:1] if args.quick else MISTRAL_RECOMMENDED_MODELS
        for model in m_models:
            print(f"  Testing {model} (Mistral) …")
            ok, msg = _probe_model(model, mistral_key, url=MISTRAL_API_URL)
            symbol = "✅" if ok else "❌"
            print(f"  {symbol} {model}: {msg}")
            results.append((model, ok, msg))
            print()
    else:
        print("⚠   No MISTRAL_API_KEY found — skipping Mistral models.")
        print("    Get a free key at console.mistral.ai → API Keys")

    # Cerebras models (primary Llama-family judge -- replaces SambaNova)
    cerebras_key = os.getenv("CEREBRAS_API_KEY", "").strip()
    if cerebras_key:
        masked_cb = cerebras_key[:8] + "..." + cerebras_key[-4:]
        print(f"\n🔑  Cerebras token: {masked_cb}")
        print()
        cb_models = CEREBRAS_RECOMMENDED_MODELS[:1] if args.quick else CEREBRAS_RECOMMENDED_MODELS
        for model in cb_models:
            print(f"  Testing {model} (Cerebras) ...")
            ok, msg = _probe_model(model, cerebras_key, url=CEREBRAS_API_URL)
            symbol = "✅" if ok else "❌"
            print(f"  {symbol} {model}: {msg}")
            if not ok and "403" in msg:
                print("     Cerebras 403 troubleshooting:")
                print("       1. Regenerate your key: cloud.cerebras.ai -> API Keys -> Delete + Create new")
                print("       2. Verify your account email is confirmed")
                print("       3. Check cloud.cerebras.ai/playground -- if that works, the key is valid")
            results.append((model, ok, msg))
            print()
    else:
        print("\n⚠   No CEREBRAS_API_KEY found -- Cerebras (gpt-oss-120b) is the recommended 3rd judge.")
        print("    Get a free key at cloud.cerebras.ai -- no credit card required.")
        print("    Add to .env:  CEREBRAS_API_KEY=<key>")

    # Groq models (supplementary -- good rate limits, multiple models)
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    if groq_key:
        masked_gq = groq_key[:8] + "..." + groq_key[-4:]
        print(f"\n🔑  Groq token: {masked_gq}")
        print()
        gq_models = GROQ_RECOMMENDED_MODELS[:1] if args.quick else GROQ_RECOMMENDED_MODELS
        for model in gq_models:
            print(f"  Testing {model} (Groq) ...")
            ok, msg = _probe_model(model, groq_key, url=GROQ_API_URL)
            symbol = "✅" if ok else "❌"
            if not ok and "403" in msg:
                print(f"  ❌ {model}: HTTP 403 -- model access not enabled.")
                print("     Fix: go to console.groq.com -> Settings -> Model Access and enable this model.")
                print("     Groq is supplementary; experiments will work with HF + SambaNova + Mistral.")
            else:
                print(f"  {symbol} {model}: {msg}")
            results.append((model, ok, msg))
            print()
    else:
        print("\n⚠   No GROQ_API_KEY found -- skipping Groq models.")
        print("    Get a free key at console.groq.com (no credit card required).")

    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    print(f"Results: {passed}/{total} models passed")

    if passed == total:
        print("\n✅  All models reachable. You can run experiments in --no-mock mode:")
        print("    python experiments/run_all.py --no-mock")
    else:
        print("\n⚠   Some models failed. Check your token and model availability.")
        for model, ok, msg in results:
            if not ok:
                print(f"  ✗ {model}: {msg}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
