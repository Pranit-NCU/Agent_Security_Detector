"""Cerebras Inference API -- chat completions judge (free tier).

OpenAI-compatible endpoint:
    POST https://api.cerebras.ai/v1/chat/completions

Get a free API key at cloud.cerebras.ai (no credit card required).
Add to .env as:  CEREBRAS_API_KEY=<key>

Why Cerebras for VERDICT
------------------------
Cerebras is the third judge alongside HF (Gemma) and Mistral (Nemo).
GPT OSS 120B is Cerebras's current production model (llama-3.3-70b was
deprecated 2026-02-16).  Using three architecturally distinct families
maximises Fleiss' kappa diversity:
  - HF Router:       Google Gemma 3 27B       (Google family)
  - Mistral API:     Mistral Nemo 12B         (Mistral family)
  - Cerebras:        OpenAI GPT OSS 120B      (OpenAI family)  <-- this judge

Rate limits (free tier, as of July 2026)
-----------------------------------------
  ~3000 tokens/s, free on Cerebras public endpoints.
Single 429 retry with 65s wait handles any burst-window exhaustion.

Environment variable
--------------------
CEREBRAS_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

from .base_judge import BaseLLMJudge, JudgeConfig


LOGGER = logging.getLogger(__name__)

CEREBRAS_API_URL = "https://api.cerebras.ai/v1/chat/completions"

# gpt-oss-120b is the current Cerebras production model (free tier).
# llama-3.3-70b was deprecated 2026-02-16; llama3.1-8b was deprecated 2026-05-27.
CEREBRAS_RECOMMENDED_MODELS: list[str] = [
    "gpt-oss-120b",    # OpenAI GPT OSS 120B -- Cerebras production model, free
]

_CEREBRAS_JUDGE_CONFIG = dict(
    timeout_seconds=60.0,
    max_retries=3,
    retry_backoff_seconds=65.0,   # Cerebras TPM window is 60s; 65s clears it
    temperature=0.0,
)
_MAX_NEW_TOKENS = 512

# Circuit breaker: once daily quota is confirmed exhausted, skip all further calls
_circuit_open: bool = False


class CerebasJudge(BaseLLMJudge):
    """Judge using Cerebras Inference API (OpenAI-compatible chat completions).

    1M tokens/day free -- roughly 5x the SambaNova quota for 121-sample runs.
    """

    API_KEY_ENV = "CEREBRAS_API_KEY"

    @property
    def provider_name(self) -> str:
        return "cerebras"

    def _invoke_model(self, prompt: str) -> str:
        global _circuit_open

        if _circuit_open:
            raise RuntimeError(
                "Cerebras circuit breaker open -- rate limit likely exhausted. "
                f"Skipping {self.config.model_name} for the rest of this run."
            )

        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set CEREBRAS_API_KEY in your .env file. "
                "Get a free key at cloud.cerebras.ai (no credit card required)."
            )

        payload: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a Python security analysis expert. "
                        "Respond ONLY with a single valid JSON object -- no prose, "
                        "no markdown fences, no extra text."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": _MAX_NEW_TOKENS,
            "temperature": self.config.temperature,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        body = json.dumps(payload).encode("utf-8")

        for attempt in range(self.config.max_retries + 1):
            req = urllib.request.Request(
                url=CEREBRAS_API_URL, data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.config.timeout_seconds
                ) as resp:
                    raw = resp.read().decode("utf-8")
                _circuit_open = False  # successful call -- quota is fine
                data = json.loads(raw)
                return data["choices"][0]["message"]["content"]

            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < self.config.max_retries:
                    wait_s = self.config.retry_backoff_seconds
                    LOGGER.warning(
                        "[Cerebras] Rate limited -- waiting %.0fs (attempt %d/%d)",
                        wait_s,
                        attempt + 1,
                        self.config.max_retries,
                    )
                    print(
                        f"[Cerebras] Rate limited -- waiting {wait_s:.0f}s "
                        f"(attempt {attempt + 1}/{self.config.max_retries})"
                    )
                    time.sleep(wait_s)
                    continue
                if exc.code == 429:
                    _circuit_open = True
                    LOGGER.error(
                        "[Cerebras] All retries exhausted with HTTP 429 -- "
                        "opening circuit breaker. Daily quota likely exhausted."
                    )
                    print(
                        "[Cerebras] All retries exhausted with HTTP 429 -- "
                        "opening circuit breaker. Daily quota (1M tokens) likely exhausted; "
                        "this judge will be skipped for the rest of the run."
                    )
                raise RuntimeError(
                    f"Cerebras API returned HTTP {exc.code} for "
                    f"{self.config.model_name}: {exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.config.max_retries:
                    LOGGER.warning(
                        "[Cerebras] Transient error on attempt %d: %s", attempt + 1, exc
                    )
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Cerebras request failed after {self.config.max_retries} attempts"
                ) from exc

        raise RuntimeError(
            f"Cerebras: exhausted retries for {self.config.model_name}"
        )


def make_cerebras_judge(model_name: str) -> CerebasJudge:
    """Convenience factory with dissertation-appropriate config."""
    return CerebasJudge(JudgeConfig(model_name=model_name, **_CEREBRAS_JUDGE_CONFIG))
