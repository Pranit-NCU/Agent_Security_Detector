"""Groq Inference API -- chat completions judge (free tier).

OpenAI-compatible endpoint:
    POST https://api.groq.com/openai/v1/chat/completions

Get a free API key at console.groq.com (no credit card required).
Add to .env as:  GROQ_API_KEY=gsk_...

Environment variable
--------------------
GROQ_API_KEY

Role in VERDICT
---------------
Groq is the 4th judge in the primary payment-free panel (ADR-001 Option D):
  OpenRouter (Cohere + Poolside) + Mistral (Nemo) + Groq (Llama 3.1 8B)
Added specifically for its much larger free-tier daily quota (14,400
req/day) relative to OpenRouter's 50 req/day account-wide cap, so Groq's
own per-judge results finish quickly even while OpenRouter's two judges
are still working through their daily allowance across multiple days.

Recommended models for VERDICT
-------------------------------
  llama-3.1-8b-instant  -- Meta Llama 3.1 8B; listed as production model on Groq.
                           If you get HTTP 403, go to console.groq.com ->
                           Settings -> Model Access and enable the model.

DO NOT use llama-3.3-70b-versatile without credits -- higher tier required.

Rate limits (free tier, July 2026)
------------------------------------
  30 RPM / 6K TPM / 14.4K RPD
TPM is the binding constraint: ~6-8 calls per minute given VERDICT's prompt sizes.
On HTTP 429 we wait 65s to clear the 1-minute TPM window before retrying.
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

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Primary model for VERDICT: Llama 3.1 8B (free, fast, Meta family)
# Kept alongside mixtral as an alternative option.
GROQ_RECOMMENDED_MODELS: list[str] = [
    "llama-3.1-8b-instant",   # Meta Llama 3.1 8B -- requires Model Access enabled in Groq console
]

# Mixtral is an alternative if you want Mistral-MoE architecture from Groq
GROQ_MIXTRAL_MODEL = "mixtral-8x7b-32768"

_GROQ_JUDGE_CONFIG = dict(
    timeout_seconds=30.0,    # Groq is very fast (315 t/s) -- 30s is generous
    max_retries=3,
    retry_backoff_seconds=65.0,   # 65s clears Groq's 1-minute TPM window
    temperature=0.0,
)
_MAX_NEW_TOKENS = 512

# Circuit breaker: skip after confirmed daily quota exhaustion (14.4K RPD limit)
_circuit_open: bool = False


class GroqJudge(BaseLLMJudge):
    """Judge using Groq Inference API (OpenAI-compatible chat completions).

    Free tier: 30 RPM / 6K TPM / 14.4K RPD.
    TPM is the binding constraint for VERDICT -- rate limit retries handle it.
    """

    API_KEY_ENV = "GROQ_API_KEY"

    @property
    def provider_name(self) -> str:
        return "groq"

    def _invoke_model(self, prompt: str) -> str:
        global _circuit_open

        if _circuit_open:
            raise RuntimeError(
                "Groq circuit breaker open -- daily quota likely exhausted. "
                f"Skipping {self.config.model_name} for the rest of this run."
            )

        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set GROQ_API_KEY in your .env file"
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
                url=GROQ_API_URL, data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.config.timeout_seconds
                ) as resp:
                    raw = resp.read().decode("utf-8")
                _circuit_open = False
                data = json.loads(raw)
                return data["choices"][0]["message"]["content"]

            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < self.config.max_retries:
                    wait_s = self.config.retry_backoff_seconds
                    LOGGER.warning(
                        "[Groq] Rate limited (TPM/RPM) -- waiting %.0fs (attempt %d/%d)",
                        wait_s, attempt + 1, self.config.max_retries,
                    )
                    print(
                        f"[Groq] Rate limited -- waiting {wait_s:.0f}s "
                        f"(attempt {attempt + 1}/{self.config.max_retries})"
                    )
                    time.sleep(wait_s)
                    continue
                if exc.code == 429:
                    _circuit_open = True
                    print(
                        "[Groq] All retries exhausted with HTTP 429 -- "
                        "opening circuit breaker. Daily quota (14.4K RPD) likely exhausted."
                    )
                if exc.code == 403:
                    raise RuntimeError(
                        f"Groq HTTP 403 for {self.config.model_name}. "
                        "This usually means the model requires credits or explicit "
                        "model permissions. Check console.groq.com -> Settings -> "
                        "Model Access to enable the model on your account. "
                        "If using free tier, verify the model is listed at "
                        "console.groq.com/docs/models under 'Production Models'."
                    ) from exc
                raise RuntimeError(
                    f"Groq API returned HTTP {exc.code} for "
                    f"{self.config.model_name}: {exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Groq request failed after {self.config.max_retries} attempts"
                ) from exc

        raise RuntimeError(
            f"Groq: exhausted retries for {self.config.model_name}"
        )


def make_groq_judge(model_name: str) -> GroqJudge:
    """Convenience factory with dissertation-appropriate config."""
    return GroqJudge(JudgeConfig(model_name=model_name, **_GROQ_JUDGE_CONFIG))
