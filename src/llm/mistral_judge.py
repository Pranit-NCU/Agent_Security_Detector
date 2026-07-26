"""Mistral AI Inference API -- chat completions judge (free Experiment plan).

OpenAI-compatible endpoint:
    POST https://api.mistral.ai/v1/chat/completions

Get a free API key at console.mistral.ai (no credit card required for Experiment plan).
Add to .env as:  MISTRAL_API_KEY=<key>

Environment variable
--------------------
MISTRAL_API_KEY

Recommended models for VERDICT
-------------------------------
MISTRAL_RECOMMENDED_MODELS provides one model that adds Mistral architectural
diversity alongside the Google Gemma (HF) and Meta Llama (SambaNova) judges:

  open-mistral-nemo  -- Mistral Nemo 12B; free on Experiment plan; ~1 RPS / 500K TPM

This replaces google/gemma-3-12b-it which was same-family as gemma-3-27b-it
and would have inflated Fleiss kappa by reducing architectural diversity.
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

MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

MISTRAL_RECOMMENDED_MODELS: list[str] = [
    "open-mistral-nemo",  # Mistral Nemo 12B — free on Experiment plan
]

_MISTRAL_JUDGE_CONFIG = dict(
    timeout_seconds=60.0,
    max_retries=2,
    retry_backoff_seconds=5.0,
    temperature=0.0,
)
_MAX_NEW_TOKENS = 512


class MistralJudge(BaseLLMJudge):
    """Judge using Mistral AI API (OpenAI-compatible chat completions)."""

    API_KEY_ENV = "MISTRAL_API_KEY"

    @property
    def provider_name(self) -> str:
        return "mistral"

    def _invoke_model(self, prompt: str) -> str:
        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set MISTRAL_API_KEY in your .env file"
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
                url=MISTRAL_API_URL, data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.config.timeout_seconds
                ) as resp:
                    raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                return data["choices"][0]["message"]["content"]

            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < self.config.max_retries:
                    LOGGER.warning(
                        "[Mistral] Rate limited — waiting %.0fs (attempt %d/%d)",
                        self.config.retry_backoff_seconds,
                        attempt + 1,
                        self.config.max_retries,
                    )
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Mistral API returned HTTP {exc.code} for "
                    f"{self.config.model_name}: {exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Mistral request failed after {self.config.max_retries} attempts"
                ) from exc

        raise RuntimeError(
            f"Mistral: exhausted retries for {self.config.model_name}"
        )


def make_mistral_judge(model_name: str) -> MistralJudge:
    """Convenience factory with dissertation-appropriate config."""
    return MistralJudge(JudgeConfig(model_name=model_name, **_MISTRAL_JUDGE_CONFIG))
