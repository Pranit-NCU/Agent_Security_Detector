"""Together AI Inference API -- chat completions judge (free-tier model).

OpenAI-compatible endpoint:
    POST https://api.together.xyz/v1/chat/completions

Get a free API key at api.together.ai (no credit card required to start; new
accounts include free credits and Together publishes explicitly *free* endpoint
models suffixed with ``-Free``).

Environment variable
--------------------
TOGETHER_API_KEY

Recommended models for VERDICT
-------------------------------
``TOGETHER_RECOMMENDED_MODELS`` provides ONE free model. It is a Meta-Llama
model, so when Cerebras (also Meta-Llama family) is already active, Together is
treated as a *supplementary / fallback* judge rather than a fourth distinct
family — this preserves the architectural-diversity rationale behind Fleiss
kappa (Google Gemma / Meta Llama / Mistral). Set ``TOGETHER_API_KEY`` only if
you want the extra vote or a Meta-family fallback when Cerebras is exhausted.

  meta-llama/Llama-3.3-70B-Instruct-Turbo-Free  -- free serverless endpoint

If Together deprecates the ``-Free`` suffix, override the model name via the
factory argument; the class itself is model-agnostic.
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

TOGETHER_API_URL = "https://api.together.xyz/v1/chat/completions"

TOGETHER_RECOMMENDED_MODELS: list[str] = [
    "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",  # free serverless endpoint
]

_TOGETHER_JUDGE_CONFIG = dict(
    timeout_seconds=60.0,
    max_retries=2,
    retry_backoff_seconds=5.0,
    temperature=0.0,
)
_MAX_NEW_TOKENS = 512


class TogetherJudge(BaseLLMJudge):
    """Judge using Together AI API (OpenAI-compatible chat completions)."""

    API_KEY_ENV = "TOGETHER_API_KEY"

    @property
    def provider_name(self) -> str:
        return "together"

    def _invoke_model(self, prompt: str) -> str:
        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set TOGETHER_API_KEY in your .env file"
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
                url=TOGETHER_API_URL, data=body, headers=headers, method="POST"
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
                        "[Together] Rate limited — waiting %.0fs (attempt %d/%d)",
                        self.config.retry_backoff_seconds,
                        attempt + 1,
                        self.config.max_retries,
                    )
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Together API returned HTTP {exc.code} for "
                    f"{self.config.model_name}: {exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"Together request failed after {self.config.max_retries} attempts"
                ) from exc

        raise RuntimeError(
            f"Together: exhausted retries for {self.config.model_name}"
        )


def make_together_judge(model_name: str) -> TogetherJudge:
    """Convenience factory with dissertation-appropriate config."""
    return TogetherJudge(JudgeConfig(model_name=model_name, **_TOGETHER_JUDGE_CONFIG))
