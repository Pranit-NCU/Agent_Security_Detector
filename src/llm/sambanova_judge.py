"""SambaNova Cloud Inference API -- chat completions judge (free tier).

OpenAI-compatible endpoint:
    POST https://api.sambanova.ai/v1/chat/completions

Get a free API key at cloud.sambanova.ai (no credit card required).
Add to .env as:  SAMBANOVA_API_KEY=<key>

Environment variable
--------------------
SAMBANOVA_API_KEY

Recommended models for VERDICT
-------------------------------
SAMBANOVA_RECOMMENDED_MODELS provides one model that adds architectural
diversity (Meta Llama) alongside the Google Gemma (HF) and Mistral judges:

  Meta-Llama-3.3-70B-Instruct  -- Meta Llama 3.3 70B; free on SambaNova (200K tokens/day)

Note: Groq returns HTTP 403 on free-tier accounts for all models — SambaNova
is the recommended replacement for the Llama-architecture third judge.

Rate limiting
-------------
SambaNova free tier: 20 RPM (1 request every 3 seconds).
_MIN_REQUEST_INTERVAL_S enforces a proactive minimum interval between calls.
On HTTP 429, exponential backoff applies: 30s → 60s → 120s → 240s.
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

SAMBANOVA_API_URL = "https://api.sambanova.ai/v1/chat/completions"

SAMBANOVA_RECOMMENDED_MODELS: list[str] = [
    "Meta-Llama-3.3-70B-Instruct",  # Meta Llama 3.3 70B — free on SambaNova
]

_MIN_REQUEST_INTERVAL_S: float = 3.5  # SambaNova free tier: 20 RPM = 1 req/3s
_last_call_time: float = 0.0           # monotonic timestamp of last API call
_circuit_open: bool = False            # True after all retries exhausted on 429 (quota exhausted)

_SAMBANOVA_JUDGE_CONFIG = dict(
    timeout_seconds=60.0,
    max_retries=4,           # enough for exponential backoff to outlast burst limits
    retry_backoff_seconds=30.0,  # base for exponential: 30s → 60s → 120s → 240s
    temperature=0.0,
)
_MAX_NEW_TOKENS = 512


class SambaNovaJudge(BaseLLMJudge):
    """Judge using SambaNova Cloud Inference API (OpenAI-compatible chat completions)."""

    API_KEY_ENV = "SAMBANOVA_API_KEY"

    @property
    def provider_name(self) -> str:
        return "sambanova"

    def _invoke_model(self, prompt: str) -> str:
        global _last_call_time, _circuit_open

        if _circuit_open:
            raise RuntimeError(
                f"SambaNova circuit breaker open — daily quota likely exhausted. "
                f"Skipping {self.config.model_name} for the rest of this run."
            )

        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set SAMBANOVA_API_KEY in your .env file"
            )

        # Proactive rate-limit: enforce minimum interval between SambaNova calls
        elapsed = time.monotonic() - _last_call_time
        if elapsed < _MIN_REQUEST_INTERVAL_S:
            time.sleep(_MIN_REQUEST_INTERVAL_S - elapsed)

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
                url=SAMBANOVA_API_URL, data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.config.timeout_seconds
                ) as resp:
                    raw = resp.read().decode("utf-8")
                _last_call_time = time.monotonic()
                _circuit_open = False  # successful call — quota is fine
                data = json.loads(raw)
                return data["choices"][0]["message"]["content"]

            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < self.config.max_retries:
                    wait_s = self.config.retry_backoff_seconds * (2 ** attempt)
                    LOGGER.warning(
                        "[SambaNova] Rate limited — waiting %.0fs (attempt %d/%d)",
                        wait_s,
                        attempt + 1,
                        self.config.max_retries,
                    )
                    _last_call_time = time.monotonic()
                    time.sleep(wait_s)
                    continue
                if exc.code == 429:
                    _circuit_open = True
                    LOGGER.error(
                        "[SambaNova] All retries exhausted with HTTP 429 — opening circuit breaker. "
                        "Daily quota is likely exhausted; this judge will be skipped for the rest of the run."
                    )
                raise RuntimeError(
                    f"SambaNova API returned HTTP {exc.code} for "
                    f"{self.config.model_name}: {exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"SambaNova request failed after {self.config.max_retries} attempts"
                ) from exc

        raise RuntimeError(
            f"SambaNova: exhausted retries for {self.config.model_name}"
        )


def make_sambanova_judge(model_name: str) -> SambaNovaJudge:
    """Convenience factory with dissertation-appropriate config."""
    return SambaNovaJudge(JudgeConfig(model_name=model_name, **_SAMBANOVA_JUDGE_CONFIG))
