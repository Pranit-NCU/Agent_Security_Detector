"""OpenRouter implementation of the semantic security judge.

OpenAI-compatible endpoint:
    POST https://openrouter.ai/api/v1/chat/completions

Get a free API key at openrouter.ai/keys (no credit card required for
:free-suffixed models). Add to .env as:  OPENROUTER_API_KEY=<key>

Environment variable
--------------------
OPENROUTER_API_KEY

Recommended models for VERDICT
-------------------------------
OPENROUTER_RECOMMENDED_MODELS provides two free, no-card-required models
that add Cohere and Poolside architectural diversity alongside the Mistral
(direct API) and Groq judges -- the genuinely payment-free 4-judge panel:

  cohere/north-mini-code:free   -- Cohere North Mini Code, 30B MoE (3B active)
  poolside/laguna-xs-2.1:free   -- Poolside Laguna XS 2.1, 33B MoE (3B active)

OpenRouter's free-tier limits are ACCOUNT-WIDE, shared across both models
combined (not per-model): 20 requests/minute, 50 requests/day for unpaid
accounts. The 1000/day tier requires $10 in lifetime purchases, which would
break the no-credit-card design -- see CLAUDE.md's ADR-001 for the caching
and subsampling mitigation used to fit VERDICT's call volume under this cap.
Ref: https://openrouter.ai/docs/api/reference/limits
"""

from __future__ import annotations

import logging
import os

from ._http_utils import post_json_with_retry
from .base_judge import BaseLLMJudge, JudgeConfig


LOGGER = logging.getLogger(__name__)

OPENROUTER_RECOMMENDED_MODELS: list[str] = [
    "cohere/north-mini-code:free",   # Cohere North Mini Code — free, no card
    "poolside/laguna-xs-2.1:free",   # Poolside Laguna XS 2.1 — free, no card
]

_OPENROUTER_JUDGE_CONFIG = dict(
    timeout_seconds=60.0,
    max_retries=2,
    retry_backoff_seconds=5.0,
    temperature=0.0,
)


class OpenRouterJudge(BaseLLMJudge):
    """Judge adapter for OpenRouter chat completion models."""

    API_KEY_ENV = "OPENROUTER_API_KEY"

    @property
    def provider_name(self) -> str:
        return "openrouter"

    def _invoke_model(self, prompt: str) -> str:
        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(f"Missing API key in environment variable {self.API_KEY_ENV}")

        url = "https://openrouter.ai/api/v1/chat/completions"
        payload = {
            "model": self.config.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.temperature,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://local-hybrid-sast-llm",
            "X-Title": "hybrid-sast-llm-security-benchmark",
        }

        response_text = post_json_with_retry(
            url=url,
            payload=payload,
            headers=headers,
            timeout_seconds=self.config.timeout_seconds,
            max_retries=self.config.max_retries,
            retry_backoff_seconds=self.config.retry_backoff_seconds,
        )
        return self._extract_model_text(response_text)

    def _extract_model_text(self, response_text: str) -> str:
        payload = self._parse_json_response(response_text)
        try:
            choices = payload["choices"]
            first = choices[0]
            return str(first["message"]["content"])
        except (IndexError, KeyError, TypeError) as exc:
            LOGGER.error("Unexpected OpenRouter response structure: %s", response_text[:800])
            raise ValueError("Unexpected OpenRouter response structure") from exc


def make_openrouter_judge(model_name: str) -> OpenRouterJudge:
    """Convenience factory with dissertation-appropriate config."""
    return OpenRouterJudge(JudgeConfig(model_name=model_name, **_OPENROUTER_JUDGE_CONFIG))
