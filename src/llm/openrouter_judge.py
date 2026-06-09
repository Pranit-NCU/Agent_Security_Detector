"""OpenRouter implementation of the semantic security judge."""

from __future__ import annotations

import logging
import os

from ._http_utils import post_json_with_retry
from .base_judge import BaseLLMJudge


LOGGER = logging.getLogger(__name__)


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
