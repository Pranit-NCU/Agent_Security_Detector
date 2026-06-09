"""Ollama-backed implementation of the semantic security judge."""

from __future__ import annotations

import logging
import os

from ._http_utils import post_json_with_retry
from .base_judge import BaseLLMJudge


LOGGER = logging.getLogger(__name__)


class OllamaJudge(BaseLLMJudge):
    """Judge adapter for local Ollama model endpoints."""

    BASE_URL_ENV = "OLLAMA_BASE_URL"

    @property
    def provider_name(self) -> str:
        return "ollama"

    def _invoke_model(self, prompt: str) -> str:
        base_url = os.getenv(self.BASE_URL_ENV, "http://localhost:11434").rstrip("/")
        url = f"{base_url}/api/generate"

        payload = {
            "model": self.config.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }

        response_text = post_json_with_retry(
            url=url,
            payload=payload,
            headers={},
            timeout_seconds=self.config.timeout_seconds,
            max_retries=self.config.max_retries,
            retry_backoff_seconds=self.config.retry_backoff_seconds,
        )
        return self._extract_model_text(response_text)

    def _extract_model_text(self, response_text: str) -> str:
        payload = self._parse_json_response(response_text)
        try:
            return str(payload["response"])
        except KeyError as exc:
            LOGGER.error("Unexpected Ollama response structure: %s", response_text[:800])
            raise ValueError("Unexpected Ollama response structure") from exc
