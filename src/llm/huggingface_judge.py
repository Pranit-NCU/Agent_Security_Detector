"""Hugging Face inference API implementation of the semantic security judge."""

from __future__ import annotations

import logging
import os

from ._http_utils import post_json_with_retry
from .base_judge import BaseLLMJudge


LOGGER = logging.getLogger(__name__)


class HuggingFaceJudge(BaseLLMJudge):
    """Judge adapter for Hugging Face Inference API models."""

    API_KEY_ENV = "HUGGINGFACE_API_KEY"

    @property
    def provider_name(self) -> str:
        return "huggingface"

    def _invoke_model(self, prompt: str) -> str:
        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(f"Missing API key in environment variable {self.API_KEY_ENV}")

        url = f"https://api-inference.huggingface.co/models/{self.config.model_name}"
        payload = {
            "inputs": prompt,
            "parameters": {
                "temperature": self.config.temperature,
                "return_full_text": False,
            },
        }
        headers = {"Authorization": f"Bearer {api_key}"}

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
        if isinstance(payload, list):
            try:
                first = payload[0]
                if isinstance(first, dict) and "generated_text" in first:
                    return str(first["generated_text"])
            except (IndexError, KeyError, TypeError) as exc:
                LOGGER.error("Unexpected Hugging Face response list: %s", response_text[:800])
                raise ValueError("Unexpected Hugging Face response structure") from exc

        if isinstance(payload, dict) and "generated_text" in payload:
            return str(payload["generated_text"])

        LOGGER.error("Unexpected Hugging Face response structure: %s", response_text[:800])
        raise ValueError("Unexpected Hugging Face response structure")
