"""Gemini-backed implementation of the semantic security judge."""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
import random
import time
from typing import Any, Dict
from urllib import error, request

from .base_judge import BaseLLMJudge, JudgeConfig


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class GeminiUsageMetadata:
    """Token usage and request-level metadata from a Gemini invocation."""

    prompt_tokens: int
    candidate_tokens: int
    total_tokens: int
    finish_reason: str
    api_latency_ms: float
    estimated_cost_usd: float


class GeminiJudge(BaseLLMJudge):
    """Judge adapter for Google Gemini models."""

    API_KEY_ENV = "GEMINI_API_KEY"
    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, config: JudgeConfig) -> None:
        super().__init__(config)
        self._last_usage_metadata: GeminiUsageMetadata | None = None

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def last_usage_metadata(self) -> GeminiUsageMetadata | None:
        """Return token usage and latency metadata from the last completed call."""
        return self._last_usage_metadata

    def parse_response(self, raw_response: str) -> Dict[str, Any]:
        """Parse response and apply confidence/exploitability normalization safeguards."""
        parsed = super().parse_response(raw_response)
        parsed["confidence"] = self._normalize_confidence(
            confidence=float(parsed["confidence"]),
            false_positive_probability=float(parsed["false_positive_probability"]),
            is_vulnerable=bool(parsed["is_vulnerable"]),
        )
        parsed["exploitability"] = self._normalize_exploitability(
            exploitability=str(parsed["exploitability"]),
            reasoning=str(parsed["reasoning"]),
            is_vulnerable=bool(parsed["is_vulnerable"]),
        )
        return parsed

    def _invoke_model(self, prompt: str) -> str:
        api_key = os.getenv(self.API_KEY_ENV, "").strip()
        if not api_key:
            raise RuntimeError(f"Missing API key in environment variable {self.API_KEY_ENV}")

        url = f"{self.BASE_URL}/{self.config.model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.config.temperature,
                "responseMimeType": "application/json",
            },
        }
        headers = {"Content-Type": "application/json"}

        raw_provider_response, api_latency_ms = self._post_with_retry(
            url=url,
            payload=payload,
            headers=headers,
            timeout_seconds=self.config.timeout_seconds,
            max_retries=self.config.max_retries,
            base_backoff_seconds=self.config.retry_backoff_seconds,
        )
        model_text = self._extract_model_text(raw_provider_response)
        strict_json_text = self._enforce_strict_json(model_text)
        self._last_usage_metadata = self._extract_usage_metadata(
            raw_provider_response=raw_provider_response,
            api_latency_ms=api_latency_ms,
        )
        return strict_json_text

    def benchmark_fields(self) -> Dict[str, float | int | str]:
        """Return benchmark-ready metadata for token and latency analysis."""
        metadata = self.last_usage_metadata
        if metadata is None:
            return {
                "provider": self.provider_name,
                "model_name": self.config.model_name,
                "prompt_tokens": 0,
                "candidate_tokens": 0,
                "total_tokens": 0,
                "api_latency_ms": 0.0,
                "estimated_cost_usd": 0.0,
                "finish_reason": "UNKNOWN",
            }
        return {
            "provider": self.provider_name,
            "model_name": self.config.model_name,
            "prompt_tokens": metadata.prompt_tokens,
            "candidate_tokens": metadata.candidate_tokens,
            "total_tokens": metadata.total_tokens,
            "api_latency_ms": metadata.api_latency_ms,
            "estimated_cost_usd": metadata.estimated_cost_usd,
            "finish_reason": metadata.finish_reason,
        }

    def _post_with_retry(
        self,
        *,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        timeout_seconds: float,
        max_retries: int,
        base_backoff_seconds: float,
    ) -> tuple[str, float]:
        payload_bytes = json.dumps(payload).encode("utf-8")
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            req = request.Request(url=url, data=payload_bytes, headers=headers, method="POST")
            start = time.perf_counter()
            try:
                with request.urlopen(req, timeout=timeout_seconds) as response:
                    latency_ms = (time.perf_counter() - start) * 1000.0
                    body = response.read().decode("utf-8")
                    return body, latency_ms
            except error.HTTPError as exc:
                last_error = exc
                is_retriable = exc.code in {408, 409, 429, 500, 502, 503, 504}
                if attempt >= max_retries or not is_retriable:
                    break
                self._sleep_backoff(base_backoff_seconds, attempt)
            except (error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt >= max_retries:
                    break
                self._sleep_backoff(base_backoff_seconds, attempt)

        if last_error is None:
            raise RuntimeError("Gemini API request failed without explicit error")
        raise RuntimeError("Gemini API request failed after retries") from last_error

    def _sleep_backoff(self, base_backoff_seconds: float, attempt: int) -> None:
        if base_backoff_seconds <= 0.0:
            return
        backoff = base_backoff_seconds * (2**attempt)
        jitter = random.uniform(0.0, min(0.25, base_backoff_seconds))
        time.sleep(backoff + jitter)

    def _enforce_strict_json(self, model_text: str) -> str:
        stripped = model_text.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            json.loads(stripped)
            return stripped

        if stripped.startswith("```") and stripped.endswith("```"):
            fenced_body = stripped.strip("`").strip()
            if fenced_body.lower().startswith("json"):
                fenced_body = fenced_body[4:].strip()
            if fenced_body.startswith("{") and fenced_body.endswith("}"):
                json.loads(fenced_body)
                return fenced_body

        raise ValueError("Gemini response violated strict JSON-only requirement")

    def _extract_model_text(self, response_text: str) -> str:
        payload = self._parse_json_response(response_text)
        try:
            candidates = payload["candidates"]
            first = candidates[0]
            parts = first["content"]["parts"]
            text_parts = [str(part.get("text", "")) for part in parts if isinstance(part, dict)]
            joined = "\n".join(part for part in text_parts if part.strip())
            if not joined.strip():
                raise ValueError("Gemini candidate did not return textual content")
            return joined
        except (IndexError, KeyError, TypeError) as exc:
            LOGGER.error("Unexpected Gemini response structure: %s", response_text[:800])
            raise ValueError("Unexpected Gemini response structure") from exc

    def _extract_usage_metadata(
        self,
        *,
        raw_provider_response: str,
        api_latency_ms: float,
    ) -> GeminiUsageMetadata:
        payload = self._parse_json_response(raw_provider_response)

        usage = payload.get("usageMetadata", {}) if isinstance(payload, dict) else {}
        prompt_tokens = int(usage.get("promptTokenCount", 0))
        candidate_tokens = int(usage.get("candidatesTokenCount", 0))
        total_tokens = int(usage.get("totalTokenCount", prompt_tokens + candidate_tokens))

        finish_reason = "UNKNOWN"
        if isinstance(payload, dict):
            candidates = payload.get("candidates", [])
            if isinstance(candidates, list) and candidates:
                first = candidates[0]
                if isinstance(first, dict):
                    finish_reason = str(first.get("finishReason", "UNKNOWN"))

        estimated_cost_usd = self._estimate_cost_usd(
            prompt_tokens=prompt_tokens,
            candidate_tokens=candidate_tokens,
        )

        return GeminiUsageMetadata(
            prompt_tokens=prompt_tokens,
            candidate_tokens=candidate_tokens,
            total_tokens=total_tokens,
            finish_reason=finish_reason,
            api_latency_ms=api_latency_ms,
            estimated_cost_usd=estimated_cost_usd,
        )

    def _estimate_cost_usd(self, *, prompt_tokens: int, candidate_tokens: int) -> float:
        input_per_million = float(os.getenv("GEMINI_INPUT_USD_PER_MILLION_TOKENS", "0"))
        output_per_million = float(os.getenv("GEMINI_OUTPUT_USD_PER_MILLION_TOKENS", "0"))
        prompt_cost = (prompt_tokens / 1_000_000.0) * input_per_million
        candidate_cost = (candidate_tokens / 1_000_000.0) * output_per_million
        return round(prompt_cost + candidate_cost, 8)

    def _normalize_confidence(
        self,
        *,
        confidence: float,
        false_positive_probability: float,
        is_vulnerable: bool,
    ) -> float:
        confidence_clamped = min(max(confidence, 0.0), 1.0)
        fpp_clamped = min(max(false_positive_probability, 0.0), 1.0)

        decision_confidence = confidence_clamped if is_vulnerable else (1.0 - confidence_clamped)
        reliability_signal = 1.0 - fpp_clamped
        normalized = (decision_confidence + reliability_signal) / 2.0
        return round(min(max(normalized, 0.0), 1.0), 4)

    def _normalize_exploitability(
        self,
        *,
        exploitability: str,
        reasoning: str,
        is_vulnerable: bool,
    ) -> str:
        text = exploitability.strip()
        if text:
            return text

        reasoning_text = reasoning.strip()
        if not reasoning_text:
            return "Not enough evidence to determine exploitability."

        for sentence in [segment.strip() for segment in reasoning_text.split(".") if segment.strip()]:
            lowered = sentence.lower()
            if "attacker" in lowered or "input" in lowered or "exploit" in lowered:
                return sentence + "."

        if is_vulnerable:
            return "Potentially exploitable based on security reasoning; manual validation recommended."
        return "Model judged the finding as non-exploitable in this context."
