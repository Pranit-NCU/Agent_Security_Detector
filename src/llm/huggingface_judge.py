"""HuggingFace Inference Router -- chat completions judge.

Uses the OpenAI-compatible router endpoint (replaces the retired
api-inference.huggingface.co as of July 2025):

    POST https://router.huggingface.co/v1/chat/completions

The router automatically selects the fastest available provider for the
requested model.  Token must have "Make calls to Inference Providers"
permission (fine-grained token from huggingface.co/settings/tokens).

Environment variable
--------------------
HF_API_KEY   (also accepted: HUGGINGFACE_API_KEY for backward-compat)

Recommended models for VERDICT
-------------------------------
RECOMMENDED_MODELS is a list of three non-gated, freely-accessible
instruction-tuned models available via the HF Inference Router:

  google/gemma-3-27b-it  -- Google; 27B; non-gated; primary judge via HF Router

Second judge (Mistral Nemo) is served via Mistral API (see mistral_judge.py).
Third judge (Llama 3.3 70B) is served via SambaNova (see sambanova_judge.py).
gemma-3-12b-it was removed — same family as gemma-3-27b-it inflates Fleiss kappa.
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

# One Gemma model via HF Router. Second judge (Mistral Nemo) comes from
# mistral_judge.py; third (Llama 3.3 70B) from sambanova_judge.py.
# gemma-3-12b-it removed: same family as 27B inflates inter-model agreement.
RECOMMENDED_MODELS: list[str] = [
    "google/gemma-3-27b-it",   # Google Gemma 3 — 27B, confirmed working ✅
]

# Suggested config values for HF (models can be slow on first call)
HF_JUDGE_CONFIG = dict(
    timeout_seconds=90.0,
    max_retries=2,
    retry_backoff_seconds=5.0,
    temperature=0.0,
)

_HF_ROUTER_URL = "https://router.huggingface.co/v1/chat/completions"
_MAX_NEW_TOKENS = 512
_MAX_LOADING_WAITS = 3
_DEFAULT_LOADING_WAIT_S = 30.0


class HuggingFaceJudge(BaseLLMJudge):
    """Judge using HuggingFace Inference API (Messages / chat completions endpoint)."""

    API_KEY_ENV = "HF_API_KEY"
    API_KEY_ENV_LEGACY = "HUGGINGFACE_API_KEY"

    @property
    def provider_name(self) -> str:
        return "huggingface"

    def _invoke_model(self, prompt: str) -> str:
        api_key = (
            os.getenv(self.API_KEY_ENV, "").strip()
            or os.getenv(self.API_KEY_ENV_LEGACY, "").strip()
        )
        if not api_key:
            raise RuntimeError(
                "Missing API key -- set HF_API_KEY in your .env file"
            )

        url = _HF_ROUTER_URL
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

        raw = self._post_with_loading_retry(url, payload, headers)
        return self._extract_chat_content(raw)

    def _post_with_loading_retry(
        self, url: str, payload: dict, headers: dict
    ) -> str:
        """POST with special handling for HF 503 model-loading responses."""
        body = json.dumps(payload).encode("utf-8")

        for attempt in range(_MAX_LOADING_WAITS + 1):
            req = urllib.request.Request(
                url=url, data=body, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.config.timeout_seconds
                ) as resp:
                    return resp.read().decode("utf-8")

            except urllib.error.HTTPError as exc:
                if exc.code == 503 and attempt < _MAX_LOADING_WAITS:
                    wait_s = _parse_loading_wait(exc)
                    LOGGER.info(
                        "[HF] %s loading -- waiting %.0fs (attempt %d/%d)",
                        self.config.model_name,
                        wait_s,
                        attempt + 1,
                        _MAX_LOADING_WAITS,
                    )
                    print(
                        f"[HF] Model {self.config.model_name!r} still loading, "
                        f"waiting {wait_s:.0f}s..."
                    )
                    time.sleep(wait_s)
                    continue
                raise RuntimeError(
                    f"HF API returned HTTP {exc.code} for {self.config.model_name}: "
                    f"{exc.reason}"
                ) from exc

            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < _MAX_LOADING_WAITS:
                    LOGGER.warning(
                        "[HF] Transient error on attempt %d: %s", attempt + 1, exc
                    )
                    time.sleep(self.config.retry_backoff_seconds)
                    continue
                raise RuntimeError(
                    f"HF request failed after {_MAX_LOADING_WAITS} attempts"
                ) from exc

        raise RuntimeError(
            f"HF model {self.config.model_name!r} still loading after "
            f"{_MAX_LOADING_WAITS} wait cycles"
        )

    @staticmethod
    def _extract_chat_content(raw: str) -> str:
        """Pull assistant message content from a chat completions response."""
        try:
            data = json.loads(raw)
            choices = data.get("choices", [])
            if choices:
                content = choices[0].get("message", {}).get("content", "")
                if content:
                    return content
        except (json.JSONDecodeError, KeyError, IndexError, TypeError):
            pass
        LOGGER.warning("[HF] Unexpected chat response shape; returning raw for parsing")
        return raw


def _parse_loading_wait(exc: urllib.error.HTTPError) -> float:
    """Extract estimated_time from HF 503 JSON body; default 30s."""
    try:
        body = exc.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        return min(float(data.get("estimated_time", _DEFAULT_LOADING_WAIT_S)), 60.0)
    except Exception:
        return _DEFAULT_LOADING_WAIT_S


def make_hf_judge(model_name: str) -> HuggingFaceJudge:
    """Convenience factory with dissertation-appropriate config."""
    return HuggingFaceJudge(JudgeConfig(model_name=model_name, **HF_JUDGE_CONFIG))
