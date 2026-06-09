"""Small HTTP helpers for LLM provider adapters."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Mapping
from urllib import error, request


LOGGER = logging.getLogger(__name__)


def post_json_with_retry(
    *,
    url: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout_seconds: float,
    max_retries: int,
    retry_backoff_seconds: float,
) -> str:
    """POST JSON and return text body with bounded retries on transient failures."""
    body = json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json", **headers}

    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        req = request.Request(url=url, data=body, headers=request_headers, method="POST")
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                return response.read().decode("utf-8")
        except (error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt >= max_retries:
                break
            LOGGER.warning(
                "Transient provider request failure on attempt=%d/%d: %s",
                attempt + 1,
                max_retries + 1,
                exc,
            )
            if retry_backoff_seconds > 0:
                time.sleep(retry_backoff_seconds)

    if last_error is None:
        raise RuntimeError("Provider request failed without explicit error")
    raise RuntimeError("Provider request failed after retries") from last_error
