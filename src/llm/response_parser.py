"""Normalization and JSON extraction for LLM responses."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping


JSON_OBJECT_PATTERN = re.compile(r"\{(?:.|\n|\r)*\}", re.MULTILINE)


def parse_model_json(raw_response: str) -> Dict[str, Any]:
    """Extract and parse the first JSON object from model output text."""
    candidate = _extract_json_candidate(raw_response)
    parsed = json.loads(candidate)
    _assert_schema(parsed)
    return {
        "is_vulnerable": bool(parsed["is_vulnerable"]),
        "cwe": str(parsed["cwe"]),
        "severity": str(parsed["severity"]),
        "confidence": float(parsed["confidence"]),
        "reasoning": str(parsed["reasoning"]),
        "exploitability": str(parsed["exploitability"]),
        "recommended_fix": str(parsed["recommended_fix"]),
        "false_positive_probability": float(parsed["false_positive_probability"]),
    }


def _extract_json_candidate(raw_response: str) -> str:
    stripped = raw_response.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    fenced = re.search(r"```(?:json)?\s*(\{(?:.|\n|\r)*?\})\s*```", raw_response)
    if fenced:
        return fenced.group(1).strip()

    match = JSON_OBJECT_PATTERN.search(raw_response)
    if match:
        return match.group(0).strip()

    raise ValueError("No JSON object found in model response")


def _assert_schema(parsed: Mapping[str, Any]) -> None:
    required = {
        "is_vulnerable",
        "cwe",
        "severity",
        "confidence",
        "reasoning",
        "exploitability",
        "recommended_fix",
        "false_positive_probability",
    }
    missing = required.difference(parsed.keys())
    if missing:
        raise ValueError(f"Response JSON missing fields: {sorted(missing)}")
