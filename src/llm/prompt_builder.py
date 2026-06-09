"""Prompt construction helpers for LLM-based vulnerability validation."""

from __future__ import annotations

import json
from typing import Any, Mapping, Optional, Sequence


DEFAULT_SECURITY_POLICY = """You are a security verification judge for a static analysis pipeline.
Only determine whether the reported issue is realistically exploitable in the provided code context.
Do not infer vulnerabilities that are not supported by evidence in the snippet and findings.
"""


OUTPUT_SCHEMA = {
    "is_vulnerable": True,
    "cwe": "CWE-89",
    "severity": "HIGH",
    "confidence": 0.92,
    "reasoning": "...",
    "exploitability": "...",
    "recommended_fix": "...",
    "false_positive_probability": 0.05,
}


def build_security_validation_prompt(
    code_snippet: str,
    sast_findings: Sequence[Mapping[str, Any]],
    *,
    security_policy: Optional[str] = None,
) -> str:
    """Build deterministic prompt with strict JSON-only response requirements."""
    policy = (security_policy or DEFAULT_SECURITY_POLICY).strip()
    findings_json = json.dumps(list(sast_findings), indent=2, sort_keys=True)
    schema_json = json.dumps(OUTPUT_SCHEMA, indent=2, sort_keys=True)

    return (
        "[SECURITY POLICY]\n"
        f"{policy}\n\n"
        "[CODE SNIPPET]\n"
        f"{code_snippet.strip()}\n\n"
        "[SAST FINDINGS]\n"
        f"{findings_json}\n\n"
        "[REQUIRED OUTPUT JSON SCHEMA]\n"
        f"{schema_json}\n\n"
        "[STRICT RESPONSE INSTRUCTIONS]\n"
        "1) Return ONLY one valid JSON object and no additional text.\n"
        "2) Use the exact field names from the required schema.\n"
        "3) confidence and false_positive_probability must be numeric values in [0.0, 1.0].\n"
        "4) If uncertain, lower confidence and explain uncertainty in reasoning.\n"
    )
